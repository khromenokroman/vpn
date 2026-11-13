#pragma once

#include <sodium.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string_view>

/**
 * @brief Направление трафика: у каждого свой ключ, поэтому пакет нельзя отразить отправителю.
 */
enum class Direction { CLIENT_TO_SERVER, SERVER_TO_CLIENT };

/**
 * @brief Сессия отправителя: время запуска и случайное число.
 *
 * Время (CLOCK_REALTIME, нс) упорядочивает сессии одного собеседника: после перезапуска сессия новее.
 * Случайная часть не даёт двум клиентам с общим ключом, запущенным в одну наносекунду, получить один nonce.
 */
struct SessionId {
    std::uint64_t start_ns = 0; ///< время запуска, нс от эпохи Unix
    std::uint64_t random = 0;   ///< случайная часть

    bool operator==(const SessionId&) const = default;

    /** @brief Новая сессия: текущее время и случайное число из libsodium. */
    static SessionId generate();
};

/**
 * @brief Открытая часть заголовка пакета, из неё же собирается nonce.
 */
struct PacketHeader {
    SessionId session; ///< сессия отправителя
    std::uint64_t seq; ///< номер пакета в сессии, с 0
};

/**
 * @brief Сессия отправки: номера пакетов растут на 1, nonce не повторяется.
 *
 * next() потокобезопасен: данные и keep-alive отправляют разные потоки.
 */
class TxSession {
   public:
    TxSession() : m_id(SessionId::generate()) {}

    TxSession(const TxSession&) = delete;
    TxSession& operator=(const TxSession&) = delete;

    /** @brief Заголовок для следующего пакета. */
    PacketHeader next() { return {m_id, m_seq.fetch_add(1, std::memory_order_relaxed)}; }

    /** @brief Идентификатор сессии. */
    const SessionId& id() const { return m_id; }

   private:
    SessionId m_id;
    std::atomic<std::uint64_t> m_seq{0};
};

/**
 * @brief Шифрование пакетов туннеля XChaCha20-Poly1305.
 *
 * Формат: [magic "POM2" 4][начало сессии 8][случайная часть 8][номер 8][шифротекст + тег 16], числа big-endian.
 * Nonce - 24 байта после magic, magic проверяется как associated data.
 *
 * Из общего секрета выводится главный ключ (BLAKE2b), из него crypto_kdf - ключи направлений
 * клиент->сервер и сервер->клиент. Ключи лежат в памяти, заблокированной от свопа, и затираются в деструкторе.
 */
class Crypto {
   public:
    /** @brief Результат расшифровки. */
    enum class Open {
        OK,           ///< расшифрован
        MALFORMED,    ///< короче заголовка с тегом или чужой magic
        OLD_PROTOCOL, ///< формат до 0.5.0.0 (magic "POMA")
        AUTH_FAILED,  ///< подделан, повреждён, другой ключ или другое направление
    };

    /**
     * @param secret общий секрет из файла ключа
     * @param tx направление, в котором этот участник отправляет; принимает он в обратном
     */
    Crypto(std::string_view secret, Direction tx);
    ~Crypto();

    Crypto(const Crypto&) = delete;
    Crypto& operator=(const Crypto&) = delete;

    /**
     * @brief Шифрует пакет.
     * @param header сессия и номер, у каждого пакета свой
     * @param plain открытый пакет, не пустой
     * @param plain_size размер открытого пакета
     * @param out буфер результата, не меньше plain_size + overhead()
     * @param out_size размер результата
     * @return false при пустом пакете или ошибке libsodium
     */
    bool seal(const PacketHeader& header, const char* plain, std::size_t plain_size, char* out, std::size_t& out_size) const;

    /**
     * @brief Расшифровывает и проверяет пакет. Повтор не проверяется, это делает PeerState по header.
     * @param in зашифрованный пакет
     * @param in_size размер
     * @param out буфер результата, не меньше in_size - overhead()
     * @param out_size размер расшифрованного пакета
     * @param header заголовок пакета, заполняется при OK
     */
    Open open(const char* in, std::size_t in_size, char* out, std::size_t& out_size, PacketHeader& header) const;

    /** @brief Сколько байт шифрование добавляет к пакету. */
    static constexpr std::size_t overhead() { return HEADER_SIZE + TAG_SIZE; }

   private:
    static constexpr unsigned char MAGIC[4] = {'P', 'O', 'M', '2'};
    static constexpr std::size_t MAGIC_SIZE = sizeof(MAGIC);
    static constexpr std::size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    static constexpr std::size_t TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    static constexpr std::size_t HEADER_SIZE = MAGIC_SIZE + NONCE_SIZE;
    static constexpr std::size_t KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
    static_assert(NONCE_SIZE == 8 + 8 + 8, "nonce = начало сессии + случайная часть + номер");

    unsigned char m_tx_key[KEY_SIZE]{};
    unsigned char m_rx_key[KEY_SIZE]{};
};
