#pragma once

#include <sodium.h>

#include <cstddef>
#include <string_view>

/**
 * @brief Шифрование пакетов туннеля XChaCha20-Poly1305 общим ключом.
 *
 * Формат пакета: [magic "POMA" 4 байта][nonce 24 байта][шифротекст + тег 16 байт].
 * Ключ хранится в памяти, заблокированной от свопа, и затирается в деструкторе.
 */
class Crypto {
   public:
    /**
     * @brief Выводит ключ шифрования из общего секрета (BLAKE2b, 32 байта).
     * @param secret общий секрет из файла ключа
     */
    explicit Crypto(std::string_view secret);
    ~Crypto();

    Crypto(const Crypto&) = delete;
    Crypto& operator=(const Crypto&) = delete;

    /**
     * @brief Шифрует пакет.
     * @param plain открытый пакет, не пустой
     * @param plain_size размер открытого пакета
     * @param out буфер результата, не меньше plain_size + overhead()
     * @param out_size размер результата
     * @return false при пустом пакете или ошибке libsodium
     */
    bool encrypt(const char* plain, std::size_t plain_size, char* out, std::size_t& out_size);

    /**
     * @brief Расшифровывает и проверяет пакет.
     * @param encrypted зашифрованный пакет
     * @param encrypted_size размер зашифрованного пакета
     * @param out буфер результата, не меньше encrypted_size - overhead()
     * @param out_size размер расшифрованного пакета
     * @return false, если пакет короткий, без magic, подделан или зашифрован другим ключом
     */
    bool decrypt(const char* encrypted, std::size_t encrypted_size, char* out, std::size_t& out_size);

    /** @brief Сколько байт шифрование добавляет к пакету. */
    static constexpr std::size_t overhead() { return HEADER_SIZE + TAG_SIZE; }

   private:
    static constexpr unsigned char MAGIC[4] = {'P', 'O', 'M', 'A'};
    static constexpr std::size_t MAGIC_SIZE = sizeof(MAGIC);
    static constexpr std::size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    static constexpr std::size_t TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    static constexpr std::size_t HEADER_SIZE = MAGIC_SIZE + NONCE_SIZE;

    unsigned char m_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]{};
};
