#include "crypto.hpp"

#include <chrono>
#include <cstring>

namespace {

/** @brief Контекст crypto_kdf, ровно crypto_kdf_CONTEXTBYTES символов. */
constexpr char KDF_CONTEXT[] = "pomavpn2";
static_assert(sizeof(KDF_CONTEXT) - 1 == crypto_kdf_CONTEXTBYTES);

/** @brief Номер подключа crypto_kdf для направления. */
std::uint64_t subkey_id(Direction d) { return d == Direction::CLIENT_TO_SERVER ? 1 : 2; }

Direction opposite(Direction d) { return d == Direction::CLIENT_TO_SERVER ? Direction::SERVER_TO_CLIENT : Direction::CLIENT_TO_SERVER; }

void put_be64(unsigned char* p, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<unsigned char>(v & 0xFF);
        v >>= 8;
    }
}

std::uint64_t get_be64(const unsigned char* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

constexpr unsigned char OLD_MAGIC[4] = {'P', 'O', 'M', 'A'};

} // namespace

SessionId SessionId::generate() {
    SessionId id;
    auto now = std::chrono::system_clock::now().time_since_epoch();
    id.start_ns = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
    randombytes_buf(&id.random, sizeof(id.random));
    return id;
}

Crypto::Crypto(std::string_view secret, Direction tx) {
    // без mlock ключи могут попасть в своп; не критично для работы, поэтому только попытка
    sodium_mlock(m_tx_key, sizeof(m_tx_key));
    sodium_mlock(m_rx_key, sizeof(m_rx_key));

    unsigned char master[crypto_kdf_KEYBYTES];
    sodium_mlock(master, sizeof(master));
    crypto_generichash(master, sizeof(master), reinterpret_cast<const unsigned char*>(secret.data()), secret.size(), nullptr, 0);
    crypto_kdf_derive_from_key(m_tx_key, sizeof(m_tx_key), subkey_id(tx), KDF_CONTEXT, master);
    crypto_kdf_derive_from_key(m_rx_key, sizeof(m_rx_key), subkey_id(opposite(tx)), KDF_CONTEXT, master);
    sodium_munlock(master, sizeof(master));
}

Crypto::~Crypto() {
    // sodium_munlock затирает память перед снятием блокировки
    sodium_munlock(m_tx_key, sizeof(m_tx_key));
    sodium_munlock(m_rx_key, sizeof(m_rx_key));
}

bool Crypto::seal(const PacketHeader& header, const char* plain, std::size_t plain_size, char* out, std::size_t& out_size) const {
    if (plain_size == 0) return false;

    auto* o = reinterpret_cast<unsigned char*>(out);
    std::memcpy(o, MAGIC, MAGIC_SIZE);
    unsigned char* nonce = o + MAGIC_SIZE;
    put_be64(nonce, header.session.start_ns);
    put_be64(nonce + 8, header.session.random);
    put_be64(nonce + 16, header.seq);

    unsigned long long cipher_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(o + HEADER_SIZE, &cipher_len, reinterpret_cast<const unsigned char*>(plain), plain_size,
                                                        MAGIC, MAGIC_SIZE, nullptr, nonce, m_tx_key);
    if (rc != 0) return false;

    out_size = HEADER_SIZE + cipher_len;
    return true;
}

Crypto::Open Crypto::open(const char* in, std::size_t in_size, char* out, std::size_t& out_size, PacketHeader& header) const {
    if (in_size < MAGIC_SIZE) return Open::MALFORMED;
    if (std::memcmp(in, MAGIC, MAGIC_SIZE) != 0) {
        return std::memcmp(in, OLD_MAGIC, MAGIC_SIZE) == 0 ? Open::OLD_PROTOCOL : Open::MALFORMED;
    }
    if (in_size <= HEADER_SIZE + TAG_SIZE) return Open::MALFORMED;

    const auto* p = reinterpret_cast<const unsigned char*>(in);
    const unsigned char* nonce = p + MAGIC_SIZE;
    unsigned long long plain_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(reinterpret_cast<unsigned char*>(out), &plain_len, nullptr, p + HEADER_SIZE,
                                                        in_size - HEADER_SIZE, MAGIC, MAGIC_SIZE, nonce, m_rx_key);
    if (rc != 0) return Open::AUTH_FAILED;

    header.session.start_ns = get_be64(nonce);
    header.session.random = get_be64(nonce + 8);
    header.seq = get_be64(nonce + 16);
    out_size = plain_len;
    return Open::OK;
}
