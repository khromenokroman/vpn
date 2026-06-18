#include "crypto.hpp"

#include <cstring>

constexpr unsigned char Crypto::MAGIC[4];

Crypto::Crypto(std::string_view password) {
    crypto_generichash(m_key,
                       sizeof(m_key),
                       reinterpret_cast<const unsigned char*>(password.data()),
                       password.size(),
                       nullptr,
                       0);
}

constexpr std::size_t Crypto::overhead() {
    return HEADER_SIZE + TAG_SIZE;
}

bool Crypto::encrypt(const char* plain, std::size_t plain_size, char* out, std::size_t& out_size) {
    if (plain_size == 0) return false;

    unsigned char nonce[NONCE_SIZE];
    randombytes_buf(nonce, sizeof(nonce));

    std::memcpy(out, MAGIC, MAGIC_SIZE);
    std::memcpy(out + MAGIC_SIZE, nonce, NONCE_SIZE);

    unsigned long long cipher_len = 0;

    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(out + HEADER_SIZE),
        &cipher_len,
        reinterpret_cast<const unsigned char*>(plain),
        plain_size,
        nullptr,
        0,
        nullptr,
        nonce,
        m_key);

    if (rc != 0) return false;

    out_size = HEADER_SIZE + cipher_len;
    return true;
}

bool Crypto::decrypt(const char* encrypted, std::size_t encrypted_size, char* out, std::size_t& out_size) {
    if (encrypted_size <= HEADER_SIZE + TAG_SIZE) {
        return false;
    }

    if (std::memcmp(encrypted, MAGIC, MAGIC_SIZE) != 0) {
        return false;
    }

    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(encrypted + MAGIC_SIZE);
    const unsigned char* cipher = reinterpret_cast<const unsigned char*>(encrypted + HEADER_SIZE);
    std::size_t cipher_size = encrypted_size - HEADER_SIZE;

    unsigned long long plain_len = 0;

    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(out),
        &plain_len,
        nullptr,
        cipher,
        cipher_size,
        nullptr,
        0,
        nonce,
        m_key);

    if (rc != 0) {
        return false;
    }

    out_size = plain_len;
    return true;
}
