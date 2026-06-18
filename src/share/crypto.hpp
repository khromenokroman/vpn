#pragma once

#include <sodium.h>

#include <cstddef>
#include <string_view>

class Crypto {
   public:
    explicit Crypto(std::string_view password);

    bool encrypt(const char* plain, std::size_t plain_size, char* out, std::size_t& out_size);
    bool decrypt(const char* encrypted, std::size_t encrypted_size, char* out, std::size_t& out_size);

    static constexpr std::size_t overhead();

   private:
    static constexpr unsigned char MAGIC[4] = {'P', 'O', 'M', 'A'};
    static constexpr std::size_t MAGIC_SIZE = sizeof(MAGIC);
    static constexpr std::size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    static constexpr std::size_t TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    static constexpr std::size_t HEADER_SIZE = MAGIC_SIZE + NONCE_SIZE;

    unsigned char m_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]{};
};
