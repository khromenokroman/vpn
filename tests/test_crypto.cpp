#include <gtest/gtest.h>
#include <sodium.h>

#include <string>
#include <vector>

#include "share/crypto.hpp"

namespace {

class CryptoTest : public ::testing::Test {
   protected:
    void SetUp() override { ASSERT_GE(sodium_init(), 0) << "libsodium не инициализирована"; }

    /** @brief Шифрует строку, при ошибке тест падает. */
    std::vector<char> seal(Crypto& c, const std::string& plain) {
        std::vector<char> out(plain.size() + Crypto::overhead());
        std::size_t out_size = 0;
        EXPECT_TRUE(c.encrypt(plain.data(), plain.size(), out.data(), out_size)) << "encrypt \"" << plain << "\"";
        out.resize(out_size);
        return out;
    }
};

} // namespace

/**
 * @brief Зашифрованный пакет расшифровывается тем же секретом в исходные байты,
 * размер растёт ровно на overhead() (от него считается рекомендуемый MTU).
 */
TEST_F(CryptoTest, RoundTrip) {
    Crypto a("secret"), b("secret");
    const std::string plain("\x45\x00\x00\x1c payload \0 with zero", 26);
    std::vector<char> sealed = seal(a, plain);
    EXPECT_EQ(sealed.size(), plain.size() + Crypto::overhead()) << "открытый пакет " << plain.size() << " байт, overhead " << Crypto::overhead();
    EXPECT_EQ(Crypto::overhead(), 44u) << "формат: magic 4 + nonce 24 + тег 16";

    std::vector<char> out(sealed.size());
    std::size_t out_size = 0;
    ASSERT_TRUE(b.decrypt(sealed.data(), sealed.size(), out.data(), out_size)) << "пакет зашифрован тем же секретом";
    EXPECT_EQ(std::string(out.data(), out_size), plain);
}

/**
 * @brief Пакет начинается с magic "POMA": по нему совместимы сервер, Linux- и Android-клиент.
 */
TEST_F(CryptoTest, PacketStartsWithMagic) {
    Crypto c("secret");
    std::vector<char> sealed = seal(c, "x");
    EXPECT_EQ(std::string(sealed.data(), 4), "POMA");
}

/**
 * @brief Nonce случайный: два шифрования одного пакета дают разные байты.
 */
TEST_F(CryptoTest, NonceIsRandom) {
    Crypto c("secret");
    EXPECT_NE(seal(c, "same"), seal(c, "same")) << "одинаковый nonce при одном ключе раскрывает XOR открытых текстов";
}

/**
 * @brief Другой секрет, изменённый байт, чужой magic и обрезанный пакет не расшифровываются.
 */
TEST_F(CryptoTest, RejectsForeignOrDamaged) {
    Crypto a("secret"), other("other");
    std::vector<char> sealed = seal(a, "payload");
    std::vector<char> out(sealed.size());
    std::size_t out_size = 0;

    EXPECT_FALSE(other.decrypt(sealed.data(), sealed.size(), out.data(), out_size)) << "секрет \"secret\", расшифровка секретом \"other\"";

    for (std::size_t i : {std::size_t{0}, std::size_t{4}, std::size_t{28}, sealed.size() - 1}) {
        std::vector<char> bad = sealed;
        bad[i] ^= 1;
        EXPECT_FALSE(a.decrypt(bad.data(), bad.size(), out.data(), out_size)) << "изменён байт " << i << " из " << bad.size();
    }

    for (std::size_t len : {std::size_t{0}, std::size_t{1}, Crypto::overhead(), sealed.size() - 1}) {
        EXPECT_FALSE(a.decrypt(sealed.data(), len, out.data(), out_size)) << "пакет обрезан до " << len << " байт из " << sealed.size();
    }
}

/**
 * @brief Пустой открытый пакет не шифруется.
 */
TEST_F(CryptoTest, RejectsEmptyPlain) {
    Crypto c("secret");
    char out[64];
    std::size_t out_size = 0;
    EXPECT_FALSE(c.encrypt("", 0, out, out_size));
}
