#include <gtest/gtest.h>
#include <sodium.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "share/crypto.hpp"

namespace {

class CryptoTest : public ::testing::Test {
   protected:
    void SetUp() override { ASSERT_GE(sodium_init(), 0) << "libsodium не инициализирована"; }

    /** @brief Шифрует строку, при ошибке тест падает. */
    static std::vector<char> seal(const Crypto& c, const PacketHeader& h, const std::string& plain) {
        std::vector<char> out(plain.size() + Crypto::overhead());
        std::size_t out_size = 0;
        EXPECT_TRUE(c.seal(h, plain.data(), plain.size(), out.data(), out_size)) << "seal \"" << plain << "\"";
        out.resize(out_size);
        return out;
    }

    /** @brief Расшифровывает, возвращает результат и открытый текст. */
    static Crypto::Open open(const Crypto& c, const std::vector<char>& in, std::string& plain, PacketHeader& h) {
        std::vector<char> out(in.size());
        std::size_t out_size = 0;
        Crypto::Open r = c.open(in.data(), in.size(), out.data(), out_size, h);
        plain.assign(out.data(), r == Crypto::Open::OK ? out_size : 0);
        return r;
    }

    const PacketHeader HEADER{{0x0102030405060708ULL, 0x1112131415161718ULL}, 0x2122232425262728ULL};
};

} // namespace

/**
 * @brief Пакет клиента расшифровывается сервером в исходные байты с тем же заголовком,
 * размер растёт ровно на overhead() (от него считается рекомендуемый MTU).
 */
TEST_F(CryptoTest, RoundTrip) {
    Crypto client("secret", Direction::CLIENT_TO_SERVER), server("secret", Direction::SERVER_TO_CLIENT);
    const std::string plain("\x45\x00\x00\x1c payload \0 with zero", 26);
    std::vector<char> sealed = seal(client, HEADER, plain);
    EXPECT_EQ(sealed.size(), plain.size() + Crypto::overhead()) << "открытый пакет " << plain.size() << " байт, overhead " << Crypto::overhead();
    EXPECT_EQ(Crypto::overhead(), 44u) << "формат: magic 4 + сессия 16 + номер 8 + тег 16";

    std::string out;
    PacketHeader h{};
    ASSERT_EQ(open(server, sealed, out, h), Crypto::Open::OK) << "клиент -> сервер, общий секрет";
    EXPECT_EQ(out, plain);
    EXPECT_EQ(h.session, HEADER.session);
    EXPECT_EQ(h.seq, HEADER.seq);

    std::vector<char> back = seal(server, HEADER, plain);
    ASSERT_EQ(open(client, back, out, h), Crypto::Open::OK) << "сервер -> клиент";
    EXPECT_EQ(out, plain);
}

/**
 * @brief Заголовок открытый и big-endian: magic "POM2", затем начало сессии, случайная часть и номер.
 * Его же читает Android-клиент, поэтому порядок байт фиксирован тестом.
 */
TEST_F(CryptoTest, HeaderLayout) {
    Crypto c("secret", Direction::CLIENT_TO_SERVER);
    std::vector<char> sealed = seal(c, HEADER, "x");
    EXPECT_EQ(std::string(sealed.data(), 4), "POM2");
    std::vector<unsigned char> expected;
    for (int i = 1; i <= 8; ++i) expected.push_back(static_cast<unsigned char>(i));
    for (int i = 1; i <= 8; ++i) expected.push_back(static_cast<unsigned char>(0x10 + i));
    for (int i = 1; i <= 8; ++i) expected.push_back(static_cast<unsigned char>(0x20 + i));
    EXPECT_EQ(std::vector<unsigned char>(sealed.begin() + 4, sealed.begin() + 28), expected) << "байты 4..27: nonce = сессия + номер";
}

/**
 * @brief Пакет нельзя отразить отправителю: у направлений разные ключи, и свой же пакет
 * участник не расшифрует.
 */
TEST_F(CryptoTest, DirectionsUseDifferentKeys) {
    Crypto client("secret", Direction::CLIENT_TO_SERVER), other_client("secret", Direction::CLIENT_TO_SERVER);
    std::vector<char> sealed = seal(client, HEADER, "payload");
    std::string out;
    PacketHeader h{};
    EXPECT_EQ(open(client, sealed, out, h), Crypto::Open::AUTH_FAILED) << "пакет клиента вернули самому клиенту";
    EXPECT_EQ(open(other_client, sealed, out, h), Crypto::Open::AUTH_FAILED) << "пакет клиента подали другому клиенту с тем же ключом";
}

/**
 * @brief Разные номера дают разный шифротекст одного пакета: nonce не повторяется.
 */
TEST_F(CryptoTest, SeqChangesCiphertext) {
    Crypto c("secret", Direction::CLIENT_TO_SERVER);
    TxSession tx;
    std::set<std::vector<char>> seen;
    for (int i = 0; i < 100; ++i) {
        PacketHeader h = tx.next();
        EXPECT_EQ(h.seq, static_cast<std::uint64_t>(i)) << "номера идут подряд с 0";
        EXPECT_TRUE(seen.insert(seal(c, h, "same")).second) << "повтор шифротекста на пакете " << i;
    }
    EXPECT_NE(TxSession().id(), tx.id()) << "у новой сессии другой идентификатор";
}

/**
 * @brief Изменённый заголовок (включая номер пакета), шифротекст, другой секрет и обрезанный пакет
 * не расшифровываются: подменить номер, чтобы обойти окно повторов, нельзя.
 */
TEST_F(CryptoTest, RejectsForeignOrDamaged) {
    Crypto client("secret", Direction::CLIENT_TO_SERVER), server("secret", Direction::SERVER_TO_CLIENT);
    Crypto other("other", Direction::SERVER_TO_CLIENT);
    std::vector<char> sealed = seal(client, HEADER, "payload");
    std::string out;
    PacketHeader h{};

    EXPECT_EQ(open(other, sealed, out, h), Crypto::Open::AUTH_FAILED) << "секрет \"secret\", расшифровка секретом \"other\"";

    for (std::size_t i : {std::size_t{4}, std::size_t{12}, std::size_t{20}, std::size_t{27}, std::size_t{28}, sealed.size() - 1}) {
        std::vector<char> bad = sealed;
        bad[i] ^= 1;
        EXPECT_EQ(open(server, bad, out, h), Crypto::Open::AUTH_FAILED) << "изменён байт " << i << " из " << bad.size();
    }
    std::vector<char> bad_magic = sealed;
    bad_magic[3] = 'X';
    EXPECT_EQ(open(server, bad_magic, out, h), Crypto::Open::MALFORMED) << "magic POMX";

    for (std::size_t len : {std::size_t{0}, std::size_t{3}, std::size_t{4}, Crypto::overhead()}) {
        std::vector<char> cut(sealed.begin(), sealed.begin() + static_cast<std::ptrdiff_t>(len));
        EXPECT_EQ(open(server, cut, out, h), Crypto::Open::MALFORMED) << "пакет обрезан до " << len << " байт из " << sealed.size();
    }
    std::vector<char> cut(sealed.begin(), sealed.end() - 1);
    EXPECT_EQ(open(server, cut, out, h), Crypto::Open::AUTH_FAILED) << "обрезан последний байт тега";
}

/**
 * @brief Пакет формата до 0.5.0.0 (magic "POMA") опознаётся отдельно, чтобы в журнале было
 * «обновите клиент», а не молчаливый отказ.
 */
TEST_F(CryptoTest, DetectsOldProtocol) {
    Crypto server("secret", Direction::SERVER_TO_CLIENT);
    std::vector<char> old(4 + 24 + 16 + 20, '\0');
    std::copy_n("POMA", 4, old.begin());
    std::string out;
    PacketHeader h{};
    EXPECT_EQ(open(server, old, out, h), Crypto::Open::OLD_PROTOCOL);
}

/**
 * @brief Пустой открытый пакет не шифруется.
 */
TEST_F(CryptoTest, RejectsEmptyPlain) {
    Crypto c("secret", Direction::CLIENT_TO_SERVER);
    char out[64];
    std::size_t out_size = 0;
    EXPECT_FALSE(c.seal(HEADER, "", 0, out, out_size));
}
