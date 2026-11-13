#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#include "share/key_file.hpp"

namespace fs = std::filesystem;
using ::testing::HasSubstr;

namespace {

/**
 * @brief Временный каталог на время теста.
 */
class KeyFileTest : public ::testing::Test {
   protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0) << "libsodium не инициализирована";
        std::string tmpl = (fs::temp_directory_path() / "vpn-key-test-XXXXXX").string();
        ASSERT_NE(::mkdtemp(tmpl.data()), nullptr) << "mkdtemp " << tmpl << ": " << std::strerror(errno);
        m_dir = tmpl;
    }
    void TearDown() override { fs::remove_all(m_dir); }

    /** @brief Создаёт файл с содержимым и правами. */
    fs::path make_file(const std::string& name, const std::string& content, mode_t mode) {
        fs::path p = m_dir / name;
        std::ofstream(p, std::ios::binary) << content;
        EXPECT_EQ(::chmod(p.c_str(), mode), 0) << "chmod " << p << ": " << std::strerror(errno);
        return p;
    }

    /** @brief Ожидает отказ read_key_file с причиной, содержащей reason. */
    void expect_rejected(const fs::path& p, const std::string& reason) {
        try {
            SecretBuffer key = read_key_file(p);
            ADD_FAILURE() << "файл " << p << ": ожидался отказ с причиной \"" << reason << "\", а прочитан ключ \"" << key.view() << "\"";
        } catch (const KeyFileError& e) {
            EXPECT_THAT(e.what(), HasSubstr(reason)) << "файл " << p << ": ожидалась причина \"" << reason << "\"";
            EXPECT_THAT(e.what(), HasSubstr(p.string())) << "в сообщении об ошибке должен быть путь к файлу";
        }
    }

    fs::path m_dir;
};

#define EXPECT_REJECTED(path, reason)  \
    do {                               \
        SCOPED_TRACE("вызов отсюда");  \
        expect_rejected(path, reason); \
    } while (0)

} // namespace

/**
 * @brief Ключ с правами 0600 читается, завершающий перевод строки отбрасывается:
 * вывод `openssl rand -base64 32 > key` должен давать тот же ключ, что и строка в --key раньше.
 */
TEST_F(KeyFileTest, ReadsKeyAndStripsTrailingNewline) {
    const std::string content = "dGVzdC1rZXktbm90LWZvci1wcm9kdWN0aW9uLTAwMDA=\r\n \n";
    fs::path p = make_file("key", content, 0600);
    SecretBuffer key = read_key_file(p);
    EXPECT_EQ(key.view(), "dGVzdC1rZXktbm90LWZvci1wcm9kdWN0aW9uLTAwMDA=") << "содержимое файла: \"" << content << "\"";
}

/**
 * @brief Права 0400 (так systemd кладёт LoadCredential=) допустимы.
 */
TEST_F(KeyFileTest, AcceptsReadOnlyOwner) {
    fs::path p = make_file("key", "secret", 0400);
    EXPECT_EQ(read_key_file(p).view(), "secret") << "права 0400";
}

/**
 * @brief Пробелы внутри и в начале ключа сохраняются: обрезается только хвост.
 */
TEST_F(KeyFileTest, KeepsInnerAndLeadingSpaces) {
    fs::path p = make_file("key", " a b\n", 0600);
    EXPECT_EQ(read_key_file(p).view(), " a b") << "содержимое \" a b\\n\"";
}

/**
 * @brief Файл, читаемый группой или всеми, отвергается: ключ уже мог утечь.
 */
TEST_F(KeyFileTest, RejectsGroupOrWorldPermissions) {
    for (mode_t mode : {0640, 0604, 0644, 0660, 0610}) {
        SCOPED_TRACE(::testing::Message() << "права " << std::oct << mode);
        fs::path p = make_file("key", "secret", mode);
        EXPECT_REJECTED(p, "открывают ключ другим пользователям");
    }
}

/**
 * @brief Пустой файл и файл только из переводов строк отвергаются.
 */
TEST_F(KeyFileTest, RejectsEmpty) {
    EXPECT_REJECTED(make_file("empty", "", 0600), "пустой");
    EXPECT_REJECTED(make_file("newlines", "\n\r\n  \n", 0600), "ключ пустой");
}

/**
 * @brief Файл больше KEY_FILE_MAX_SIZE отвергается (защита от указания на большой файл).
 */
TEST_F(KeyFileTest, RejectsTooLarge) { EXPECT_REJECTED(make_file("big", std::string(KEY_FILE_MAX_SIZE + 1, 'a'), 0600), "больше допустимых"); }

/**
 * @brief Файл ровно KEY_FILE_MAX_SIZE байт читается целиком.
 */
TEST_F(KeyFileTest, AcceptsMaxSize) {
    fs::path p = make_file("max", std::string(KEY_FILE_MAX_SIZE, 'a'), 0600);
    EXPECT_EQ(read_key_file(p).size(), KEY_FILE_MAX_SIZE) << "файл " << KEY_FILE_MAX_SIZE << " байт";
}

/**
 * @brief Символьная ссылка отвергается, даже если указывает на корректный файл.
 */
TEST_F(KeyFileTest, RejectsSymlink) {
    fs::path target = make_file("key", "secret", 0600);
    fs::path link = m_dir / "link";
    fs::create_symlink(target, link);
    EXPECT_REJECTED(link, "символьная ссылка");
}

/**
 * @brief Каталог вместо файла отвергается.
 */
TEST_F(KeyFileTest, RejectsDirectory) {
    fs::path d = m_dir / "dir";
    fs::create_directory(d);
    fs::permissions(d, fs::perms::owner_all);
    EXPECT_REJECTED(d, "не обычный файл");
}

/**
 * @brief Отсутствующий файл: в ошибке путь и причина от ОС.
 */
TEST_F(KeyFileTest, RejectsMissing) { EXPECT_REJECTED(m_dir / "nope", std::strerror(ENOENT)); }

/**
 * @brief Явный --key-file важнее CREDENTIALS_DIRECTORY.
 */
TEST(ResolveKeyPath, ExplicitWins) {
    EXPECT_EQ(resolve_key_path(fs::path("/etc/k"), "/run/credentials/x"), fs::path("/etc/k"))
        << "--key-file=/etc/k, CREDENTIALS_DIRECTORY=/run/credentials/x";
}

/**
 * @brief Без --key-file берётся vpn-key из каталога учётных данных systemd.
 */
TEST(ResolveKeyPath, UsesCredentialsDirectory) {
    EXPECT_EQ(resolve_key_path(std::nullopt, "/run/credentials/x"), fs::path("/run/credentials/x/vpn-key"))
        << "--key-file не задан, CREDENTIALS_DIRECTORY=/run/credentials/x";
}

/**
 * @brief Ни --key-file, ни CREDENTIALS_DIRECTORY (или пустая переменная): понятная ошибка.
 */
TEST(ResolveKeyPath, FailsWithoutSource) {
    for (const char* dir : {static_cast<const char*>(nullptr), ""}) {
        SCOPED_TRACE(dir ? "CREDENTIALS_DIRECTORY пустая" : "CREDENTIALS_DIRECTORY не задана");
        try {
            fs::path p = resolve_key_path(std::nullopt, dir);
            ADD_FAILURE() << "ожидалась ошибка, получен путь " << p;
        } catch (const KeyFileError& e) {
            EXPECT_THAT(e.what(), HasSubstr("--key-file")) << "сообщение должно подсказывать параметр";
        }
    }
}
