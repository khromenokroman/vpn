#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

/**
 * @brief Ошибка чтения файла ключа; what() содержит путь и причину.
 */
class KeyFileError : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
};

/**
 * @brief Секрет в памяти, защищённой от свопа (sodium_malloc) и затираемой при освобождении.
 *
 * Не копируется, только перемещается.
 */
class SecretBuffer {
   public:
    /**
     * @brief Выделяет защищённый буфер.
     * @param capacity размер буфера в байтах, больше нуля
     * @throw std::bad_alloc если sodium_malloc не выделил память
     */
    explicit SecretBuffer(std::size_t capacity);
    ~SecretBuffer();

    SecretBuffer(const SecretBuffer&) = delete;
    SecretBuffer& operator=(const SecretBuffer&) = delete;
    SecretBuffer(SecretBuffer&& other) noexcept;
    SecretBuffer& operator=(SecretBuffer&& other) noexcept;

    /** @brief Начало буфера для записи. */
    unsigned char* data() noexcept { return m_data; }
    /** @brief Начало буфера для чтения. */
    const unsigned char* data() const noexcept { return m_data; }
    /** @brief Размер полезных данных. */
    std::size_t size() const noexcept { return m_size; }
    /** @brief Ёмкость буфера. */
    std::size_t capacity() const noexcept { return m_capacity; }
    /** @brief Устанавливает размер полезных данных, не больше ёмкости. */
    void resize(std::size_t size);
    /** @brief Секрет как строка без копирования. */
    std::string_view view() const noexcept { return {reinterpret_cast<const char*>(m_data), m_size}; }

   private:
    unsigned char* m_data = nullptr;
    std::size_t m_capacity = 0;
    std::size_t m_size = 0;
};

/** @brief Имя файла ключа в каталоге $CREDENTIALS_DIRECTORY (LoadCredential= в systemd). */
inline constexpr std::string_view KEY_CREDENTIAL_NAME = "vpn-key";

/** @brief Максимальный размер файла ключа в байтах. */
inline constexpr std::size_t KEY_FILE_MAX_SIZE = 4096;

/**
 * @brief Читает общий ключ из файла.
 *
 * Требования к файлу: обычный файл (не симлинк), владелец - текущий эффективный пользователь,
 * нет прав для группы и остальных, размер от 1 до KEY_FILE_MAX_SIZE байт.
 * Завершающие пробелы и переводы строки отбрасываются, чтобы файл от `openssl rand -base64 32 > key`
 * давал тот же ключ, что и строка без перевода строки.
 *
 * @param path путь к файлу
 * @return содержимое файла в защищённой памяти
 * @throw KeyFileError если файл не открывается или не удовлетворяет требованиям
 */
SecretBuffer read_key_file(const std::filesystem::path& path);

/**
 * @brief Определяет путь к файлу ключа.
 *
 * Если путь задан явно (--key-file), возвращается он. Иначе, если задан каталог учётных данных systemd
 * (переменная CREDENTIALS_DIRECTORY), возвращается `<каталог>/vpn-key`.
 *
 * @param key_file путь из параметра --key-file, если задан
 * @param credentials_dir значение CREDENTIALS_DIRECTORY или nullptr
 * @return путь к файлу ключа
 * @throw KeyFileError если не задано ни то, ни другое
 */
std::filesystem::path resolve_key_path(const std::optional<std::filesystem::path>& key_file, const char* credentials_dir);

/**
 * @brief Загружает ключ для запуска: путь из --key-file или $CREDENTIALS_DIRECTORY/vpn-key.
 * @param key_file значение --key-file, пустая строка - не задан
 * @return секрет
 * @throw KeyFileError если путь не задан или файл не прошёл проверки
 */
SecretBuffer load_key(const std::string& key_file);
