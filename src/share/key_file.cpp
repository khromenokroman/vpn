#include "key_file.hpp"

#include <fcntl.h>
#include <fmt/format.h>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <new>
#include <utility>

SecretBuffer::SecretBuffer(std::size_t capacity) : m_capacity(capacity) {
    m_data = static_cast<unsigned char*>(sodium_malloc(capacity));
    if (m_data == nullptr) {
        throw std::bad_alloc();
    }
}

SecretBuffer::~SecretBuffer() {
    // sodium_free затирает память перед освобождением
    sodium_free(m_data);
}

SecretBuffer::SecretBuffer(SecretBuffer&& other) noexcept
    : m_data(std::exchange(other.m_data, nullptr)), m_capacity(std::exchange(other.m_capacity, 0)), m_size(std::exchange(other.m_size, 0)) {}

SecretBuffer& SecretBuffer::operator=(SecretBuffer&& other) noexcept {
    if (this != &other) {
        sodium_free(m_data);
        m_data = std::exchange(other.m_data, nullptr);
        m_capacity = std::exchange(other.m_capacity, 0);
        m_size = std::exchange(other.m_size, 0);
    }
    return *this;
}

void SecretBuffer::resize(std::size_t size) {
    if (size > m_capacity) {
        throw std::length_error(fmt::format("размер {} больше ёмкости {}", size, m_capacity));
    }
    m_size = size;
}

namespace {

/**
 * @brief Закрывает дескриптор при выходе из области видимости.
 */
class FdGuard {
   public:
    explicit FdGuard(int fd) noexcept : m_fd(fd) {}
    ~FdGuard() {
        if (m_fd >= 0) ::close(m_fd);
    }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;

   private:
    int m_fd;
};

bool is_trailing_space(unsigned char c) { return c == '\n' || c == '\r' || c == ' ' || c == '\t'; }

} // namespace

SecretBuffer read_key_file(const std::filesystem::path& path) {
    // O_NOFOLLOW: симлинк в последнем компоненте пути отвергается, ELOOP
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        int err = errno;
        if (err == ELOOP) {
            throw KeyFileError(fmt::format("файл ключа {}: символьная ссылка не допускается", path.string()));
        }
        throw KeyFileError(fmt::format("файл ключа {}: {}", path.string(), std::strerror(err)));
    }
    FdGuard guard(fd);

    struct stat st {};
    if (::fstat(fd, &st) < 0) {
        throw KeyFileError(fmt::format("файл ключа {}: {}", path.string(), std::strerror(errno)));
    }
    if (!S_ISREG(st.st_mode)) {
        throw KeyFileError(fmt::format("файл ключа {}: не обычный файл", path.string()));
    }
    if (st.st_uid != ::geteuid()) {
        throw KeyFileError(fmt::format("файл ключа {}: владелец uid {}, ожидается uid {}", path.string(), st.st_uid, ::geteuid()));
    }
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw KeyFileError(fmt::format("файл ключа {}: права {:04o} открывают ключ другим пользователям, нужно 0600 или 0400", path.string(),
                                       static_cast<unsigned>(st.st_mode & 07777)));
    }
    if (st.st_size <= 0) {
        throw KeyFileError(fmt::format("файл ключа {}: пустой", path.string()));
    }
    if (static_cast<std::size_t>(st.st_size) > KEY_FILE_MAX_SIZE) {
        throw KeyFileError(fmt::format("файл ключа {}: размер {} байт больше допустимых {}", path.string(), st.st_size, KEY_FILE_MAX_SIZE));
    }

    // +1: чтение до EOF, чтобы заметить файл, выросший после fstat
    SecretBuffer key(KEY_FILE_MAX_SIZE + 1);
    std::size_t total = 0;
    while (total < key.capacity()) {
        ssize_t n = ::read(fd, key.data() + total, key.capacity() - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw KeyFileError(fmt::format("файл ключа {}: {}", path.string(), std::strerror(errno)));
        }
        if (n == 0) break;
        total += static_cast<std::size_t>(n);
    }
    if (total > KEY_FILE_MAX_SIZE) {
        throw KeyFileError(fmt::format("файл ключа {}: размер больше допустимых {} байт", path.string(), KEY_FILE_MAX_SIZE));
    }

    while (total > 0 && is_trailing_space(key.data()[total - 1])) {
        --total;
    }
    if (total == 0) {
        throw KeyFileError(fmt::format("файл ключа {}: ключ пустой", path.string()));
    }
    key.resize(total);
    return key;
}

std::filesystem::path resolve_key_path(const std::optional<std::filesystem::path>& key_file, const char* credentials_dir) {
    if (key_file) {
        return *key_file;
    }
    if (credentials_dir != nullptr && *credentials_dir != '\0') {
        return std::filesystem::path(credentials_dir) / KEY_CREDENTIAL_NAME;
    }
    throw KeyFileError(fmt::format("не задан файл ключа: укажите --key-file или LoadCredential={}:<путь> в юните systemd", KEY_CREDENTIAL_NAME));
}
