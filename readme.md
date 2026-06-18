# VPN

Простой VPN-туннель на C++17 для Linux.

Проект состоит из двух приложений:

- `vpn-server` — серверная часть, поднимает TUN-интерфейс, настраивает NAT/forwarding и принимает UDP-пакеты от клиентов.
- `vpn-client` — клиентская часть, поднимает TUN-интерфейс, перенаправляет трафик через UDP-туннель на сервер.

> Важно: проект предназначен для Linux и требует запуска от `root`, так как использует `/dev/net/tun`, маршруты, `iptables` и настройку сетевых интерфейсов.

## Возможности

- Создание TUN-интерфейса.
- UDP-туннель между клиентом и сервером.
- Настройка маршрута по умолчанию на клиенте через VPN.
- Настройка NAT и forwarding на сервере.
- Настраиваемые параметры через командную строку.
- Логирование через `syslog`.
- Увеличение буферов UDP-сокета для повышения производительности.

## Зависимости

Нужны:

- C++17 compiler
- CMake
- Boost.Program_options
- fmt
- pthread
- iproute2
- iptables

### Ubuntu / Debian

```bash
apt update
apt install -y \
    build-essential \
    cmake \
    libboost-program-options-dev \
    libfmt-dev \
    iproute2 \
    iptables
```

## Сборка

```bash
mkdir build && cd build  
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

После сборки бинарники будут примерно здесь:

```bash
build/src/server/vpn-server
build/src/client/vpn-client
```
## Запуск сервера

Минимальный пример:

```bash
sudo ./vpn-server --port 1194
```

Полный пример:

```bash
sudo ./vpn-server \
    --port 1194 \
    --mtu 1420 \
    --tun-name tun0 \
    --tun-ip 192.168.200.1
```

Короткие параметры:

```bash
sudo ./vpn-server -p 1194 -m 1420 -n tun0 -i 192.168.200.1
```

### Параметры сервера

| Параметр | Коротко | Описание | По умолчанию |
|---|---:|---|---|
| `--help` | `-h` | Показать справку | — |
| `--port` | `-p` | UDP-порт сервера | обязательный |
| `--mtu` | `-m` | MTU TUN-интерфейса | `1420` |
| `--tun-name` | `-n` | Имя TUN-интерфейса | `tun0` |
| `--tun-ip` | `-i` | IP-адрес TUN-интерфейса сервера | `192.168.200.1` |

## Запуск клиента

Минимальный пример:

```bash
sudo ./vpn-client --server <SERVER_PUBLIC_IP> --port 1194
```

Пример:

```bash
sudo ./vpn-client \
    --server 1.2.3.4 \
    --port 1194 \
    --mtu 1420 \
    --tun-name tun0 \
    --tun-ip 192.168.200.2
```

Короткие параметры:

```bash
sudo ./vpn-client -s 1.2.3.4 -p 1194 -m 1420 -n tun0 -i 192.168.200.2
```

### Параметры клиента

| Параметр | Коротко | Описание | По умолчанию |
|---|---:|---|---|
| `--help` | `-h` | Показать справку | — |
| `--server` | `-s` | Публичный IP сервера | обязательный |
| `--port` | `-p` | UDP-порт сервера | обязательный |
| `--mtu` | `-m` | MTU TUN-интерфейса | `1420` |
| `--tun-name` | `-n` | Имя TUN-интерфейса | `tun0` |
| `--tun-ip` | `-i` | IP-адрес TUN-интерфейса клиента | `192.168.200.2` |

## Проверка работы

На сервере:

```bash
ip addr show tun0
ip route
sudo iptables -t nat -L -n -v
sudo iptables -L FORWARD -n -v
```

На клиенте:

```bash
ip addr show tun0
ip route
ping 192.168.200.1
```

Проверка внешнего IP через VPN:

```bash
curl ifconfig.me
```

## Логи

Проект пишет логи в `syslog`.

Просмотр логов через `journalctl`:

```bash
journalctl -f -t vpn-server
journalctl -f -t vpn-client
```

## Важное ограничение безопасности

На данный момент туннель передаёт IP-пакеты поверх UDP без шифрования.

Это означает:

- трафик может быть прочитан между клиентом и сервером;
- возможна подмена пакетов;
- нет аутентификации клиента;
- это не production-ready VPN.

Для реального использования нужно добавить:

- шифрование;
- аутентификацию;
- защиту от replay-атак;
- проверку целостности пакетов.

Например:

- ChaCha20-Poly1305;
- AES-GCM;
- libsodium;
- OpenSSL EVP API.
