# poma-vpn

![VPN preview](logo/logo.png)

Личный VPN для Linux: TUN-интерфейс поверх UDP, пакеты шифруются XChaCha20-Poly1305 (libsodium) общим ключом.
C++20, сборка и пакеты под Debian 12 и Debian 13.

- `vpn-server` (пакет `poma-vpn-server`) поднимает TUN, принимает клиентов по UDP и выпускает их трафик
  в интернет через NAT (`iptables MASQUERADE`).
- `vpn-client` (пакет `poma-vpn-client`) поднимает TUN и направляет весь трафик машины через сервер.

Обеим программам нужен root: они создают `/dev/net/tun`, настраивают адреса, маршруты и `iptables`.
Под systemd от root остаются только `CAP_NET_ADMIN` (и `CAP_NET_RAW` у сервера для `iptables`).

## Установка

Пакеты для Debian 12 (`-debian12.deb`) и Debian 13 (`-debian13.deb`) лежат в
[релизах](https://github.com/khromenokroman/vpn/releases). Зависимости (`iproute2`, `iptables`, библиотеки)
ставит `apt`.

### Сервер

```bash
sudo apt install ./poma-vpn-server_X.Y.Z.0_amd64-debian13.deb
```

При первой установке создаётся случайный ключ `/etc/poma-vpn/key` (32 байта в base64, права `600`).
Служба сама не запускается: сначала проверить параметры в `/etc/default/poma-vpn-server`.

```bash
# /etc/default/poma-vpn-server
VPN_SERVER_OPTS="--port 51820 --mtu 1380"
```

```bash
sudo systemctl enable --now poma-vpn-server
journalctl -u poma-vpn-server
```

Если на сервере есть межсетевой экран, UDP-порт должен быть открыт; правило `INPUT` для порта сервер
добавляет сам и убирает при остановке.

### Клиент

```bash
sudo apt install ./poma-vpn-client_X.Y.Z.0_amd64-debian13.deb
# ключ с сервера, тот же файл
sudo install -d -m 700 /etc/poma-vpn
sudo install -m 600 key /etc/poma-vpn/key
```

```bash
# /etc/default/poma-vpn-client
VPN_CLIENT_OPTS="--server 203.0.113.10 --port 51820 --tun-ip 192.168.200.2 --mtu 1380"
```

```bash
sudo systemctl enable --now poma-vpn-client
```

У каждого клиента свой `--tun-ip` из подсети /24 сервера (`192.168.200.2`, `192.168.200.3`, ...).

### Обновление и удаление

- Обновление пакета перезапускает работающую службу; выключенная остаётся выключенной,
  `/etc/default/*` и ключ сохраняются.
- `apt remove` останавливает службу: сервер убирает свои правила `iptables`, клиент свои маршруты.
- `apt purge` удаляет `/etc/default/poma-vpn-*`. Ключ `/etc/poma-vpn/key` остаётся: без него перестанут
  работать клиенты, удалить его можно вручную.

## Ключ

Клиент и сервер используют один общий ключ. Он читается только из файла: в аргументах командной строки
его видели бы все пользователи через `ps` и `/proc/<pid>/cmdline`.

Создать вручную (без пакета):

```bash
sudo install -d -m 700 /etc/poma-vpn
head -c 32 /dev/urandom | base64 | sudo install -m 600 /dev/stdin /etc/poma-vpn/key
```

Требования к файлу, иначе программа завершится с ошибкой:

- обычный файл, не символьная ссылка;
- владелец тот же пользователь, от которого запущена программа (`root`);
- нет прав для группы и остальных (`600` или `400`);
- размер от 1 до 4096 байт; завершающие пробелы и переводы строки отбрасываются.

Путь задаётся параметром `--key-file`. Без него ключ берётся из `$CREDENTIALS_DIRECTORY/vpn-key`:
юниты из пакетов передают его через `LoadCredential=vpn-key:/etc/poma-vpn/key`, и самой службе доступ
к `/etc` не нужен.

## Параметры

### vpn-server

| Параметр | Коротко | Описание | По умолчанию |
|---|---|---|---|
| `--port` | `-p` | UDP-порт | обязательный |
| `--mtu` | `-m` | MTU TUN-интерфейса | `1420` |
| `--tun-name` | `-n` | имя TUN-интерфейса | `tun0` |
| `--tun-ip` | `-i` | адрес сервера в туннеле; подсеть клиентов - его /24 | `192.168.200.1` |
| `--external-iface` | `-e` | интерфейс для NAT | интерфейс маршрута по умолчанию |
| `--key-file` | `-k` | файл общего ключа | `$CREDENTIALS_DIRECTORY/vpn-key` |
| `--version` | `-V` | версия | |
| `--help` | `-h` | справка | |

Что сервер меняет в системе и возвращает при остановке:

- создаёт TUN-интерфейс;
- включает `net.ipv4.ip_forward` (при остановке не выключает: он может быть нужен чему-то ещё);
- добавляет 4 правила `iptables`: `MASQUERADE` подсети туннеля на внешнем интерфейсе, `FORWARD` из туннеля
  наружу, `FORWARD` обратно только для ответов (conntrack `RELATED,ESTABLISHED`), `INPUT` для UDP-порта.
  При остановке они удаляются, а при запуске сначала убираются такие же, оставшиеся после `SIGKILL`.

### vpn-client

| Параметр | Коротко | Описание | По умолчанию |
|---|---|---|---|
| `--server` | `-s` | IPv4-адрес сервера | обязательный |
| `--port` | `-p` | UDP-порт сервера | обязательный |
| `--mtu` | `-m` | MTU TUN-интерфейса | `1420` |
| `--tun-name` | `-n` | имя TUN-интерфейса | `tun0` |
| `--tun-ip` | `-i` | адрес клиента в туннеле | `192.168.200.2` |
| `--key-file` | `-k` | файл общего ключа | `$CREDENTIALS_DIRECTORY/vpn-key` |
| `--version` | `-V` | версия | |
| `--help` | `-h` | справка | |

Маршрут по умолчанию клиент не трогает. Он добавляет маршрут до сервера через прежний шлюз и два маршрута
`0.0.0.0/1` и `128.0.0.0/1` через TUN: они точнее маршрута по умолчанию и забирают весь трафик.
При остановке маршруты удаляются, при аварийном завершении исчезают вместе с TUN-интерфейсом,
и сеть работает как до запуска. Без маршрута по умолчанию клиент не стартует.

Раз в 10 с клиент отправляет зашифрованный keep-alive: сервер забывает клиента после 60 с тишины,
а NAT по пути закрывает UDP-сопоставление ещё раньше.

## Формат пакета

```text
[magic "POMA", 4 байта][nonce, 24 байта][шифротекст + тег Poly1305, 16 байт]
```

- ключ: `crypto_generichash` (BLAKE2b, 32 байта) от содержимого файла ключа;
- nonce случайный для каждого пакета;
- внутри шифрования IPv4-пакет или служебный пакет, первый байт которого `0x00`
  (у IP-пакета там версия 4 или 6). Keep-alive: `[0x00][0x01][0x00][0x00][IPv4 клиента в туннеле]`.

Накладные расходы 44 байта на пакет. При MTU внешней сети 1500 и заголовках IPv4 + UDP (28 байт) для туннеля
остаётся 1428, поэтому в `/etc/default` стоит `--mtu 1380` с запасом на PPPoE и туннели провайдера.

## Ограничения

- нет защиты от повтора пакетов (replay): перехваченный пакет можно отправить ещё раз;
- нет handshake и сессионных ключей: один долговременный ключ на всех, без ротации и forward secrecy;
- один ключ на оба направления;
- только IPv4.

## Relay

`setup-relay.sh` настраивает промежуточный сервер, который пробрасывает UDP-порт VPN на основной сервер
(DNAT + MASQUERADE, правила сохраняются через `iptables-persistent`). Клиенты указывают в `--server`
адрес relay.

```bash
sudo ./setup-relay.sh 203.0.113.10 51820
```

## Сборка из исходников

Debian 12 или 13:

```bash
sudo apt install build-essential cmake pkg-config \
    libboost-program-options-dev libsodium-dev libfmt-dev libgtest-dev libgmock-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
cd build && cpack -G DEB   # poma-vpn-server_*.deb и poma-vpn-client_*.deb
```

Бинарники: `build/vpn-server`, `build/vpn-client`. Тесты без GoogleTest: `-DBUILD_TESTS=OFF`.

### Проверки в docker

```bash
tests/deb_install.sh build bookworm   # установка, службы под systemd, обновление, remove, purge
tests/e2e.sh build trixie             # туннель между контейнерами: сервер, клиент и узел за сервером
```

Обоим скриптам нужен docker с `--privileged`, `e2e.sh` ещё модуль `tun`. Их же запускает CI
(`.github/workflows/release.yml`) для Debian 12 и 13; тег `vX.Y.Z.0` публикует релиз с пакетами.

## Журнал

Программы пишут в syslog и, при ошибках запуска, в stderr:

```bash
journalctl -u poma-vpn-server -f
journalctl -u poma-vpn-client -f
```
