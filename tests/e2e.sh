#!/bin/bash
# E2E: сервер, клиент и цель в отдельных контейнерах с установленными пакетами poma-vpn.
# Сеть wan (172.30.1.0/24): сервер .2 и цель .4; сеть lan (172.30.2.0/24): сервер .2 и клиент .3.
# Цель доступна клиенту только через туннель.
#
# Использование: tests/e2e.sh <каталог с poma-vpn-*.deb> <bookworm|trixie>
# Нужен docker с правом --privileged и модуль tun.
set -u

DEBS=$(cd "$1" && pwd)
CODENAME=$2
img=poma-vpn-e2e:$CODENAME
docker build -q -t "$img" -f - "$DEBS" >/dev/null <<DOCKERFILE || exit 1
FROM debian:$CODENAME
COPY *.deb /tmp/deb/
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/deb/*.deb iputils-ping procps tcpdump >/dev/null && rm -rf /tmp/deb /var/lib/apt/lists/*
DOCKERFILE

fail=0
check() { if eval "$2"; then echo "OK   $1"; else echo "FAIL $1"; fail=1; fi; }

cleanup() { docker rm -f vpn-srv vpn-cli vpn-tgt >/dev/null 2>&1; docker network rm vpn-wan vpn-lan >/dev/null 2>&1; }
cleanup
docker network create --subnet 172.30.1.0/24 vpn-wan >/dev/null
docker network create --subnet 172.30.2.0/24 vpn-lan >/dev/null
docker run -d --name vpn-srv --network vpn-wan --ip 172.30.1.2 --sysctl net.ipv4.ip_forward=1 --cap-add NET_ADMIN --device /dev/net/tun "$img" sleep 600 >/dev/null
docker network connect --ip 172.30.2.2 vpn-lan vpn-srv
docker run -d --name vpn-cli --network vpn-lan --ip 172.30.2.3 --privileged --sysctl net.ipv4.ip_forward=0 "$img" sleep 600 >/dev/null
docker run -d --name vpn-tgt --network vpn-wan --ip 172.30.1.4 --cap-add NET_ADMIN "$img" sleep 600 >/dev/null
# MASQUERADE на внешнем интерфейсе eth0 (wan); обратный маршрут цели нужен для проверки пинга цель -> клиент
docker exec vpn-tgt ip route add 192.168.200.0/24 via 172.30.1.2
for n in vpn-srv vpn-cli; do docker exec $n bash -c 'install -d -m700 /etc/poma-vpn; printf "e2e-secret\n" > /etc/poma-vpn/key; chmod 600 /etc/poma-vpn/key'; done

srv_rules() { docker exec vpn-srv bash -c 'iptables -S; iptables -t nat -S' | grep -cE '192.168.200|tun0|51820'; }
cli_default_before=$(docker exec vpn-cli ip route show default)

docker exec -d vpn-srv bash -c 'vpn-server -p 51820 -e eth0 -k /etc/poma-vpn/key >/tmp/out.log 2>&1'
sleep 1
check "правила iptables сервера добавлены (4)" '[ "$(srv_rules)" = 4 ]'
docker exec -d vpn-cli bash -c 'vpn-client -s 172.30.2.2 -p 51820 -k /etc/poma-vpn/key >/tmp/out.log 2>&1'
sleep 2

check "цель -> клиент до первого пакета клиента (сервер узнал клиента по keep-alive)" 'docker exec vpn-tgt ping -c2 -W2 192.168.200.2 >/dev/null'
check "клиент -> цель через туннель" 'docker exec vpn-cli ping -c3 -W2 172.30.1.4 >/dev/null'
check "клиент -> сервер в туннеле 192.168.200.1" 'docker exec vpn-cli ping -c2 -W2 192.168.200.1 >/dev/null'
check "маршрут до цели через tun0" 'docker exec vpn-cli ip route get 172.30.1.4 | grep -q "dev tun0"'
check "маршрут по умолчанию клиента не изменён" '[ "$(docker exec vpn-cli ip route show default)" = "$cli_default_before" ]'
check "нет ip_forward на клиенте" '[ "$(docker exec vpn-cli cat /proc/sys/net/ipv4/ip_forward)" = 0 ]'

# повтор: перехватить зашифрованный ping клиента и отправить его серверу ещё 5 раз с другого порта;
# echo request до цели не должен дойти ни разу, и адрес клиента на сервере не должен смениться
tgt_pings() { docker exec vpn-tgt iptables -nvxL INPUT | awk '/icmptype 8/ {print $1}'; }
docker exec vpn-tgt iptables -A INPUT -p icmp --icmp-type echo-request
docker exec -d vpn-cli timeout 10 tcpdump -U -i eth0 -c1 -w /tmp/ping.pcap 'udp and dst port 51820 and greater 150'
sleep 1
docker exec vpn-cli ping -c1 -W2 172.30.1.4 >/dev/null
# файл готов, когда tcpdump завершился
for i in $(seq 50); do docker exec vpn-cli pgrep -x tcpdump >/dev/null || break; sleep 0.1; done
# pcap: заголовок файла 24 + записи 16, кадр: Ethernet 14 + IPv4 20 + UDP 8
docker exec vpn-cli bash -c 'tail -c +83 /tmp/ping.pcap > /tmp/ping.bin'
check "перехвачен зашифрованный ping (84 + 44 байта)" '[ "$(docker exec vpn-cli stat -c %s /tmp/ping.bin)" = 128 ]'
docker exec vpn-tgt iptables -Z INPUT
docker exec vpn-cli bash -c 'for i in 1 2 3 4 5; do cat /tmp/ping.bin > /dev/udp/172.30.2.2/51820; done'
sleep 1
check "повтор перехваченного пакета не дошёл до цели (0 из 5)" '[ "$(tgt_pings)" = 0 ]'
check "после повтора туннель работает" 'docker exec vpn-cli ping -c2 -W2 172.30.1.4 >/dev/null'
check "настоящий ping дошёл до цели (счётчик работает)" '[ "$(tgt_pings)" -ge 2 ]'

stop_proc() {  # $1 контейнер, $2 программа, $3 сигнал
    local b t0
    b=$(docker exec $1 pgrep -x $2)
    t0=$(date +%s%N); docker exec $1 kill -$3 $b
    for i in $(seq 100); do docker exec $1 kill -0 $b 2>/dev/null || break; sleep 0.05; done
    echo $(( ($(date +%s%N) - t0) / 1000000 ))
}

# перезапуск сервера: новая сессия, клиент снова принят по ближайшему keep-alive (до 10 с)
stop_proc vpn-srv vpn-server TERM >/dev/null
docker exec -d vpn-srv bash -c 'vpn-server -p 51820 -e eth0 -k /etc/poma-vpn/key >/tmp/out.log 2>&1'
t0=$(date +%s)
for i in $(seq 30); do docker exec vpn-cli ping -c1 -W1 172.30.1.4 >/dev/null 2>&1 && break; done
check "после перезапуска сервера туннель восстановлен за $(( $(date +%s) - t0 )) с (не больше 15)" '[ $(( $(date +%s) - t0 )) -le 15 ] && docker exec vpn-cli ping -c1 -W2 172.30.1.4 >/dev/null'

ms=$(stop_proc vpn-cli vpn-client TERM); echo "     клиент остановлен за ${ms} мс"
check "клиент: маршруты VPN удалены" '! docker exec vpn-cli ip route | grep -qE "172.30.2.2|0.0.0.0/1|128.0.0.0/1|tun0"'
check "клиент: код выхода 0, вывода нет" '[ -z "$(docker exec vpn-cli cat /tmp/out.log)" ]'

# аварийное завершение: маршруты через tun0 уходят вместе с интерфейсом
docker exec -d vpn-cli bash -c 'vpn-client -s 172.30.2.2 -p 51820 -k /etc/poma-vpn/key'
sleep 2
check "клиент перезапущен, туннель работает" 'docker exec vpn-cli ping -c2 -W2 172.30.1.4 >/dev/null'
stop_proc vpn-cli vpn-client KILL >/dev/null
check "после SIGKILL клиента нет tun0 и маршрутов /1" '! docker exec vpn-cli ip route | grep -qE "0.0.0.0/1|128.0.0.0/1|tun0"'
check "после SIGKILL клиента сервер в lan доступен напрямую" 'docker exec vpn-cli ping -c1 -W2 172.30.2.2 >/dev/null'

ms=$(stop_proc vpn-srv vpn-server TERM); echo "     сервер остановлен за ${ms} мс"
check "сервер: правила iptables удалены" '[ "$(srv_rules)" = 0 ]'

[ "${E2E_KEEP:-}" = 1 ] || cleanup
exit $fail
