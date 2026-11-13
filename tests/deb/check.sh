#!/bin/bash
# Сценарий внутри контейнера с systemd (запускает tests/deb_install.sh): установка poma-vpn-server и
# poma-vpn-client из /deb, ключ, работа служб под ограничениями юнитов, обновление, remove, purge.
set -u
fail=0
ok() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fail=1; }
journal() { journalctl -u "$1" --no-pager | tail -5; }
wait_active() { for _ in $(seq 50); do systemctl is-active -q "$1" && return 0; sleep 0.1; done; return 1; }
srv_rules() { { iptables -S; iptables -t nat -S; } | grep -cE '192.168.200|tun0|51820'; }
export DEBIAN_FRONTEND=noninteractive
KEY=/etc/poma-vpn/key

apt-get update -qq >/dev/null
apt-get install -y -qq /deb/*.deb >/dev/null 2>&1 || bad "apt install"
[ "$(stat -c '%a %U' "$KEY" 2>/dev/null)" = "600 root" ] && ok "сервер создал ключ, права 600 root" \
    || bad "ключ: $(stat -c '%a %U' "$KEY" 2>&1)"
[ "$(stat -c '%a' /etc/poma-vpn)" = 700 ] && ok "каталог ключа 700" || bad "каталог ключа $(stat -c '%a' /etc/poma-vpn)"
key_hash=$(sha256sum "$KEY")
for u in poma-vpn-server poma-vpn-client; do
    systemctl is-active -q $u && bad "$u запущена сразу после установки" || ok "$u не запущена до настройки"
    systemctl is-enabled -q $u && bad "$u включена без настройки" || ok "$u не включена до настройки"
done

# сервер на внешнем интерфейсе контейнера
sed -i 's/^VPN_SERVER_OPTS=.*/VPN_SERVER_OPTS="--port 51820 --external-iface eth0"/' /etc/default/poma-vpn-server
echo 0 > /proc/sys/net/ipv4/ip_forward  # в docker он включён заранее
systemctl enable -q --now poma-vpn-server
wait_active poma-vpn-server && ok "сервер запущен под ограничениями юнита" || { bad "сервер не запущен"; journal poma-vpn-server; }
sleep 0.5
ip link show tun0 >/dev/null 2>&1 && ok "сервер создал tun0" || bad "нет tun0"
[ "$(srv_rules)" = 4 ] && ok "правила iptables добавлены (4)" || { bad "правил iptables: $(srv_rules)"; journal poma-vpn-server; }
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] && ok "ip_forward включён" || bad "ip_forward не включён"
pid=$(systemctl show -p MainPID --value poma-vpn-server)
grep -q '^CapBnd:\s*0000000000003000$' "/proc/$pid/status" && ok "у сервера только CAP_NET_ADMIN и CAP_NET_RAW" \
    || bad "привилегии сервера: $(grep CapBnd "/proc/$pid/status")"

# клиент в том же контейнере: свой TUN и подсеть, сервер - адрес eth0
eth0_ip=$(ip -4 -o addr show eth0 | awk '{split($4, a, "/"); print a[1]}')
sed -i "s|^VPN_CLIENT_OPTS=.*|VPN_CLIENT_OPTS=\"--server $eth0_ip --port 51820 --tun-name tun1 --tun-ip 192.168.201.2\"|" \
    /etc/default/poma-vpn-client
default_before=$(ip route show default)
systemctl start poma-vpn-client
wait_active poma-vpn-client && ok "клиент запущен под ограничениями юнита" || { bad "клиент не запущен"; journal poma-vpn-client; }
sleep 0.5
ip route | grep -q '0.0.0.0/1 dev tun1' && ok "клиент добавил маршрут 0.0.0.0/1 через tun1" || { bad "нет маршрута 0.0.0.0/1"; journal poma-vpn-client; }
pid=$(systemctl show -p MainPID --value poma-vpn-client)
grep -q '^CapBnd:\s*0000000000001000$' "/proc/$pid/status" && ok "у клиента только CAP_NET_ADMIN" \
    || bad "привилегии клиента: $(grep CapBnd "/proc/$pid/status")"
systemctl stop poma-vpn-client
ip route | grep -qE '0.0.0.0/1|128.0.0.0/1|tun1' && bad "маршруты клиента остались" || ok "клиент остановлен, маршруты удалены"
[ "$(ip route show default)" = "$default_before" ] && ok "маршрут по умолчанию не изменён" || bad "маршрут по умолчанию изменён"
journalctl -u poma-vpn-client --no-pager | grep -qE '[Оо]шибк|[Нн]е удалось' && { bad "ошибки в журнале клиента"; journal poma-vpn-client; } \
    || ok "в журнале клиента нет ошибок"

# обновление: включённая работающая служба перезапускается, настройки и ключ сохраняются
old_pid=$(systemctl show -p MainPID --value poma-vpn-server)
apt-get install -y -qq --reinstall /deb/*.deb >/dev/null 2>&1 || bad "переустановка"
grep -q -- '--external-iface eth0' /etc/default/poma-vpn-server && ok "настройки сохранены при обновлении" || bad "настройки затёрты"
[ "$(sha256sum "$KEY")" = "$key_hash" ] && ok "ключ не перезаписан при обновлении" || bad "ключ перезаписан"
wait_active poma-vpn-server && [ "$(systemctl show -p MainPID --value poma-vpn-server)" != "$old_pid" ] \
    && ok "сервер перезапущен после обновления" || bad "сервер не перезапущен"
systemctl is-active -q poma-vpn-client && bad "остановленный клиент запустился при обновлении" || ok "остановленный клиент не запущен"
sleep 0.5
[ "$(srv_rules)" = 4 ] && ok "после перезапуска правил iptables снова 4" || bad "правил iptables после перезапуска: $(srv_rules)"
journalctl -u poma-vpn-server --no-pager | grep -qE '[Оо]шибк|[Нн]е удалось' && { bad "ошибки в журнале сервера"; journal poma-vpn-server; } \
    || ok "в журнале сервера нет ошибок"

apt-get remove -y -qq poma-vpn-server poma-vpn-client >/dev/null 2>&1 || bad "remove"
systemctl is-active -q poma-vpn-server && bad "сервер работает после удаления" || ok "remove: сервер остановлен"
[ "$(srv_rules)" = 0 ] && ok "remove: правила iptables удалены" || bad "remove: правил iptables $(srv_rules)"
[ -e /etc/default/poma-vpn-server ] && ok "remove: настройки остались" || bad "remove: настройки удалены"
apt-get purge -y -qq poma-vpn-server poma-vpn-client >/dev/null 2>&1 || bad "purge"
[ ! -e /etc/default/poma-vpn-server ] && [ ! -e /etc/default/poma-vpn-client ] && ok "purge: настройки удалены" || bad "purge: настройки остались"
[ "$(sha256sum "$KEY" 2>/dev/null)" = "$key_hash" ] && ok "purge: ключ сохранён" || bad "purge: ключ удалён"

apt-get install -y -qq /deb/*.deb >/dev/null 2>&1 || bad "повторная установка"
[ "$(sha256sum "$KEY")" = "$key_hash" ] && ok "повторная установка: прежний ключ" || bad "повторная установка: ключ сменился"
exit $fail
