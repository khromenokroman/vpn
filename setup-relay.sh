#!/bin/bash
# Скрипт настройки relay-сервера для проксирования UDP-трафика VPN.
# Запускать от root на российском VPS (Ubuntu/Debian).
# После настройки клиенты подключаются к IP этого relay вместо реального VPN-сервера.

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Запустите от root: sudo $0"
    exit 1
fi

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Использование: $0 <IP_VPN_сервера> <порт>"
    echo "Пример:        $0 132.243.124.73 51820"
    exit 1
fi

VPN_SERVER="$1"
VPN_PORT="$2"

echo "Relay: $(hostname -I | awk '{print $1}') -> $VPN_SERVER:$VPN_PORT"

# Форвардинг пакетов
echo 1 > /proc/sys/net/ipv4/ip_forward
grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# Удалить старые правила если есть
iptables -t nat -D PREROUTING -p udp --dport "$VPN_PORT" -j DNAT --to-destination "$VPN_SERVER:$VPN_PORT" 2>/dev/null || true
iptables -t nat -D POSTROUTING -p udp -d "$VPN_SERVER" --dport "$VPN_PORT" -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -p udp -d "$VPN_SERVER" --dport "$VPN_PORT" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -p udp -s "$VPN_SERVER" --sport "$VPN_PORT" -j ACCEPT 2>/dev/null || true

# Добавить правила
iptables -t nat -A PREROUTING  -p udp --dport "$VPN_PORT" -j DNAT --to-destination "$VPN_SERVER:$VPN_PORT"
iptables -t nat -A POSTROUTING -p udp -d "$VPN_SERVER"   --dport "$VPN_PORT" -j MASQUERADE
iptables -A FORWARD -p udp -d "$VPN_SERVER" --dport "$VPN_PORT" -j ACCEPT
iptables -A FORWARD -p udp -s "$VPN_SERVER" --sport "$VPN_PORT" -j ACCEPT

# Сохранить правила
if ! dpkg -l iptables-persistent &>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent
fi
netfilter-persistent save

echo ""
echo "Готово. Клиенты должны подключаться к: $(hostname -I | awk '{print $1}'):$VPN_PORT"
