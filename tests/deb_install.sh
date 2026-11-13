#!/bin/bash
# Проверка пакетов в контейнере с systemd: установка, запуск служб под ограничениями юнитов,
# обновление, remove, purge (сценарий tests/deb/check.sh).
#
# Использование: tests/deb_install.sh <каталог с poma-vpn-*.deb> <bookworm|trixie>
# Нужен docker с правом --privileged.
set -euo pipefail

DEBS=$(cd "$1" && pwd)
CODENAME=$2
DIR=$(cd "$(dirname "$0")" && pwd)
IMAGE=poma-vpn-systemd:$CODENAME

# в образах debian policy-rc.d запрещает запуск служб из пакетов, на настоящей машине его нет
docker build -q -t "$IMAGE" - >/dev/null <<DOCKERFILE
FROM debian:$CODENAME
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv >/dev/null \
    && rm -f /usr/sbin/policy-rc.d
CMD ["/lib/systemd/systemd"]
DOCKERFILE

CID=$(docker run -d --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$DEBS":/deb:ro -v "$DIR/deb/check.sh":/check.sh:ro "$IMAGE")
trap 'docker rm -f "$CID" >/dev/null' EXIT
for _ in $(seq 50); do
    state=$(docker exec "$CID" systemctl is-system-running 2>/dev/null || true)
    [ "$state" = running ] || [ "$state" = degraded ] && break
    sleep 0.2
done
# в docker корень смонтирован как private, и каталог LoadCredential= не доходит до службы;
# на обычной машине systemd делает / shared при загрузке
docker exec "$CID" mount --make-rshared /
docker exec "$CID" bash /check.sh
