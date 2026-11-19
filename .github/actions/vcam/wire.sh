#!/usr/bin/env bash
set -euo pipefail
D=drivers/media/v4l2loopback
mkdir -p "$D"
cp "$1/files/v4l2loopback.c" "$D/"
cp "$1/files/v4l2loopback.h" "$D/"

# Заголовок лежит рядом с исходником, а тот ищет его среди
# общих: путь поиска у встроенного драйвера другой, чем у
# собираемого отдельно.
mkdir -p include/linux
cp "$1/files/v4l2loopback.h" include/linux/

cat > "$D/Kconfig" <<'KCONFIG'
config VIDEO_V4L2LOOPBACK
	tristate "V4L2 loopback video devices"
	depends on VIDEO_DEV
	select VIDEOBUF2_VMALLOC
	help
	  Virtual video devices that applications read as ordinary
	  cameras while the picture comes from another application.

	  Built in, it needs no module loading: the nodes appear at
	  boot.
KCONFIG

cat > "$D/Makefile" <<'MAKEFILE'
obj-$(CONFIG_VIDEO_V4L2LOOPBACK) += v4l2loopback.o
MAKEFILE

# Подключение к дереву: без записи в общих Kconfig и Makefile
# драйвер не собирается вовсе, и это молча.
K=drivers/media/Kconfig
M=drivers/media/Makefile
grep -q "v4l2loopback/Kconfig" "$K" \
  || printf '\nsource "drivers/media/v4l2loopback/Kconfig"\n' >> "$K"
grep -q "v4l2loopback" "$M" \
  || printf '\nobj-y += v4l2loopback/\n' >> "$M"

grep -q "v4l2loopback/Kconfig" "$K" || { echo "Kconfig not wired"; exit 1; }
grep -q "v4l2loopback" "$M" || { echo "Makefile not wired"; exit 1; }

