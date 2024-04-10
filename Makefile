# binhlock - simple screen locker
# See LICENSE file for copyright and license details.

# paths
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man
BIN = zig-out/bin/

all: binhlock

binhlock: src/*.zig *.zig
	zig build

clean:
	rm -f ${BIN}binhlock

install: all
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp -f ${BIN}binhlock ${DESTDIR}${PREFIX}/bin
	chmod 755 ${DESTDIR}${PREFIX}/bin/binhlock
	chmod u+s ${DESTDIR}${PREFIX}/bin/binhlock

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/binhlock

.PHONY: all clean install uninstall
