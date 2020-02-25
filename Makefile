# SPDX-License-Identifier: MIT
# MLD Poker - A small utility that pokes sleepy devices for MLD Reports
#
# Copyright (c) 2020 Linus Lüssing <linus.luessing@c0d3.blue>
#
# License-Filename: LICENSES/preferred/MIT
#

mldpoker: mldpoker.o chksum.o neigh.o libnetlink.o

mldpoker.o: mldpoker.c neigh.h chksum.h list.h

neigh.o: neigh.c libnetlink.h list.h neigh.h

libnetlink.o: libnetlink.c libnetlink.h

.PHONY: clean

clean:
	rm mldpoker *.o 2> /dev/null || true
