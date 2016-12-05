PREFIX ?= /usr/local
PYTHON ?= python

install:
	install etc/serviced ${PREFIX}/etc/rc.d/
	install sbin/serviced ${PREFIX}/sbin/
	install sbin/servicectl ${PREFIX}/sbin/
	install -d ${PREFIX}/lib/serviced
	install -d ${PREFIX}/lib/serviced/src
	cp -a src/ ${PREFIX}/lib/serviced/src/
