PREFIX ?= /usr/local
PYTHON ?= python

install:
	install etc/crashd ${PREFIX}/etc/rc.d/
	install sbin/crashd ${PREFIX}/sbin/
	install sbin/crash-wrapper ${PREFIX}/sbin/
	install -d ${PREFIX}/lib/crashd
	install -d ${PREFIX}/lib/crashd/src
	install -d ${PREFIX}/libexec/telemetry
	cp -a src/ ${PREFIX}/lib/crashd/src/
	cp -a libexec/ ${PREFIX}/libexec/telemetry/
