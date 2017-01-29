PREFIX ?= /usr/local
PYTHON ?= python

install:
	install -d  ${STAGEDIR}${PREFIX}/etc/serviced.d/
	install -d ${PREFIX}/lib/logd
	install -d ${PREFIX}/lib/logd/src
	install etc/serviced.d/* ${STAGEDIR}${PREFIX}/etc/serviced.d/
	install sbin/logd ${PREFIX}/sbin/
	install sbin/logctl ${PREFIX}/sbin/
	cp -a src/ ${PREFIX}/lib/logd/src/
