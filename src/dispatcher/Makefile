PREFIX ?= /usr/local
PYTHON ?= python
BROWSERIFY_BUNDLE= ${PREFIX}/share/js-freenas-dispatcher/middleware.js

install:
	install etc/dispatcher ${STAGEDIR}${PREFIX}/etc/rc.d/
	install etc/serviced.d/* ${STAGEDIR}${PREFIX}/etc/serviced.d/
	install etc/middleware.conf ${STAGEDIR}${PREFIX}/etc/middleware.conf
	install tools/dispatcherd ${STAGEDIR}${PREFIX}/sbin/
	install tools/dispatcherctl ${STAGEDIR}${PREFIX}/sbin/
	install tools/sdsinit ${STAGEDIR}${PREFIX}/sbin/
	install tools/taskworker ${STAGEDIR}${PREFIX}/libexec/
	install -d ${STAGEDIR}${PREFIX}/lib/dispatcher/src
	install -d ${STAGEDIR}${PREFIX}/lib/dispatcher/src/frontend
	install -d ${STAGEDIR}${PREFIX}/lib/dispatcher/src/lib
	install -d ${STAGEDIR}${PREFIX}/lib/dispatcher/src/taskworker
	install -d ${STAGEDIR}${PREFIX}/lib/dispatcher/plugins
	install -d ${STAGEDIR}${PREFIX}/lib/dispatcher/pydev
	install -d ${STAGEDIR}${PREFIX}/lib/dispatcher/ssh
	install -d ${STAGEDIR}${PREFIX}/libexec/dispatcher
	${PYTHON} setup.py build_ext --build-lib=${STAGEDIR}${PREFIX}/lib/dispatcher/src/
	cp src/run.py ${STAGEDIR}${PREFIX}/lib/dispatcher/src/
	cp -R src/frontend/ ${STAGEDIR}${PREFIX}/lib/dispatcher/src/frontend/
	cp -R src/taskworker/ ${STAGEDIR}${PREFIX}/lib/dispatcher/src/taskworker/
	cp -R plugins/ ${STAGEDIR}${PREFIX}/lib/dispatcher/plugins/
	cp -R pydev/ ${STAGEDIR}${PREFIX}/lib/dispatcher/pydev/
	cp -R ssh/ ${STAGEDIR}${PREFIX}/lib/dispatcher/ssh/
	cp -R libexec/ ${STAGEDIR}${PREFIX}/libexec/dispatcher/
	${PYTHON} setup_plugins.py build_ext --build-lib=${STAGEDIR}${PREFIX}/lib/dispatcher/plugins/
	cp -R plugins/*.html ${STAGEDIR}${PREFIX}/lib/dispatcher/plugins/
	cp -R plugins/*.c ${STAGEDIR}${PREFIX}/lib/dispatcher/plugins/
	cp ${BROWSERIFY_BUNDLE} ${STAGEDIR}${PREFIX}/lib/dispatcher/src/frontend/static/middleware.js
