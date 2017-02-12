# $FreeBSD$

PORTNAME=	freenas-alertd
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}

CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}pushbullet>0:${PORTSDIR}/devel/py-pushbullet

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS alert daemon

USES=		python
USE_PYTHON=	py3kplist
EXTRACT_ONLY=

NO_BUILD=	yes
MAKE_JOBS_UNSAFE= yes
ALL_TARGET=	obj all
WRKSRC=		/usr/middleware_src/alertd

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

do-install:
	${MAKE} -C ${WRKSRC} install PREFIX=${STAGEDIR}${PREFIX} PYTHON=${PYTHON_CMD}

post-install:
	${PYTHON_CMD} -m compileall ${STAGEDIR}${PREFIX}/lib/alertd
	(cd ${STAGEDIR}${PREFIX}/lib/alertd; ${FIND} -E . -type f -regex ".*.pyc?" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print length, $$0}' | ${SORT} -rn \
		| ${AWK} '{print "lib/alertd/"$$2 }' >> ${TMPPLIST})

	(cd ${STAGEDIR}${PREFIX}/lib/alertd/emitters; ${FIND} . -type f -regex ".*.pyc?" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print length, $$0}' | ${SORT} -rn \
		| ${AWK} '{print "lib/alertd/emitters/"$$2 }' >> ${TMPPLIST})

	(cd ${STAGEDIR}${PREFIX}/lib/alertd/templates; ${FIND} . -type f -regex ".*.mako" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print length, $$0}' | ${SORT} -rn \
		| ${AWK} '{print "lib/alertd/templates/"$$2 }' >> ${TMPPLIST})

.include <bsd.port.mk>
