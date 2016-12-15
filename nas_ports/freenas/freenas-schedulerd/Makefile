# $FreeBSD$

PORTNAME=	freenas-schedulerd
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}

CATEGORIES=	freenas
VALID_CATEGORIES+=	freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS periodic tasks daemon

RUN_DEPENDS=	\
		${PYTHON_PKGNAMEPREFIX}apscheduler>0:${PORTSDIR}/devel/py-apscheduler \
		${PYTHON_PKGNAMEPREFIX}jsonpickle>0:${PORTSDIR}/devel/py-jsonpickle \
		${PYTHON_PKGNAMEPREFIX}pytz>0:${PORTSDIR}/devel/py-pytz

USES=		python
USE_PYTHON=	py3kplist
EXTRACT_ONLY=

NO_BUILD=	yes
MAKE_JOBS_UNSAFE= yes
ALL_TARGET=	obj all
WRKSRC=		/usr/middleware_src/schedulerd

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

do-install:
	${MAKE} -C ${WRKSRC} install PREFIX=${STAGEDIR}${PREFIX} PYTHON=${PYTHON_CMD}

post-install:
	${PYTHON_CMD} -m compileall ${STAGEDIR}${PREFIX}/lib/schedulerd
	(cd ${STAGEDIR}${PREFIX}/lib/schedulerd; ${FIND} -E . -type f -regex ".*.pyc?" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print length, $$0}' | ${SORT} -rn \
		| ${AWK} '{print "lib/schedulerd/"$$2 }' >> ${TMPPLIST})

.include <bsd.port.mk>
