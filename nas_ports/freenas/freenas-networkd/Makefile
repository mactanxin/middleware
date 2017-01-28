# $FreeBSD$

PORTNAME=	freenas-networkd
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS network configuration daemon

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}freenas.dispatcher>0:${PORTSDIR}/freenas/py-freenas.dispatcher \
		${PYTHON_PKGNAMEPREFIX}netif>0:${PORTSDIR}/freenas/py-netif \
		${PYTHON_PKGNAMEPREFIX}logd>0:${PORTSDIR}/freenas/py-logd

USES=		python
USE_PYTHON=	py3kplist
EXTRACT_ONLY=

NO_BUILD=	yes
MAKE_JOBS_UNSAFE= yes
ALL_TARGET=	obj all
WRKSRC=		/usr/middleware_src/networkd

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

do-install:
	${MAKE} -C ${WRKSRC} install PREFIX=${STAGEDIR}${PREFIX} PYTHON=${PYTHON_CMD}

post-install:
	${PYTHON_CMD} -m compileall ${STAGEDIR}${PREFIX}/lib/networkd

.include <bsd.port.mk>
