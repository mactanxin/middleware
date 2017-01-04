# $FreeBSD$

PORTNAME=	wbclient
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	Python wrapper around Samba wbclient.

BUILD_DEPENDS=  ${LOCALBASE}/bin/cython:${PORTSDIR}/lang/cython \
		talloc>=2.1.2:${PORTSDIR}/devel/talloc \
		samba45>=0:${PORTSDIR}/net/samba45

USES=		python
USE_PYTHON=	autoplist distutils
EXTRACT_ONLY=

WRKSRC=		/usr/middleware_src/py-wbclient

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

.include <bsd.port.mk>
