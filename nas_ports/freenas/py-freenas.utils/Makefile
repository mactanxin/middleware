# $FreeBSD$

PORTNAME=	freenas.utils
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS common Python modules

BUILD_DEPENDS=  ${LOCALBASE}/bin/cython:${PORTSDIR}/lang/cython
RUN_DEPENDS=	\
		${PYTHON_PKGNAMEPREFIX}dateutil>0:${PORTSDIR}/devel/py-dateutil \
		${PYTHON_PKGNAMEPREFIX}six>0:${PORTSDIR}/devel/py-six \
		${PYTHON_PKGNAMEPREFIX}msgpack-python>0:${PORTSDIR}/devel/py-msgpack-python

USES=		python
USE_PYTHON=	autoplist distutils
EXTRACT_ONLY=

MAKE_ENV=	VERSION=${PRODUCT_VERSION}
WRKSRC=		/usr/middleware_src/py-freenas.utils

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

.include <bsd.port.mk>
