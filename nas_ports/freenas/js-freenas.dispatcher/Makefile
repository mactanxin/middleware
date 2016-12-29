# $FreeBSD$

PORTNAME=	js-freenas.dispatcher
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}

CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS javascript dispatcher client

FETCH_DEPENDS=	npm2>0:${PORTSDIR}/www/npm2

BUILD_DEPENDS=  npm2>0:${PORTSDIR}/www/npm2

BROWSERIFY_BUNDLE= ${STAGEDIR}/${PREFIX}/share/js-freenas-dispatcher

EXTRACT_ONLY=

NO_BUILD=	yes
MAKE_JOBS_UNSAFE= yes
ALL_TARGET=	obj all
WRKSRC=		/usr/middleware_src/dispatcher-client/javascript

checksum:
	${ECHO_CMD} ${.TARGET} not needed because building direct

fetch:
	${MAKE} -C ${WRKSRC} fetch

extract:
	:

do-install:
	@mkdir -p ${BROWSERIFY_BUNDLE}
	${MAKE} -C ${WRKSRC} install STAGEDIR=${STAGEDIR} PREFIX=${PREFIX} BROWSERIFY_BUNDLE=${BROWSERIFY_BUNDLE}/middleware.js

.include <bsd.port.mk>
