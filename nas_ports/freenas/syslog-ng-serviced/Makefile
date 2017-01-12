# $FreeBSD$

PORTNAME=	syslog-ng-serviced
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}

CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	serviced syslog-ng plugin

RUN_DEPENDS=	libserviced>0:${PORTSDIR}/freenas/libserviced \
		syslog-ng37>=3.7.3:${PORTSDIR}/sysutils/syslog-ng37

BUILD_DEPENDS=	${RUN_DEPENDS}

USE_GNOME=	glib20
USES=		cmake pkgconfig
EXTRACT_ONLY=

NO_BUILD=	yes
MAKE_JOBS_UNSAFE= yes
ALL_TARGET=	obj all
WRKSRC=		/usr/middleware_src/syslog-ng-serviced

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

.include <bsd.port.mk>
