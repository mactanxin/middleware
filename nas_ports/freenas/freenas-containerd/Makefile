# $FreeBSD$

PORTNAME=	freenas-containerd
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
CATEGORIES=	freenas
VALID_CATEGORIES+=	freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS container daemon

RUN_DEPENDS=	\
		${PYTHON_PKGNAMEPREFIX}gevent>0:${PORTSDIR}/devel/py-gevent \
		${PYTHON_PKGNAMEPREFIX}gevent-websocket>0:${PORTSDIR}/www/py-gevent-websocket \
		${PYTHON_PKGNAMEPREFIX}setproctitle>0:${PORTSDIR}/devel/py-setproctitle \
		${PYTHON_PKGNAMEPREFIX}docker-py>0:${PORTSDIR}/devel/py-docker \
		${PYTHON_PKGNAMEPREFIX}dockerpty>0:${PORTSDIR}/devel/py-dockerpty \
		uefi-edk2-bhyve>0:${PORTSDIR}/sysutils/uefi-edk2-bhyve \
		uefi-edk2-bhyve-csm>0:${PORTSDIR}/sysutils/uefi-edk2-bhyve-csm

USES=		python
EXTRACT_ONLY=

NO_BUILD=	yes
MAKE_JOBS_UNSAFE= yes
ALL_TARGET=	obj all
WRKSRC=		/usr/middleware_src/containerd

fetch:
	${MAKE} -C ${WRKSRC} fetch WRKSRC=${WRKSRC}

checksum extract:
	${ECHO_CMD} ${.TARGET} not needed because building direct

do-install:
	${MAKE} -C ${WRKSRC} install PREFIX=${STAGEDIR}${PREFIX} PYTHON=${PYTHON_CMD} WRKSRC=${WRKSRC}

post-install:
	${PYTHON_CMD} -m compileall ${STAGEDIR}${PREFIX}/lib/containerd
	(cd ${STAGEDIR}${PREFIX}/lib/containerd; ${FIND} -E . -type f -regex \
		".*((.pyc?)|(.so)|(.jso?n?)|(.html)|(.map)|(.css)|(.png)|(.jpg)|(.gif)|(.md)|(.txt)|(.swf)|(.eot)|(.svg)|(.ttf)|(.woff2?)|(.c))+$$" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print "lib/containerd/"$$0 }' >> ${TMPPLIST})

.include <bsd.port.mk>