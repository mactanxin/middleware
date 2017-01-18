# $FreeBSD$

PORTNAME=	freenas-dispatcher
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS middleware daemon

BUILD_DEPENDS=	cython>0:${PORTSDIR}/lang/cython

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}argh>0:${PORTSDIR}/devel/py-argh \
		${PYTHON_PKGNAMEPREFIX}dateutil>0:${PORTSDIR}/devel/py-dateutil \
		${PYTHON_PKGNAMEPREFIX}Flask>0:${PORTSDIR}/www/py-flask \
		${PYTHON_PKGNAMEPREFIX}Flask-Bootstrap>0:${PORTSDIR}/www/py-flask-bootstrap \
		${PYTHON_PKGNAMEPREFIX}freenas.utils>0:${PORTSDIR}/freenas/py-freenas.utils \
		${PYTHON_PKGNAMEPREFIX}gevent>0:${PORTSDIR}/devel/py-gevent \
		${PYTHON_PKGNAMEPREFIX}gevent-websocket>0:${PORTSDIR}/www/py-gevent-websocket \
		${PYTHON_PKGNAMEPREFIX}jsonschema>0:${PORTSDIR}/devel/py-jsonschema \
		${PYTHON_PKGNAMEPREFIX}lxml>0:${PORTSDIR}/devel/py-lxml \
		${PYTHON_PKGNAMEPREFIX}openssl>=16.2.0:${PORTSDIR}/security/py-openssl \
		${PYTHON_PKGNAMEPREFIX}psutil>0:${PORTSDIR}/sysutils/py-psutil \
		${PYTHON_PKGNAMEPREFIX}pyee>0:${PORTSDIR}/devel/py-pyee \
		${PYTHON_PKGNAMEPREFIX}requests>0:${PORTSDIR}/www/py-requests \
		${PYTHON_PKGNAMEPREFIX}simplejson>0:${PORTSDIR}/devel/py-simplejson \
		${PYTHON_PKGNAMEPREFIX}texttable>0:${PORTSDIR}/textproc/py-texttable \
		${PYTHON_PKGNAMEPREFIX}ws4py>0:${PORTSDIR}/freenas/py-ws4py \
		${PYTHON_PKGNAMEPREFIX}pygit2>0:${PORTSDIR}/devel/py-pygit2 \
		${PYTHON_PKGNAMEPREFIX}docker-py>0:${PORTSDIR}/devel/py-docker \
		${PYTHON_PKGNAMEPREFIX}boto3>0:${PORTSDIR}/devel/py-boto3 \
		${PYTHON_PKGNAMEPREFIX}dockerhub>0:${PORTSDIR}/freenas/py-dockerhub \
		${PYTHON_PKGNAMEPREFIX}dockerfile-parse>0:${PORTSDIR}/devel/py-dockerfile-parse \
		${PYTHON_PKGNAMEPREFIX}python-consul>0:${PORTSDIR}/devel/py-consul \
		${PYTHON_PKGNAMEPREFIX}sortedcontainers>0:${PORTSDIR}/devel/py-sortedcontainers \
		${PYTHON_PKGNAMEPREFIX}freenas.dispatcher>0:${PORTSDIR}/freenas/py-freenas.dispatcher \
		${PYTHON_PKGNAMEPREFIX}libusb1>0:${PORTSDIR}/devel/py-libusb1 \
		${PYTHON_PKGNAMEPREFIX}wsaccel>0:${PORTSDIR}/www/py-wsaccel \
		pyvmomi>0:${PORTSDIR}/net/py-pyvmomi \
		js-freenas.dispatcher>0:${PORTSDIR}/freenas/js-freenas.dispatcher

USES=		python
USE_PYTHON=	py3kplist

EXTRACT_ONLY=

NO_BUILD=	yes
MAKE_JOBS_UNSAFE= yes
ALL_TARGET=	obj all
WRKSRC=		/usr/middleware_src/dispatcher

checksum:
	${ECHO_CMD} ${.TARGET} not needed because building direct

fetch:
	:

extract:
	:

do-install:
	${MAKE} -C ${WRKSRC} install STAGEDIR=${STAGEDIR} PREFIX=${PREFIX} PYTHON=${PYTHON_CMD}

post-install:
	${PYTHON_CMD} -m compileall ${STAGEDIR}${PREFIX}/lib/dispatcher
	(cd ${STAGEDIR}${PREFIX}/lib/dispatcher; ${FIND} -E . -type f -regex \
		".*((.pyc?)|(.so)|(.jso?n?)|(.html)|(.map)|(.css)|(.png)|(.jpg)|(.gif)|(.md)|(.txt)|(.swf)|(.eot)|(.svg)|(.ttf)|(.woff2?)|(.c))+$$" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print "lib/dispatcher/"$$0 }' >> ${TMPPLIST})


.include <bsd.port.mk>
