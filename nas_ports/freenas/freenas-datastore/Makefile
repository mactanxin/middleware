# $FreeBSD$

PORTNAME=	freenas-datastore
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}

CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS data store layer

USES=		python
USE_PYTHON=	py3kplist

OPTIONS_SINGLE=	USE_POSTGRESQL USE_MONGODB

BUILD_DEPENDS=	jq>0:${PORTSDIR}/textproc/jq

.if ${PORT_OPTIONS:USE_POSTGRESQL}
RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}psycopg2>0:${PORTSDIR}/databases/py-psycopg2 \
		postgresql93-server>0:${PORTSDIR}/databases/postgresql93-server \
		postgresql93-contrib>0:${PORTSDIR}/databases/postgresql93-contrib \
		freenas-dispatcher>0:${PORTSDIR}/freenas/freenas-dispatcher
.endif

.if ${PORT_OPTIONS:USE_MONGODB}
RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}pymongo>0:${PORTSDIR}/databases/pymongo \
		mongodb>0:${PORTSDIR}/databases/mongodb \
		freenas-dispatcher>0:${PORTSDIR}/freenas/freenas-dispatcher \
		${PYTHON_PKGNAMEPREFIX}dateutil>0:${PORTSDIR}/devel/py-dateutil
.endif

RUN_DEPENDS+=	\
	${PYTHON_PKGNAMEPREFIX}argh>0:${PORTSDIR}/devel/py-argh

EXTRACT_ONLY=

MAKE_JOBS_UNSAFE= yes
ALL_TARGET=	obj all
WRKSRC=		/usr/middleware_src/datastore

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

do-build:
	(cat ${WRKSRC}/share/factory.json | ${LOCALBASE}/bin/jq . || (${ECHO_CMD} "Why yuo haz no validate thiz factory.json!? No donuts for yuo!" && ${FALSE}))

do-install:
	${MAKE} -C ${WRKSRC} install STAGEDIR=${STAGEDIR} PREFIX=${PREFIX} PYTHON=${PYTHON_CMD}
	${MKDIR} -p ${STAGEDIR}/data/freenas.db

post-install:
	${PYTHON_CMD} -m compileall ${STAGEDIR}${PREFIX}/share/datastore/migrations
	(cd ${STAGEDIR}${PREFIX}/share/datastore/migrations; ${FIND} -E . -type f -regex ".*.pyc?" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print length, $$0}' | ${SORT} -rn \
		| ${AWK} '{print "share/datastore/migrations/"$$2 }' >> ${TMPPLIST})

.include <bsd.port.mk>
