# $FreeBSD$

PORTNAME=	jsonpatch
PORTVERSION=	1.14
CATEGORIES=	devel python
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

MAINTAINER=	harm@weites.com
COMMENT=	Apply JSON-Patches (RFC 6902)

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}jsonpointer>0:devel/py-jsonpointer

LICENSE=	BSD3CLAUSE

USE_GITHUB=	yes
GH_ACCOUNT=	stefankoegl
GH_PROJECT=	python-json-patch
GH_TAGNAME=	4e95310

USES=		python
USE_PYTHON=	autoplist distutils

regression-test: build
	@cd ${WRKSRC} && ${PYTHON_CMD} tests.py
	@cd ${WRKSRC} && ${PYTHON_CMD} ext_tests.py

.include <bsd.port.mk>
