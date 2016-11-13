# $FreeBSD$

PORTNAME=	docker-pycreds
PORTVERSION=	0.2.1
CATEGORIES=	devel python
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

MAINTAINER=	dev@ixsystems.com
COMMENT=	Python bindings for the docker credentials store API

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}six>=1.4.0:devel/py-six

USES=		python
USE_PYTHON=	autoplist distutils
USE_GITHUB=	yes
GH_ACCOUNT=	shin-
GH_PROJECT=	dockerpy-creds

NO_ARCH=	yes

.include <bsd.port.mk>
