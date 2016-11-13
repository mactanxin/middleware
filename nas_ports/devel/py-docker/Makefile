# $FreeBSD$

PORTNAME=	docker-py
PORTVERSION=	1.10.6
CATEGORIES=	devel python
MASTER_SITES=	CHEESESHOP
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}websocket-client>=0.32.0:${PORTSDIR}/www/py-websocket-client \
		${PYTHON_PKGNAMEPREFIX}requests>=2.11.0:${PORTSDIR}/www/py-requests \
		${PYTHON_PKGNAMEPREFIX}six>=1.4.0:${PORTSDIR}/devel/py-six \
		${PYTHON_PKGNAMEPREFIX}docker-pycreds>=0.2.1:${PORTSDIR}/devel/py-docker-pycreds \
		${PYTHON_PKGNAMEPREFIX}backports.ssl_match_hostname>=3.5:${PORTSDIR}/security/py-backports.ssl_match_hostname

MAINTAINER=	jceel@FreeBSD.org
COMMENT=	Python client for Docker.

USES=		python
USE_PYTHON=	autoplist distutils
USE_GITHUB=	yes
GH_ACCOUNT=	docker
GH_PROJECT=	docker-py

.include <bsd.port.mk>
