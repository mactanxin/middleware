# $FreeBSD$

PORTNAME=	boto3
PORTVERSION=	1.4.0
CATEGORIES=	devel python
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}
MAINTAINER=	dev@FreeBSD.org
COMMENT=	The AWS SDK for Python

RUN_DEPENDS=    ${PYTHON_PKGNAMEPREFIX}dateutil>=2.1:${PORTSDIR}/devel/py-dateutil \
                ${PYTHON_PKGNAMEPREFIX}jmespath>=0.5.0:${PORTSDIR}/devel/py-jmespath \
                ${PYTHON_PKGNAMEPREFIX}six>=1.8.0:${PORTSDIR}/devel/py-six \
                ${PYTHON_PKGNAMEPREFIX}botocore>0:${PORTSDIR}/devel/py-botocore \
                ${PYTHON_PKGNAMEPREFIX}s3transfer>=0.1.0:net/py-s3transfer

USES=		python
USE_PYTHON=	autoplist distutils
USE_GITHUB=	yes
GH_ACCOUNT=	boto

.include <bsd.port.mk>
