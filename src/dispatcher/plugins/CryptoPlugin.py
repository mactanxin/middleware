#
# Copyright 2015 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import errno
import os
import re
import time
import datetime
import tarfile
import io
from pathlib import Path
from pytz import UTC
from datastore import DatastoreException
from freenas.dispatcher.rpc import RpcException, description, accepts, returns, generator
from freenas.dispatcher.rpc import SchemaHelper as h
from task import Provider, Task, TaskException, VerifyException, query, TaskDescription
from freenas.utils import query as q, COUNTRY_CODES
from freenas.dispatcher.fd import FileDescriptor

from OpenSSL import crypto


def export_privatekey(buf, passphrase=None):
    key = crypto.load_privatekey(
        crypto.FILETYPE_PEM,
        buf,
        passphrase=str(passphrase) if passphrase else None
    )

    return crypto.dump_privatekey(
        crypto.FILETYPE_PEM,
        key,
        passphrase=str(passphrase) if passphrase else None
    ).decode('utf-8')


def get_cert_info(buf):
    if isinstance(buf, str):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf.encode('utf-8'))
    else:
        cert = buf

    cert_info = {
        'country': cert.get_subject().C,
        'state': cert.get_subject().ST,
        'city': cert.get_subject().L,
        'organization': cert.get_subject().O,
        'common': cert.get_subject().CN,
        'email': cert.get_subject().emailAddress
    }

    signature_algorithm = cert.get_signature_algorithm().decode('utf-8')
    m = re.match('^(.+)[Ww]ith', signature_algorithm)
    if m:
        cert_info['digest_algorithm'] = m.group(1).upper()

    return cert_info


def load_privatekey(buf, passphrase=None):
    return crypto.load_privatekey(
        crypto.FILETYPE_PEM,
        buf,
        passphrase=lambda x: str(passphrase) if passphrase else ''
    )


def get_file_contents(path):
    with open(path, 'r') as f:
        return f.read()


def get_utc_string_from_asn1generalizedtime(asn1):
    return str(datetime.datetime.strptime(asn1, "%Y%m%d%H%M%SZ").replace(tzinfo=UTC))


@description("Provider for certificates")
class CertificateProvider(Provider):
    @query('crypto-certificate')
    @generator
    def query(self, filter=None, params=None):
        def extend(certificate):
            if certificate['type'].startswith('CA_'):
                cert_path = '/etc/certificates/CA'
            else:
                cert_path = '/etc/certificates'

            if certificate.get('certificate'):
                certificate['certificate_path'] = os.path.join(
                    cert_path, '{0}.crt'.format(certificate['name']))

            if certificate.get('privatekey'):
                certificate['privatekey_path'] = os.path.join(
                    cert_path, '{0}.key'.format(certificate['name']))

            if certificate.get('csr'):
                certificate['csr_path'] = os.path.join(
                    cert_path, '{0}.csr'.format(certificate['name']))

            return certificate

        return q.query(
            self.datastore.query_stream('crypto.certificates', callback=extend),
            *(filter or []),
            stream=True,
            **(params or {})
        )

    @accepts()
    @returns(h.object())
    def get_country_codes(self):
        return COUNTRY_CODES


@accepts(h.all_of(
    h.ref('crypto-certificate'),
    h.required('type', 'name', 'country', 'state', 'city', 'organization', 'email', 'common'),
    h.forbidden('certificate_path', 'privatekey_path'),
))
@description('Creates a certificate')
class CertificateCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating certificate"

    def describe(self, certificate):
        return TaskDescription("Creating certificate {name}", name=certificate['name'])

    def verify(self, certificate):
        certificate['selfsigned'] = certificate.get('selfsigned', False)
        certificate['signing_ca_name'] = certificate.get('signing_ca_name', False)

        if '"' in certificate['name']:
            raise VerifyException(errno.EINVAL, 'Provide certificate name without : `"`')

        if certificate['type'] in ('CERT_INTERNAL', 'CA_INTERNAL', 'CA_INTERMEDIATE'):
            if not certificate['selfsigned'] and not certificate['signing_ca_name']:
                raise VerifyException(errno.ENOENT,
                                      'Either "selfsigned" or "signing_ca_name" field value must be specified')
            if certificate['selfsigned'] and certificate['signing_ca_name']:
                raise VerifyException(errno.ENOENT,
                                      'Only one of "selfsigned","signing_ca_name" fields should be specified')

        if certificate['type'] == 'CA_INTERMEDIATE':
            if not certificate['signing_ca_name']:
                raise VerifyException(errno.ENOENT, '"signing_ca_name" field value not specified')

        return ['system']

    def run(self, certificate):
        def get_x509_inst(cert_info):
            cert = crypto.X509()
            map_x509_subject_info(cert, cert_info)
            if not cert_info.get('serial'):
                cert.set_serial_number(get_next_x509_serial_number())
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(cert_info['lifetime'] * (60 * 60 * 24))
            return cert

        def get_x509req_inst(cert_info):
            req = crypto.X509Req()
            map_x509_subject_info(req, cert_info)
            return req

        def get_next_x509_serial_number():
            return int(time.time())

        def map_x509_subject_info(x509, info):
            x509.get_subject().C = info['country']
            x509.get_subject().ST = info['state']
            x509.get_subject().L = info['city']
            x509.get_subject().O = info['organization']
            x509.get_subject().CN = info['common']
            x509.get_subject().emailAddress = info['email']

        def add_x509_extensions(x509, cert_type):
            if cert_type == 'CERT_INTERNAL':
                x509.add_extensions([
                    crypto.X509Extension("subjectKeyIdentifier".encode('utf-8'), False, "hash".encode('utf-8'),
                                         subject=x509)
                ])
            if cert_type == 'CA_INTERNAL':
                x509.add_extensions([
                    crypto.X509Extension("basicConstraints".encode('utf-8'), True, "CA:TRUE".encode('utf-8')),
                    crypto.X509Extension("keyUsage".encode('utf-8'), True, "keyCertSign, cRLSign".encode('utf-8')),
                    crypto.X509Extension("subjectKeyIdentifier".encode('utf-8'), False, "hash".encode('utf-8'),
                                         subject=x509),
                ])
            if cert_type == 'CA_INTERMEDIATE':
                x509.add_extensions([
                    crypto.X509Extension("basicConstraints".encode('utf-8'), True, "CA:TRUE".encode('utf-8')),
                    crypto.X509Extension("keyUsage".encode('utf-8'), True, "keyCertSign, cRLSign".encode('utf-8')),
                    crypto.X509Extension("subjectKeyIdentifier".encode('utf-8'), False, "hash".encode('utf-8'),
                                         subject=x509),
                ])

        def generate_key(key_length):
            k = crypto.PKey()
            k.generate_key(crypto.TYPE_RSA, key_length)
            return k

        if self.datastore.exists('crypto.certificates', ('name', '=', certificate['name'])):
            raise TaskException(errno.EEXIST, 'Certificate named "{0}" already exists'.format(certificate['name']))

        if certificate['signing_ca_name']:
            if not self.datastore.exists('crypto.certificates', ('name', '=', certificate['signing_ca_name'])):
                raise TaskException(errno.ENOENT,
                                    'Signing certificate "{0}" not found'.format(certificate['signing_ca_name']))

        try:
            certificate['selfsigned'] = certificate.get('selfsigned', False)
            certificate['key_length'] = certificate.get('key_length', 2048)
            certificate['digest_algorithm'] = certificate.get('digest_algorithm', 'SHA256')
            certificate['lifetime'] = certificate.get('lifetime', 3650)

            key = generate_key(certificate['key_length'])

            if certificate['type'] == 'CERT_CSR':
                x509 = get_x509req_inst(certificate)
                x509.set_pubkey(key)
                x509.sign(key, certificate['digest_algorithm'])

                certificate['csr'] = crypto.dump_certificate_request(crypto.FILETYPE_PEM, x509).decode('utf-8')
                certificate['privatekey'] = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')
            else:
                x509 = get_x509_inst(certificate)
                x509.set_pubkey(key)
                add_x509_extensions(x509, certificate['type'])

                if certificate['selfsigned']:
                    signing_x509 = x509
                    signkey = key
                else:
                    signing_cert_db_entry = self.datastore.get_one('crypto.certificates',
                                                                   ('name', '=', certificate['signing_ca_name']))
                    certificate['signing_ca_id'] = signing_cert_db_entry['id']
                    signing_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, signing_cert_db_entry['certificate'])
                    signkey = load_privatekey(signing_cert_db_entry['privatekey'])

                x509.set_issuer(signing_x509.get_subject())
                x509.sign(signkey, certificate['digest_algorithm'])

                try:
                    notbefore = x509.get_notBefore().decode('utf-8')
                except AttributeError:
                    certificate['not_before'] = None
                else:
                    certificate['not_before'] = get_utc_string_from_asn1generalizedtime(notbefore)

                try:
                    notafter = x509.get_notAfter().decode('utf-8')
                except AttributeError:
                    certificate['not_after'] = None
                else:
                    certificate['not_after'] = get_utc_string_from_asn1generalizedtime(notafter)

                certificate['serial'] = str(x509.get_serial_number())
                certificate['certificate'] = crypto.dump_certificate(crypto.FILETYPE_PEM, x509).decode('utf-8')
                certificate['privatekey'] = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')

            pkey = self.datastore.insert('crypto.certificates', certificate)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'crypto')
            self.dispatcher.dispatch_event('crypto.certificate.changed', {
                'operation': 'create',
                'ids': [pkey]
            })
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot create certificate: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot generate certificate: {0}'.format(str(e)))

        return pkey


@accepts(h.all_of(
    h.ref('crypto-certificate'),
    h.required('name', 'type'),
))
@description('Imports a certificate')
class CertificateImportTask(Task):
    @classmethod
    def early_describe(cls):
        return "Importing certificate"

    def describe(self, certificate):
        return TaskDescription("Importing certificate {name}", name=certificate['name'])

    def verify(self, certificate):
        if '"' in certificate['name']:
            raise VerifyException(errno.EINVAL, 'Provide certificate name without : `"`')

        if certificate['type'] not in ('CERT_EXISTING', 'CA_EXISTING'):
            raise VerifyException(
                errno.EINVAL,
                'Invalid certificate type: {0}. Should be "CERT_EXISTING" or "CA_EXISTING"'.format(
                    certificate['type']
                )
            )

        if all(k in certificate for k in ('certificate', 'certificate_path')):
            raise VerifyException(
                errno.EINVAL,
                'Both "certificate" and "certificate_path" arguments specified at the same time.'
            )

        if all(k in certificate for k in ('privatekey', 'privatekey_path')):
            raise VerifyException(
                errno.EINVAL,
                'Both "privatekey" and "privatekey_path" arguments specified at the same time.'
            )

        if certificate.get('certificate_path') and not Path(certificate['certificate_path']).is_file():
            raise VerifyException(
                errno.ENOENT,
                'Certificate file {0} does not exist'.format(certificate['certificate_path'])
            )

        if certificate.get('privatekey_path') and not Path(certificate['privatekey_path']).is_file():
            raise VerifyException(
                errno.ENOENT,
                "Certificate's privatekey file {0} does not exist".format(certificate['privatekey_path'])
            )

        if certificate.get('certificate_path'):
            try:
                crypto.load_certificate(crypto.FILETYPE_PEM, get_file_contents(
                    certificate['certificate_path']).encode('utf-8'))
            except Exception:
                raise VerifyException(
                    errno.EINVAL,
                    "Invalid certificate file contents: '{0}'".format(certificate['certificate_path'])
                )

        if certificate.get('certificate'):
            try:
                crypto.load_certificate(crypto.FILETYPE_PEM, certificate['certificate'].encode('utf-8'))
            except Exception:
                raise VerifyException(errno.EINVAL, "Invalid certificate provided")

        if certificate.get('privatekey_path'):
            try:
                crypto.load_privatekey(crypto.FILETYPE_PEM, get_file_contents(certificate['privatekey_path']))
            except Exception:
                raise VerifyException(
                    errno.EINVAL,
                    "Invalid privatekey file contents: '{0}'".format(certificate['privatekey_path'])
                )

        if certificate.get('privatekey'):
            try:
                crypto.load_privatekey(crypto.FILETYPE_PEM, certificate['privatekey'])
            except Exception:
                raise VerifyException(errno.EINVAL, "Invalid privatekey provided")

        return ['system']

    def run(self, certificate):
        if self.datastore.exists('crypto.certificates', ('name', '=', certificate['name'])):
            raise TaskException(errno.EEXIST, 'Certificate named "{0}" already exists'.format(certificate['name']))

        new_cert_db_entry = {}
        new_cert_db_entry['name'] = certificate['name']
        new_cert_db_entry['type'] = certificate['type']

        if certificate.get('certificate_path'):
            imported_cert = crypto.load_certificate(
                crypto.FILETYPE_PEM, get_file_contents(certificate['certificate_path']).encode('utf-8'))
        elif certificate.get('certificate'):
            imported_cert = crypto.load_certificate(crypto.FILETYPE_PEM, certificate['certificate'].encode('utf-8'))
        else:
            imported_cert = False

        if imported_cert:
            new_cert_db_entry['certificate'] = crypto.dump_certificate(
                crypto.FILETYPE_PEM, imported_cert).decode('utf-8')
            new_cert_db_entry.update(get_cert_info(imported_cert))
            new_cert_db_entry['serial'] = str(imported_cert.get_serial_number())
            #certificate['selfsigned'] = False
            new_cert_db_entry['not_before'] = get_utc_string_from_asn1generalizedtime(
                imported_cert.get_notBefore().decode('utf-8'))
            new_cert_db_entry['not_after'] = get_utc_string_from_asn1generalizedtime(
                imported_cert.get_notAfter().decode('utf-8'))
            new_cert_db_entry['lifetime'] = 3650
        else:
            new_cert_db_entry['certificate'] = ""

        if certificate.get('privatekey_path'):
            imported_privkey = crypto.load_privatekey(
                crypto.FILETYPE_PEM, get_file_contents(certificate['privatekey_path']))
        elif certificate.get('privatekey'):
            imported_privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, certificate['privatekey'])
        else:
            imported_privkey = False

        if imported_privkey:
            new_cert_db_entry['privatekey'] = crypto.dump_privatekey(
                crypto.FILETYPE_PEM, imported_privkey).decode('utf-8')
            new_cert_db_entry['key_length'] = imported_privkey.bits()
        else:
            new_cert_db_entry['privatekey'] = ""

        try:
            pkey = self.datastore.insert('crypto.certificates', new_cert_db_entry)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'crypto')
            self.dispatcher.dispatch_event('crypto.certificate.changed', {
                'operation': 'create',
                'ids': [pkey]
            })
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot import certificate: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot generate certificate: {0}'.format(str(e)))

        return pkey


@accepts(str, FileDescriptor)
@description("Exports certificate and private key")
class CertificateExportTask(Task):
    @classmethod
    def early_describe(cls):
        return "Exporting certificate and private key pair bundled as a tar file"

    def describe(self, id, cert_pair_fd):
        cert = self.datastore.get_by_id('crypto.certificates', id)
        return TaskDescription(
            "Exporting certificate {name} and private key pair bundled as a tar file",
            name=cert.get('name', '') if cert else ''
        )

    def verify(self, id, cert_pair_fd):
        return ['system']

    def run(self, id, cert_pair_fd):
        if not self.datastore.exists('crypto.certificates', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Certificate ID {0} does not exist'.format(id))

        name, cert, key = self.dispatcher.call_sync(
            'crypto.certificate.query',
            [('id', '=', id)],
            {'select': ['name', 'certificate', 'privatekey'], 'single': True}
        )

        with os.fdopen(cert_pair_fd.fd, mode='wb') as f:
            with tarfile.open(fileobj=f, mode='w|gz') as tf:
                cert_info = tarfile.TarInfo(name='{0}.crt'.format(name))
                cert_info.size = len(cert)
                key_info = tarfile.TarInfo(name='{0}.key'.format(name))
                key_info.size = len(key)
                tf.addfile(cert_info, io.BytesIO(cert.encode('utf-8')))
                tf.addfile(key_info, io.BytesIO(key.encode('utf-8')))


@accepts(str, h.all_of(
    h.ref('crypto-certificate'),
    h.forbidden('certificate_path', 'privatekey_path'),
))
@description('Updates a certificate')
class CertificateUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating certificate"

    def describe(self, id, updated_fields):
        cert = self.datastore.get_by_id('crypto.certificates', id)
        return TaskDescription("Updating certificate {name}", name=cert.get('name', '') if cert else '')

    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        def update_all_signed_certs_and_get_ids(old_signing_name, new_signing_name):
            certs = self.datastore.query('crypto.certificates', ('signing_ca_name', '=', old_signing_name))
            for c in certs:
                c['signing_ca_name'] = new_signing_name
                self.datastore.update('crypto.certificates', c['id'], c)
            return [c['id'] for c in certs]

        ids = [id]
        if not self.datastore.exists('crypto.certificates', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Certificate ID {0} does not exist'.format(id))

        cert = self.datastore.get_by_id('crypto.certificates', id)
        if cert['type'] in ('CA_EXISTING', 'CERT_EXISTING'):
            if 'certificate' in updated_fields:
                try:
                    crypto.load_certificate(crypto.FILETYPE_PEM, updated_fields['certificate'])
                except Exception:
                    raise TaskException(errno.EINVAL, 'Invalid certificate')
            if 'privatekey' in updated_fields:
                try:
                    crypto.load_privatekey(crypto.FILETYPE_PEM, updated_fields['privatekey'])
                except Exception:
                    raise TaskException(errno.EINVAL, 'Invalid privatekey')
            if 'name' in updated_fields:
                if self.datastore.exists('crypto.certificates', ('name', '=', updated_fields['name'])):
                    raise TaskException(errno.EEXIST,
                                        'Certificate name : "{0}" already in use'.format(updated_fields['name']))
        else:
            if len(updated_fields) > 1 or 'name' not in updated_fields:
                raise TaskException(errno.EINVAL, 'Only "name" field can be modified'.format(id))

            if self.datastore.exists('crypto.certificates', ('name', '=', updated_fields['name'])):
                raise TaskException(errno.EEXIST,
                                    'Certificate name : "{0}" already in use'.format(updated_fields['name']))

        try:
            if 'certificate' in updated_fields:
                cert['certificate'] = updated_fields['certificate']
                cert.update(get_cert_info(cert['certificate']))
            if 'privatekey' in updated_fields:
                cert['privatekey'] = updated_fields['privatekey']
            if 'name' in updated_fields:
                old_name = cert['name']
                cert['name'] = updated_fields['name']
                ids.extend(update_all_signed_certs_and_get_ids(old_name, cert['name']))
            pkey = self.datastore.update('crypto.certificates', id, cert)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'crypto')
            self.dispatcher.dispatch_event('crypto.certificate.changed', {
                'operation': 'update',
                'ids': ids
            })
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot update certificate: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot generate certificate: {0}'.format(str(e)))

        return pkey


@accepts(str)
@description('Deletes a certificate')
class CertificateDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting certificate"

    def describe(self, id):
        cert = self.datastore.get_by_id('crypto.certificates', id)
        return TaskDescription("Deleting certificate {name}", name=cert.get('name', '') if cert else '')

    def verify(self, id):
        return ['system']

    def run(self, id):
        def get_subject_cert_id_and_name():
            return self.datastore.query('crypto.certificates', ('id', '=', id), select=('id', 'name'))

        def get_related_certs_ids_and_names(id):
            certs = self.datastore.query('crypto.certificates', ('signing_ca_id', '=', id), select=('id', 'name'))
            if not certs:
                return []
            nested = []
            for (cid, _) in certs:
                nested.extend(get_related_certs_ids_and_names(cid))
            return certs + nested

        if not self.datastore.exists('crypto.certificates', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Certificate ID {0} does not exist'.format(id))

        certs = get_related_certs_ids_and_names(id)
        certs.extend(get_subject_cert_id_and_name())

        for (cid, cname) in certs:
            if not self.dispatcher.run_hook('crypto.pre_delete', cid):
                raise TaskException(errno.EBUSY, 'Certificate in use: {0}'.format(str(cname)))

        try:
            for (cid, _) in certs:
                self.datastore.delete('crypto.certificates', cid)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'crypto')
            self.dispatcher.dispatch_event('crypto.certificate.changed', {
                'operation': 'delete',
                'ids': [cid for (cid, _) in certs]
            })
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot delete certificate: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot generate certificate: {0}'.format(str(e)))


def _init(dispatcher, plugin):
    plugin.register_schema_definition('crypto-certificate', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'type': {'$ref': 'crypto-certificate-type'},
            'name': {'type': 'string'},
            'certificate': {'type': ['string', 'null']},
            'privatekey': {'type': ['string', 'null']},
            'csr': {'type': 'string'},
            'key_length': {'type': 'integer'},
            'digest_algorithm': {'$ref': 'crypto-certificate-digestalgorithm'},
            'lifetime': {'type': 'integer'},
            'not_before': {'type': 'string'},
            'not_after': {'type': 'string'},
            'country': {'type': 'string'},
            'state': {'type': 'string'},
            'city': {'type': 'string'},
            'organization': {'type': 'string'},
            'passphrase': {'type': ['string', 'null']},
            'email': {'type': 'string'},
            'common': {'type': 'string'},
            'serial': {'type': ['string', 'null']},
            'selfsigned': {'type': 'boolean'},
            'signing_ca_name': {'type': 'string'},
            'signing_ca_id': {'type': 'string'},
            'dn': {'type': 'string', 'readOnly': True},
            'valid_from': {'type': ['string', 'null'], 'readOnly': True},
            'valid_until': {'type': ['string', 'null'], 'readOnly': True},
            'certificate_path': {'type': ['string', 'null']},
            'privatekey_path': {'type': ['string', 'null']},
            'csr_path': {'type': ['string', 'null'], 'readOnly': True},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('crypto-certificate-type', {
        'type': 'string',
        'enum': [
            'CA_EXISTING', 'CA_INTERMEDIATE', 'CA_INTERNAL',
            'CERT_CSR', 'CERT_EXISTING', 'CERT_INTERMEDIATE', 'CERT_INTERNAL'
        ]
    })

    plugin.register_schema_definition('crypto-certificate-digestalgorithm', {
        'type': 'string',
        'enum': ['SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512']
    })

    plugin.register_provider('crypto.certificate', CertificateProvider)

    plugin.register_task_handler('crypto.certificate.create', CertificateCreateTask)
    plugin.register_task_handler('crypto.certificate.update', CertificateUpdateTask)
    plugin.register_task_handler('crypto.certificate.import', CertificateImportTask)
    plugin.register_task_handler('crypto.certificate.export', CertificateExportTask)
    plugin.register_task_handler('crypto.certificate.delete', CertificateDeleteTask)

    plugin.register_hook('crypto.pre_delete')

    # Register event types
    plugin.register_event_type('crypto.certificate.changed')
