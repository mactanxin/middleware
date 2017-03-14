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
import os
import glob
import shutil
from pathlib import Path


def run(context):
    cert_files_names_and_paths = get_cert_files_short_names_and_abs_paths()
    cert_files_names = set(e.get('short_name') for e in cert_files_names_and_paths)

    datastore_certs = context.client.call_sync('crypto.certificate.query')
    datastore_certs_names = set(e.get('name') for e in datastore_certs)

    cert_file_names_to_delete = cert_files_names - datastore_certs_names
    cert_file_names_to_create = datastore_certs_names - cert_files_names

    cert_files_to_delete = [e for e in cert_files_names_and_paths if e.get('short_name') in cert_file_names_to_delete]
    datastore_certs_to_create = [e for e in datastore_certs if e.get('name') in cert_file_names_to_create]

    if cert_files_to_delete:
        delete_cert_files(context, cert_files_to_delete)

    if datastore_certs_to_create:
        generate_cert_files(context, datastore_certs_to_create)

    update_installed_certs(datastore_certs)


def update_installed_certs(certs):
    """Installs/Removes system-wide OpenSSL certificates by modyfing the /usr/local/share/certs/ca-root-nss.crt file"""
    certs_filepath = '/usr/local/share/certs/ca-root-nss.crt'
    backup_filepath = certs_filepath + '.bak'
    certs_file = Path(certs_filepath)
    backup_file = Path(backup_filepath)
    def _update_certs():
        cert_begin_line = 'BEGIN CERTIFICATE'
        summary_line = '##  Number of certificates: '
        eof_line = '##  End of file.\n'
        separator = '\n\n\n'
        count = 0
        with certs_file.open('w', encoding='iso-8859-1') as o, backup_file.open('r', encoding='iso-8859-1') as i:
            for line in i:
                if summary_line in line:
                    for c in certs:
                        if c.get('certificate'):
                            o.write(c['certificate'])
                            o.write(separator)
                            count += 1
                    o.write(summary_line + '{0}\n'.format(count))
                    o.write(eof_line)
                    return
                else:
                    count += 1 if cert_begin_line in line else 0
                    o.write(line)

    if not backup_file.exists():
        shutil.copy2(certs_file, backup_file)

    if not certs:
        shutil.copy2(backup_file, certs_file)
        return

    _update_certs()


def get_cert_files_short_names_and_abs_paths():
    """Returns array of dicts where each dict describes short name (without suffix) of cert file and it's path"""
    file_names_and_paths = []
    for name in get_cert_files_fully_qualified_names():
        (path, filename) = os.path.split(name)
        (file_shortname, file_extension) = os.path.splitext(filename)
        file_names_and_paths.append({'short_name': file_shortname, 'abs_path': path})

    return file_names_and_paths


def get_cert_files_fully_qualified_names():
    """Returns array of fully qualified names of certificate files"""
    def flatten_nested_array(nested_arr):
        return [e for arr in nested_arr for e in arr]

    cert_files = [glob.glob(os.path.join(path, '*.crt')) for path in get_cert_dirs_paths()]

    return flatten_nested_array(cert_files)


def get_cert_dirs_paths():
    """Returns array of absolute paths to directories containing certificates"""
    certs_path = '/etc/certificates'
    cacerts_path = '/etc/certificates/CA'

    return [certs_path, cacerts_path]


def generate_cert_files(context, certs_to_create):
    for cert in certs_to_create:

        certificate = cert.get('certificate')
        if certificate:
            generate_file(context, cert['certificate_path'], certificate)

        privatekey = cert.get('privatekey')
        if privatekey:
            generate_file(context, cert['privatekey_path'], privatekey.secret)

        csr = cert.get('csr')
        if csr and csr['type'] == 'CERT_CSR':
            generate_file(context, cert['csr_path'], csr)


def generate_file(context, path, content):
    if not os.path.exists(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path), 0o755)

    with open(path, 'w') as f:
        f.write(content)
    context.emit_event('etcd.file_generated', {'filename': path})


def delete_cert_files(context, certs_to_delete):
    def get_all_cert_related_files(cert_name, cert_path):
        return glob.glob(os.path.join(cert_path, cert_name+".*"))

    for cert_file in certs_to_delete:
        for f in get_all_cert_related_files(cert_file['short_name'], cert_file['abs_path']):
            delete_file(context, f)


def delete_file(context, path):
    os.remove(path)
    context.emit_event('etcd.file_generated', {'filename': path})
