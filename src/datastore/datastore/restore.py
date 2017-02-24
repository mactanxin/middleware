#
# Copyright 2014 iXsystems, Inc.
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

from freenas.utils import exclude


def restore_collection(ds, dump):
    metadata = dump['metadata']
    data = dump['data']
    name = metadata['name']
    integer = metadata['pkey-type'] in ('integer', 'serial')

    ds.collection_delete(name)
    ds.collection_create(name, metadata['pkey-type'], metadata['attributes'])
    configstore = metadata['attributes'].get('configstore', False)

    for key, row in list(data.items()):
        pkey = int(key) if integer else key
        ds.insert(name, row, pkey=pkey, config=configstore)


def restore_db(ds, dump, types=None, progress_callback=None):
    for i in dump:
        metadata = i['metadata']
        attrs = metadata['attributes']
        if types and 'type' in attrs.keys() and attrs['type'] not in types:
            continue

        restore_collection(ds, i)
        if progress_callback:
            progress_callback(metadata['name'])


def dump_collection(ds, name):
    metadata = {
        'name': name,
        'pkey-type': ds.collection_get_pkey_type(name),
        'attributes': ds.collection_get_attrs(name),
        'migration': ds.collection_get_migration_policy(name),
        'migrations': ds.collection_get_migrations(name)
    }

    configstore = metadata['attributes'].get('configstore', False)

    def collect():
        return {x['id']: exclude(x, 'id') for x in ds.query(name)}

    def collect_configstore():
        return {x['id']: x['value'] for x in ds.query(name)}

    return {
        'metadata': metadata,
        'data': collect_configstore() if configstore else collect()
    }
