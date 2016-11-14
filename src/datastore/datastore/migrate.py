#
# Copyright 2014-2016 iXsystems, Inc.
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
import json
import glob
import imp
import copy
import traceback
import jsonpatch
from datastore import DatastoreException


logfile = None


class MigrationException(DatastoreException):
    pass


def log(s):
    print(s)
    print(s, file=logfile)


def log_indented(f, s):
    for line in s.split('\n'):
        f(' ' * 2 + line)


def apply_migrations(ds, collection, directory, force=False):
    log("Running migrations for collection {0}".format(collection))
    for f in sorted(glob.glob(os.path.join(directory, "*.py"))):
        name, _ = os.path.splitext(os.path.basename(f))

        try:
            mod = imp.load_source(name, f)
        except:
            log('Cannot load migration from {0}:'.format(f))
            log_indented(log, traceback.format_exc())
            raise MigrationException(traceback.format_exc())

        def mig_log(s):
            log('[{0}, {1}] {2}'.format(collection, name, s))

        migrated = 0
        total = 0

        log("[{0}] Applying migration {1}".format(collection, name))

        if ds.collection_has_migration(collection, name) and not force:
            mig_log("Migration already applied")
            continue

        for i in ds.query(collection, sort='id', dir='asc'):
            total += 1
            try:
                if not mod.probe(i, ds):
                    mig_log('Object <id:{0}> fails probe() condition, skipping'.format(i['id']))
                    continue
            except:
                mig_log('probe() failed on object <id:{0}>'.format(i['id']))
                log_indented(mig_log, traceback.format_exc())
                raise MigrationException(traceback.format_exc())

            old_obj = copy.deepcopy(i)
            try:
                new_obj = mod.apply(i, ds)
                diff = jsonpatch.make_patch(old_obj, new_obj)
            except:
                mig_log('apply() failed on object <id:{0}>:'.format(old_obj['id']))
                log_indented(mig_log, traceback.format_exc())
                raise MigrationException(traceback.format_exc())

            mig_log('Sucessfully migrated object <id:{0}>'.format(i['id']))
            if diff.patch:
                mig_log('JSON delta:')
                log_indented(mig_log, json.dumps(diff.patch, indent=4))
            else:
                mig_log('Object unchanged after migration')

            if not new_obj:
                ds.delete(collection, old_obj['id'])
                mig_log('Object deleted by migration')
            else:
                try:
                    ds.update(collection, old_obj['id'], new_obj)
                except DatastoreException as err:
                    mig_log('failed to upsert migrated object <id:{0}>: {1}'.format(new_obj['id'], str(err)))
                    continue

            migrated += 1

        mig_log("{0} out of {1} objects migrated".format(migrated, total))
        ds.collection_record_migration(collection, name)


def migrate_collection(ds, dump, directory, force=False):
    metadata = dump['metadata']
    data = dump['data']
    name = metadata['name']
    integer = metadata['pkey-type'] == 'integer'
    upsert = metadata['migration'] in ('merge-overwrite', 'replace')
    configstore = metadata['attributes'].get('configstore', False)

    if metadata['migration'] != 'replace' and directory and os.path.isdir(directory) and ds.collection_exists(name):
        apply_migrations(ds, name, directory, force)

    if metadata['migration'] == 'replace':
        ds.collection_delete(name)

    if not ds.collection_exists(name):
        ds.collection_create(name, metadata['pkey-type'], metadata['attributes'])

    # Update pkey type for collection
    ds.collection_set_pkey_type(name, metadata['pkey-type'])

    if metadata['migration'] == 'keep':
        return

    for key, row in list(data.items()):
        pkey = int(key) if integer else key
        if metadata['migration'] == 'merge-preserve':
            if not ds.exists(name, ('id', '=', pkey)):
                ds.insert(name, row, pkey=pkey, config=configstore)

            continue

        ds.update(name, pkey, row, upsert=upsert, config=configstore)


def migrate_db(ds, dump, migpath=None, types=None, force=False):
    global logfile

    # Open logfile
    filename = '/var/tmp/dsmigrate.{0}.log'.format(os.getpid())
    logfile = open(filename, 'w')

    for i in dump:
        metadata = i['metadata']
        name = metadata['name']
        if not ds.collection_exists(name):
            ds.collection_create(name, metadata['pkey-type'], metadata['attributes'])
            print("Created missing collection {0}".format(name))

    for i in dump:
        metadata = i['metadata']
        attrs = metadata['attributes']
        if types and 'type' in attrs.keys() and attrs['type'] not in types:
            continue

        directory = os.path.join(migpath, metadata['name']) if migpath else None
        migrate_collection(ds, i, directory, force)
        print("Migrated collection {0}".format(metadata['name']), file=logfile)

    logfile.close()
