#
# Copyright 2017 iXsystems, Inc.
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

import sqlite3
from task import Provider, query
from freenas.dispatcher.rpc import generator
from freenas.utils import query as q


PKGDB_FILE = '/var/db/pkg/local.sqlite'


class SoftwarePackageProvider(Provider):
    @query('software-package')
    @generator
    def query(self, filter=None, params=None):
        def collect():
            db = sqlite3.connect(PKGDB_FILE, isolation_level=None)
            try:
                cursor = db.cursor()
                for row in cursor.execute('SELECT * FROM packages'):
                    yield {
                        'id': row[0],
                        'name': row[2],
                        'version': row[3]
                    }
            finally:
                db.close()

        return q.query(collect(), *(filter or []), **(params or {}))


def _init(dispatcher, plugin):
    plugin.register_schema_definition('software-package', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'integer'},
            'name': {'type': 'string'},
            'version': {'type': 'string'}
        }
    })

    plugin.register_provider('software.package', SoftwarePackageProvider)
