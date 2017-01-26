#
# Copyright 2016 iXsystems, Inc.
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

from task import Provider, query
from freenas.dispatcher.rpc import generator
from freenas.utils import query as q


KNOWN_SERVICES = ['freenas', 'ssh']


class NeighborProvider(Provider):
    @query('Neighbor')
    @generator
    def query(self, filter=None, params=None):
        def collect():
            for regtype in KNOWN_SERVICES:
                for svc in self.dispatcher.call_sync('neighbord.discovery.find', regtype):
                    svc['service'] = regtype
                    yield svc

        return q.query(collect(), *(filter or []), **(params or {}))


def _init(dispatcher, plugin):
    plugin.register_schema_definition('Neighbor', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'hostname': {'type': 'string'},
            'description': {'type': ['string', 'null']},
            'type': {'$ref': 'neighbod-type'},
            'source': {'type': 'string'},
            'address': {'type': 'string'},
            'online': {'type': 'boolean'},
            'properties': {
                'type': 'object'
            }
        }
    })

    plugin.register_provider('neighbor', NeighborProvider)
