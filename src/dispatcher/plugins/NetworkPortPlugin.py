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

import bsd
import pf
import netif
import ipaddress
import itertools
from task import Provider, query
from freenas.utils import query as q


INADDR_ANY = ipaddress.ip_address('0.0.0.0')


class NetworkPortProvider(Provider):
    @query('Port')
    def query(self, filter=None, params=None):
        def collect_system():
            for proc in self.dispatcher.threaded(bsd.getprocs, bsd.ProcessLookupPredicate.PROC):
                seen_ports = set()
                for f in self.dispatcher.threaded(lambda: list(proc.files)):
                    if f.type != bsd.DescriptorType.SOCKET:
                        continue

                    if not f.peer_address:
                        continue

                    if f.peer_address[0] == INADDR_ANY:
                        continue

                    _, port = f.local_address
                    if port in seen_ports:
                        continue

                    try:
                        service = self.dispatcher.call_sync('serviced.job.job_by_pid', proc.pid, True)
                        type = 'SERVICE'
                        name = service['Label']
                    except:
                        type = 'OTHER'
                        name = proc.command

                    yield {
                        'consumer_type': type,
                        'consumer_pid': proc.pid,
                        'consumer_name': name,
                        'af': str(netif.AddressFamily(f.af)),
                        'port': port,
                        'protocol': f.proto
                    }

                    seen_ports.add(port)

        def collect_pf():
            if 0:
                yield None

            return

        return q.query(
            itertools.chain(collect_system(), collect_pf()),
            *(filter or []),
            **(params or {})
        )


def _init(dispatcher, plugin):
    plugin.register_schema_definition('PortConsumerType', {
        'type': 'enum',
        'enum': ['SERVICE', 'VM', 'CONTAINER', 'OTHER']
    })

    plugin.register_schema_definition('PortAddressFamily', {
        'type': 'string',
        'enum': ['INET', 'INET6']
    })

    plugin.register_schema_definition('PortProtocol', {
        'type': 'string',
        'enum': ['TCP', 'UDP']
    })

    plugin.register_schema_definition('Port', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'consumer_type': {'$ref': 'PortConsumerType'},
            'consumer_name': {'type': 'string'},
            'consumer_pid': {'type': 'integer'},
            'af': {'$ref': 'PortAddressFamily'},
            'protocol': {'$ref': 'PortProtocol'},
            'port': {'type': 'integer'}
        }
    })

    plugin.register_provider('network.port', NetworkPortProvider)
