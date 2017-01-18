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
import logging
import os
import shutil
import ipfsapi
from requests.exceptions import ConnectionError
from datastore.config import ConfigNode
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns, private
from task import Task, Provider, TaskException, ValidationException, TaskDescription

logger = logging.getLogger('IPFSPlugin')

ipfs_tasks = {
    'add': {
        'early_describe': 'Calling IPFS add',
        'accepts': (h.one_of(str, h.array(str)), bool),
        'args': ('files', 'recursive')
    },
    'get': {
        'early_describe': 'Calling IPFS get',
        'accepts': (str, h.one_of(str, None)),
        'args': ('multihash', 'filepath')
    },
    'add_json': {
        'early_describe': 'Calling IPFS add json',
        'accepts': (h.object(),),
        'args': ('json_obj',)
    }

}

ipfs_task_types = {}

ipfs_rpcs = {
    'id': {
        'accepts': ()
    },
    'version': {
        'accepts': ()
    },
    'swarm_peers': {
        'accepts': ()
    },
    'swarm_addrs': {
        'accepts': ()
    },
    'get_json': {
        'accepts': (str,)
    }
}


# Defining this decorator and keeping (might be useful sometime later)
# Not using it currently as it slows down the RPC call
def ipfs_enabled_check():
    def wrapped(fn):
        def wrap(self, *args, **kwargs):
            ipfs_state = self.dispatcher.call_sync(
                'service.query',
                [('name', '=', 'ipfs')],
                {'single': True}
            )['state']
            if ipfs_state != 'RUNNING':
                raise RpcException(
                    errno.EIO,
                    'IPFS service is not running. Please start it before performing this call'
                )
            return fn(self, *args, **kwargs)

        return wrap

    return wrapped


# This is faster as it first tries to execute the ipfsapi call and catches the exception if any
def ipfs_enabled_error():
    def wrapped(fn):
        def wrap(self, *args, **kwargs):
            try:
                return fn(self, *args, **kwargs)
            except ConnectionError:
                raise RpcException(
                    errno.EIO,
                    'IPFS service is not running. Please start it before performing this call'
                )
        return wrap
    return wrapped


@description('Provides info about IPFS service configuration')
class IPFSServiceProvider(Provider):
    def __init__(self):
        self.ipfs_api = None

    def initialize(self, context):
        super(IPFSServiceProvider, self).initialize(context)
        self.ipfs_api = ipfsapi.Client('127.0.0.1', 5001)

    @private
    @accepts()
    @returns(h.ref('ServiceIpfs'))
    def get_config(self):
        return ConfigNode('service.ipfs', self.configstore).__getstate__()


@description('Provides IPFS services')
class IPFSProvider(Provider):
    def __init__(self):
        self.ipfs_api = None

    def initialize(self, context):
        super(IPFSProvider, self).initialize(context)
        self.ipfs_api = ipfsapi.Client('127.0.0.1', 5001)

    def hash_to_link(self, hash):
        return 'http://ipfs.io/ipfs/' + hash


@private
@description('Configure IPFS service')
@accepts(h.ref('ServiceIpfs'))
class IPFSConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring IPFS service'

    def describe(self, ipfs):
        return TaskDescription('Configuring IPFS service')

    def verify(self, ipfs):
        errors = ValidationException()

        if 'path' in ipfs:
            if ipfs['path'] in [None, ''] or ipfs['path'].isspace():
                errors.add((0, ipfs['path']), "The provided path: '{0}' is not valid".format(ipfs['path']))

        if errors:
            raise errors

        return ['system']

    def run(self, ipfs):
        try:
            node = ConfigNode('service.ipfs', self.configstore)
            old_path = node['path'].value
            if 'path' in ipfs and ipfs['path'] != old_path:
                if not os.path.exists(ipfs['path']):
                    os.makedirs(ipfs['path'])
                    # jkh says that the ipfs path should be owned by root
                    os.chown(ipfs['path'], 0, 0)
                # Only move the contents and not the entire folder
                # there could be other stuff in that folder
                # (a careless user might have merged this with his other files)
                # also this folder could be a dataset in which case a simple move will fail
                # so lets just move the internal contents of this folder over
                if old_path is not None and os.path.exists(old_path):
                    try:
                        for item in os.listdir(old_path):
                            shutil.move(old_path + '/' + item, ipfs['path'])
                    except shutil.Error as serr:
                        raise TaskException(
                            errno.EIO,
                            "Migrating ipfs path resulted in error: {0}".format(serr))
            node.update(ipfs)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'ipfs')
            self.dispatcher.dispatch_event('service.ipfs.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure IPFS: {0}'.format(str(e))
            )

        return 'RESTART'


class IPFSBaseTask(Task):
    def __init__(self, dispatcher, datastore, method):
        super(IPFSBaseTask, self).__init__(dispatcher, datastore)
        self._method = method

    def describe(self, *args):
        return TaskDescription('Calling IPFS {name}', name=self._method)

    def verify(self, *args):
        return []

    @ipfs_enabled_error()
    def run(self, *args):
        ipfs_api = ipfsapi.Client('127.0.0.1', 5001)
        method = getattr(ipfs_api, self._method)
        kwargs = {}
        for idx, arg in enumerate(args):
            kwargs[ipfs_tasks[self._method]['args'][idx]] = arg

        return method(**kwargs)


def ipfs_task_factory(method):
    def __init__(self, dispatcher, datastore):
        IPFSBaseTask.__init__(self, dispatcher, datastore, method)

    def early_describe():
        return ipfs_tasks[method]['early_describe']

    cls = type(
        'IPFS' + method.capitalize() + 'Task',
        (IPFSBaseTask,),
        {'__init__': __init__, 'early_describe': early_describe}
    )
    descr_cls = description('Calls ipfsapi {0} method'.format(method))(cls)
    return private(accepts(*ipfs_tasks[method]['accepts'])(descr_cls))


for name in ipfs_tasks:
    generated_class = ipfs_task_factory(name)
    ipfs_task_types[name] = generated_class
    globals()[generated_class.__name__] = generated_class


for name in ipfs_rpcs:
    def wrapped(fn):
        def wrap(self, *args, **kwargs):
            return fn(self.ipfs_api, *args, **kwargs)
        return wrap
    method = wrapped(getattr(ipfsapi.Client, name))
    method.__name__ = name
    decorated_method = private(accepts(*ipfs_rpcs[name]['accepts'])(ipfs_enabled_error()(method)))
    setattr(IPFSProvider, name, decorated_method)


def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):

    # Register schemas
    plugin.register_schema_definition('ServiceIpfs', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceIpfs']},
            'enable': {'type': 'boolean'},
            'path': {'type': 'string'},
            'webui': {'type': 'boolean'}
        },
        'additionalProperties': False,
    })


    # Register providers
    plugin.register_provider("service.ipfs", IPFSServiceProvider)
    plugin.register_provider("ipfs", IPFSProvider)

    # Register tasks
    plugin.register_task_handler("service.ipfs.update", IPFSConfigureTask)
    for name in ipfs_tasks:
        plugin.register_task_handler("ipfs.{0}".format(name), ipfs_task_types[name])
