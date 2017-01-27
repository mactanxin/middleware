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
import logging
import requests
from io import StringIO
from task import Task, Provider, TaskDescription
from freenas.dispatcher.rpc import SchemaHelper as h, description, accepts, private
from freenas.utils import normalize
from lxml import etree

logger = logging.getLogger(__name__)


@description("Provides info about configured WebDAV shares")
class WebDAVSharesProvider(Provider):
    @private
    @accepts(str)
    def get_connected_clients(self, share_id=None):
        result = []
        config = self.dispatcher.call_sync('service.webdav.get_config').__getstate__()

        if not config['enable']:
            return result

        if 'HTTP' in config['protocol']:
            proto = 'http'
            port = config['http_port']
        elif 'HTTPS' in config['protocol']:
            proto = 'https'
            port = config['https_port']
        else:
            return result

        r = requests.get(
            '{0}://127.0.0.1:{1}/server-status'.format(proto, port),
            verify=False,
            timeout=5,
        )
        parser = etree.HTMLParser()
        tree = etree.parse(StringIO(r.text), parser)
        for table in tree.xpath('//table[1]'):
            for row in table.xpath('./tr[position()>1]'):
                cols = row.getchildren()
                request = cols[12].text
                if request == 'GET /server-status HTTP/1.1':
                    continue
                result.append({
                   'pid': cols[1].text,
                   'client': cols[10].text,
                   'request': cols[12].text,
                })
        return result


@private
@description("Adds new WebDAV share")
@accepts(h.ref('Share'))
class CreateWebDAVShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating WebDAV share"

    def describe(self, share):
        return TaskDescription("Creating WebDAV share {name}", name=share.get('name', '') if share else '')

    def verify(self, share):
        return ['service:webdav']

    def run(self, share):
        normalize(share['properties'], {
            'read_only': False,
            'permission': False,
            'show_hidden_files': False,
        })
        id = self.datastore.insert('shares', share)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'webdav')
        self.dispatcher.call_sync('service.reload', 'webdav')
        self.dispatcher.dispatch_event('share.webdav.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@private
@description("Updates existing WebDAV share")
@accepts(str, h.ref('Share'))
class UpdateWebDAVShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating WebDAV share"

    def describe(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        return TaskDescription("Updating WebDAV share {name}", name=share.get('name', id) if share else id)

    def verify(self, id, updated_fields):
        return ['service:webdav']

    def run(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        share.update(updated_fields)
        self.datastore.update('shares', id, share)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'webdav')
        self.dispatcher.call_sync('service.reload', 'webdav')
        self.dispatcher.dispatch_event('share.webdav.changed', {
            'operation': 'update',
            'ids': [id]
        })


@private
@description("Removes WebDAV share")
@accepts(str)
class DeleteWebDAVShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting WebDAV share"

    def describe(self, id):
        share = self.datastore.get_by_id('shares', id)
        return TaskDescription("Deleting WebDAV share {name}", name=share.get('name', id) if share else id)

    def verify(self, id):
        return ['service:webdav']

    def run(self, id):
        self.datastore.delete('shares', id)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'webdav')
        self.dispatcher.call_sync('service.reload', 'webdav')
        self.dispatcher.dispatch_event('share.webdav.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@private
@description("Imports existing WebDAV share")
@accepts(h.ref('Share'))
class ImportWebDAVShareTask(CreateWebDAVShareTask):
    @classmethod
    def early_describe(cls):
        return "Importing WebDAV share"

    def describe(self, share):
        return TaskDescription("Importing WebDAV share {name}", name=share.get('name', '') if share else '')

    def verify(self, share):
        return super(ImportWebDAVShareTask, self).verify(share)

    def run(self, share):
        return super(ImportWebDAVShareTask, self).run(share)


def _metadata():
    return {
        'type': 'sharing',
        'subtype': 'FILE',
        'perm_type': 'PERM',
        'method': 'webdav'
    }


def _depends():
    return ['WebDAVPlugin', 'SharingPlugin']


def _init(dispatcher, plugin):

    plugin.register_task_handler("share.webdav.create", CreateWebDAVShareTask)
    plugin.register_task_handler("share.webdav.update", UpdateWebDAVShareTask)
    plugin.register_task_handler("share.webdav.delete", DeleteWebDAVShareTask)
    plugin.register_task_handler("share.webdav.import", ImportWebDAVShareTask)
    plugin.register_provider("share.webdav", WebDAVSharesProvider)
    plugin.register_event_type('share.webdav.changed')