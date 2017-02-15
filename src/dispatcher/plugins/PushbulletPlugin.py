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

import socket
from typing import Optional, List
from freenas.dispatcher.rpc import private
from freenas.dispatcher.model import BaseStruct, types
from datastore.config import ConfigNode
from task import Provider, Task


class AlertEmitterPushbullet(BaseStruct):
    __variant_of__ = types.AlertEmitterConfig
    api_key: Optional[str]


class PushbulletProvider(Provider):
    @private
    def get_api_key(self) -> str:
        node = ConfigNode('pushbullet', self.configstore)
        return node['api_key'].value

    @private
    def get_config(self) -> AlertEmitterPushbullet:
        node = ConfigNode('pushbullet', self.configstore).__getstate__()
        return AlertEmitterPushbullet(node)


@private
class PushbulletConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating pushbullet configuration"

    def describe(self, config: AlertEmitterPushbullet) -> str:
        return "Updating pushbullet configuration"

    def verify(self, config: AlertEmitterPushbullet) -> List[str]:
        return []

    def run(self, config: AlertEmitterPushbullet) -> None:
        node = ConfigNode('pushbullet', self.configstore)
        node.update(config)


def _metadata():
    return {
        'id': '6728a456-f24a-11e6-8277-0cc47a3511b4',
        'type': 'alert_emitter',
        'name': 'pushbullet'
    }


def _depends():
    return ['AlertPlugin']


def _init(dispatcher, plugin):
    plugin.register_provider('alert.emitter.pushbullet', PushbulletProvider)
    plugin.register_task_handler('alert.emitter.pushbullet.update', PushbulletConfigureTask)
