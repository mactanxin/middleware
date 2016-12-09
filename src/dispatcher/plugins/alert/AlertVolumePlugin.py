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
import logging


logger = logging.getLogger('AlertVolume')


def _depends():
    return ['AlertPlugin', 'VolumePlugin', 'ZfsPlugin']


def _init(dispatcher, plugin):
    def volume_status(volume):
        alert = dispatcher.call_sync('alert.get_active_alert', 'VolumeDegraded', volume['id'])

        if volume['status'] == 'ONLINE' and alert:
            dispatcher.call_sync('alert.cancel', alert['id'])

        if volume['status'] not in ('ONLINE', 'LOCKED') and volume['id'] and not alert:
            dispatcher.rpc.call_sync('alert.emit', {
                'class': 'VolumeDegraded',
                'target': volume['id'],
                'title': 'Volume {0} is degraded'.format(volume['id']),
                'description': 'The volume {0} state is {1}'.format(
                    volume['id'],
                    volume['status'],
                )
            })

    def volumes_upgraded():
        for volume in dispatcher.rpc.call_sync('volume.query'):
            if volume['status'] in ('UNAVAIL', 'LOCKED'):
                continue

            if volume.get('upgraded') is not False:
                continue

            if dispatcher.call_sync('alert.get_active_alert', 'VolumeUpgradePossible', volume['id']):
                continue

            dispatcher.rpc.call_sync('alert.emit', {
                'class': 'VolumeUpgradePossible',
                'target': volume['id'],
                'title': 'Volume {0} can be upgraded'.format(volume['id']),
                'description': 'New feature flags are available for volume {0}'.format(volume['id']),
            })

    for i in dispatcher.call_sync('volume.query'):
        volume_status(i)

    def on_volume_change(args):
        if args['operation'] not in ('create', 'update'):
            return

        for i in args['entities']:
            volume_status(i)

    plugin.register_event_handler('entity-subscriber.volume.changed', on_volume_change)
    volumes_upgraded()
