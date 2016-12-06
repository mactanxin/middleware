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
from collections import deque
from datetime import datetime

from datastore import DatastoreException
from freenas.dispatcher.rpc import (
    RpcException,
    SchemaHelper as h,
    accepts,
    description,
    returns,
    private,
    generator
)
from task import Provider, Task, TaskException, TaskDescription, VerifyException, query
from freenas.utils import normalize


logger = logging.getLogger('AlertPlugin')
registered_alerts = {}
pending_alerts = deque()
pending_cancels = deque()


@description('Provides access to the alert system')
class AlertsProvider(Provider):
    @query('alert')
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream(
            'alerts', *(filter or []), **(params or {})
        )

    @private
    @accepts(str, str)
    @returns(h.one_of(h.ref('alert'), None))
    def get_active_alert(self, cls, target):
        return self.datastore.query(
            'alerts',
            ('class', '=', cls), ('target', '=', target), ('active', '=', True),
            single=True
        )

    @description("Dismisses/Deletes an alert from the database")
    @accepts(int)
    def dismiss(self, id):
        alert = self.datastore.get_by_id('alerts', id)
        if not alert:
            raise RpcException(errno.ENOENT, 'Alert {0} not found'.format(id))

        if alert['dismissed']:
            raise RpcException(errno.ENOENT, 'Alert {0} is already dismissed'.format(id))

        alert.update({
            'dismissed': True,
            'dismissed_at': datetime.utcnow()
        })

        self.datastore.update('alerts', id, alert)
        self.dispatcher.dispatch_event('alert.changed', {
            'operation': 'update',
            'ids': [id]
        })


    @description("Dismisses/Deletes all alerts from the database")
    @accepts()
    def dismiss_all(self):
        alert_list = self.query([('dismissed', '=', False)])
        for alert in alert_list:
            alert.update({
                'dismissed': True,
                'dismissed_at': datetime.utcnow()
            })

            self.datastore.update('alerts', alert['id'], alert)
            self.dispatcher.dispatch_event('alert.changed', {
                'operation': 'update',
                'ids': [alert['id']]
            })

    @private
    @description("Emits an event for the provided alert")
    @accepts(h.all_of(
        h.ref('alert'),
        h.required('class')
    ))
    @returns(int)
    def emit(self, alert):
        cls = self.datastore.get_by_id('alert.classes', alert['class'])
        if not cls:
            raise RpcException(errno.ENOENT, 'Alert class {0} not found'.format(alert['class']))

        normalize(alert, {
            'when': datetime.utcnow(),
            'dismissed': False,
            'active': True,
            'one_shot': False,
            'severity': cls['severity']
        })

        alert.update({
            'type': cls['type'],
            'subtype': cls['subtype'],
            'send_count': 0
        })

        id = self.datastore.insert('alerts', alert)
        self.dispatcher.dispatch_event('alert.changed', {
            'operation': 'create',
            'ids': [id]
        })

        try:
            self.dispatcher.call_sync('alertd.alert.emit', id)
        except RpcException as err:
            if err.code == errno.ENOENT:
                # Alertd didn't start yet. Add alert to the pending queue
                pending_alerts.append(id)
            else:
                raise

        return id

    @private
    @description("Cancels already scheduled alert")
    @accepts(int)
    def cancel(self, id):
        alert = self.datastore.get_by_id('alerts', id)
        if not alert:
            raise RpcException(errno.ENOENT, 'Alert {0} not found'.format(id))

        if not alert['active']:
            raise RpcException(errno.ENOENT, 'Alert {0} is already cancelled'.format(id))

        alert.update({
            'active': False,
            'cancelled_at': datetime.utcnow()
        })

        self.datastore.update('alerts', id, alert)
        self.dispatcher.dispatch_event('alert.changed', {
            'operation': 'update',
            'ids': [id]
        })

        try:
            self.dispatcher.call_sync('alertd.alert.cancel', id)
        except RpcException as err:
            if err.code == errno.ENOENT:
                # Alertd didn't start yet. Add alert to the pending queue
                pending_cancels.append(id)
            else:
                raise

        return id

    @description("Returns list of registered alerts")
    @accepts()
    @returns(h.ref('alert-class'))
    def get_alert_classes(self):
        return self.datastore.query('alert.classes')


@description('Provides access to the alerts filters')
class AlertsFiltersProvider(Provider):

    @query('alert-filter')
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream(
            'alert.filters', *(filter or []), **(params or {})
        )


@description("Creates an Alert Filter")
@accepts(h.all_of(
    h.ref('alert-filter'),
    h.required('id', 'emitter', 'parameters')
))
class AlertFilterCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating alert filter'

    def describe(self, alertfilter):
        return TaskDescription('Creating alert filter {name}', name=alertfilter.get('name', '') if alertfilter else '')

    def verify(self, alertfilter):
        return []

    def run(self, alertfilter):
        id = self.datastore.insert('alert.filters', alertfilter)
        normalize(alertfilter, {
            'predicates': []
        })

        self.dispatcher.dispatch_event('alert.filter.changed', {
            'operation': 'create',
            'ids': [id]
        })


@description("Deletes the specified Alert Filter")
@accepts(str)
class AlertFilterDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting alert filter'

    def describe(self, id):
        alertfilter = self.datastore.get_by_id('alert.filters', id)
        return TaskDescription('Deleting alert filter {name}', name=alertfilter.get('name', id) if alertfilter else id)

    def verify(self, id):

        alertfilter = self.datastore.get_by_id('alert.filters', id)
        if alertfilter is None:
            raise VerifyException(
                errno.ENOENT,
                'Alert filter with ID {0} does not exist'.format(id)
            )

        return []

    def run(self, id):
        try:
            self.datastore.delete('alert.filters', id)
        except DatastoreException as e:
            raise TaskException(
                errno.EBADMSG,
                'Cannot delete alert filter: {0}'.format(str(e))
            )

        self.dispatcher.dispatch_event('alert.filter.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@description("Updates the specified Alert Filter")
@accepts(str, h.ref('alert-filter'))
class AlertFilterUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating alert filter'

    def describe(self, id, updated_fields):
        alertfilter = self.datastore.get_by_id('alert.filters', id)
        return TaskDescription('Updating alert filter {name}', name=alertfilter.get('name', id) if alertfilter else id)

    def verify(self, id, updated_fields):
        return []

    def run(self, id, updated_fields):
        try:
            alertfilter = self.datastore.get_by_id('alert.filters', id)
            alertfilter.update(updated_fields)
            self.datastore.update('alert.filters', id, alertfilter)
        except DatastoreException as e:
            raise TaskException(
                errno.EBADMSG,
                'Cannot update alert filter: {0}'.format(str(e))
            )

        self.dispatcher.dispatch_event('alert.filter.changed', {
            'operation': 'update',
            'ids': [id],
        })


@accepts(str, h.ref('alert-severity'))
@description('Sends user alerts')
class SendAlertTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Sending user alert'

    def describe(self, message, priority=None):
        return TaskDescription('Sending user alert')

    def verify(self, message, priority=None):
        return []

    def run(self, message, priority=None):
        if not priority:
            priority = 'WARNING'

        self.dispatcher.call_sync('alert.emit', {
            'class': 'UserMessage',
            'severity': priority,
            'title': 'Message from user {0}'.format(self.user),
            'description': message,
            'one_shot': True
        })


def _init(dispatcher, plugin):
    plugin.register_schema_definition('alert-severity', {
        'type': 'string',
        'enum': ['CRITICAL', 'WARNING', 'INFO'],
    })

    plugin.register_schema_definition('alert-class-id', {
        'type': 'string',
        'enum': dispatcher.datastore.query('alert.classes', select='id')
    })

    plugin.register_schema_definition('alert', {
        'type': 'object',
        'properties': {
            'id': {'type': 'integer'},
            'class': {'$ref': 'alert-class-id'},
            'type': {'$ref': 'alert-type'},
            'subtype': {'type': 'string'},
            'severity': {'$ref': 'alert-severity'},
            'target': {'type': 'string'},
            'title': {'type': 'string'},
            'description': {'type': 'string'},
            'user': {'type': 'string'},
            'happened_at': {'type': 'string'},
            'cancelled_at': {'type': ['string', 'null']},
            'dismissed_at': {'type': ['string', 'null']},
            'last_emitted_at': {'type': ['string', 'null']},
            'active': {'type': 'boolean'},
            'dismissed': {'type': 'boolean'},
            'one_shot': {'type': 'boolean'},
            'send_count': {'type': 'integer'}
        },
        'additionalProperties': False
    })

    plugin.register_schema_definition('alert-type', {
        'type': 'string',
        'enum': ['SYSTEM', 'VOLUME', 'DISK']
    })

    plugin.register_schema_definition('alert-emitter-email', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['alert-emitter-email']},
            'addresses': {
                'type': 'array',
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('alert-filter', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'emitter': {'type': 'string'},
            'parameters': {
                'discriminator': '%type',
                'oneOf': [
                    {'$ref': 'alert-emitter-email'}
                ]
            },
            'predicates': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'property': {
                            'type': 'string',
                            'enum': [
                                'class', 'type', 'subtype', 'target', 'description',
                                'severity', 'active', 'dismissed'
                            ]
                        },
                        'operator': {
                            'type': 'string',
                            'enum': ['==', '!=', '<=', '>=', '>', '<', '~']
                        },
                        'value': {'type': ['string', 'integer', 'boolean', 'null']}
                    }
                }
            }
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('alert-class', {
        'type': 'object',
        'additionalProperties': {
            'type': 'object',
            'properties': {
                'id': {'$ref': 'alert-class-id'},
                'type': {'type': 'string'},
                'subtype': {'type': 'string'},
                'severity': {'$ref': 'alert-severity'}
            },
            'additionalProperties': False,
        }
    })

    # Register providers
    plugin.register_provider('alert', AlertsProvider)
    plugin.register_provider('alert.filter', AlertsFiltersProvider)

    # Register task handlers
    plugin.register_task_handler('alert.send', SendAlertTask)
    plugin.register_task_handler('alert.filter.create', AlertFilterCreateTask)
    plugin.register_task_handler('alert.filter.delete', AlertFilterDeleteTask)
    plugin.register_task_handler('alert.filter.update', AlertFilterUpdateTask)

    def on_alertd_started(args):
        if args['service-name'] != 'alertd.alert':
            return

        while pending_alerts:
            id = pending_alerts[-1]
            try:
                dispatcher.call_sync('alertd.alert.emit', id)
            except RpcException:
                logger.warning('Failed to emit alert {0}'.format(id))
            else:
                pending_alerts.pop()

        while pending_cancels:
            id = pending_cancels[-1]
            try:
                dispatcher.call_sync('alertd.alert.cancel', id)
            except RpcException:
                logger.warning('Failed to cancel alert {0}'.format(id))
            else:
                pending_cancels.pop()

    plugin.register_event_handler('plugin.service_registered', on_alertd_started)

    # Register event types
    plugin.register_event_type(
        'alert.changed',
        schema={
            'type': 'object',
            'properties': {
                'operation': {'type': 'string', 'enum': ['create', 'delete']},
                'ids': {'type': 'array', 'items': 'integer'},
            },
            'additionalProperties': False
        }
    )
    plugin.register_event_type(
        'alert.filter.changed',
        schema={
            'type': 'object',
            'properties': {
                'operation': {'type': 'string', 'enum': ['create', 'delete', 'update']},
                'ids': {'type': 'array', 'items': 'string'},
            },
            'additionalProperties': False
        }
    )
