#+
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

import sys
import time
import uuid
import logging
import setproctitle
import argparse
import pytz
import errno
from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.mongodb import MongoDBJobStore
from datastore import get_datastore, DatastoreException
from datastore.config import ConfigStore
from freenas.dispatcher.rpc import RpcService, RpcException, private, generator
from freenas.dispatcher.client import Client, ClientError
from freenas.utils import configure_logging
from freenas.utils.query import query
from freenas.utils.debug import DebugService


DEFAULT_CONFIGFILE = '/usr/local/etc/middleware.conf'
ctx = None


def job(*args, **kwargs):
    return ctx.run_job(*args, **kwargs)


class ManagementService(RpcService):
    def __init__(self, context):
        self.context = context

    @private
    @generator
    def query(self, filter=None, params=None):
        def serialize(job):
            last_task = None
            current_task = None
            current_progress = None
            schedule = {f.name: f for f in job.trigger.fields}
            schedule['coalesce'] = job.coalesce
            schedule['timezone'] = job.trigger.timezone

            last_run = self.context.datastore.query(
                'schedulerd.runs',
                ('job_id', '=', job.id),
                sort='created_at',
                single=True
            )

            if last_run:
                last_task = self.context.datastore.get_by_id('tasks', last_run['task_id'])

            return {
                'id': job.id,
                'name': job.name,
                'task': job.args[0],
                'args': job.args[1:],
                'enabled': job.next_run_time is not None,
                'hidden': job.kwargs['hidden'],
                'protected': job.kwargs['protected'],
                'status': {
                    'next_run_time': job.next_run_time,
                    'last_run_time': last_run['created_at'] if last_run else None,
                    'last_run_status': last_task['state'] if last_task else None,
                    'current_run_id': self.context.active_tasks.get(job.id)
                },
                'schedule': schedule
            }

        return query(list(map(serialize, self.context.scheduler.get_jobs())), *(filter or []), **(params or {}))

    @private
    def add(self, task):
        if 'id' not in task:
            task_id = str(uuid.uuid4())
        else:
            task_id = task['id']

        if not task.get('enabled'):
            task['schedule']['next_run_time'] = None

        self.context.logger.info('Adding new job with ID {0}'.format(task_id))
        self.context.scheduler.add_job(
            job,
            name=task['name'],
            trigger='cron',
            id=task_id,
            args=[task['task']] + task['args'],
            kwargs={
                'id': task_id,
                'name': task['name'],
                'hidden': task.get('hidden', False),
                'protected': task.get('protected', False)
            },
            **task['schedule']
        )

        return task_id

    @private
    def delete(self, job_id):
        job = self.context.scheduler.get_job(job_id)
        if not job:
            raise RpcException(errno.ENOENT, 'Job with id: {0} does not exist'.format(job_id))
        if job.kwargs['protected']:
            raise RpcException(errno.EPERM, 'Job {0} is protected from being deleted'.format(job_id))

        self.context.logger.info('Deleting job with ID {0}'.format(job_id))
        self.context.scheduler.remove_job(job_id)

    @private
    def update(self, job_id, updated_params):
        currjob = self.context.scheduler.get_job(job_id)
        self.context.logger.info('Updating job with ID {0}'.format(job_id))

        if 'name' in updated_params:
            if currjob['protected']:
                raise RpcException(errno.EPERM, 'Job {0} is protected from being renamed'.format(job_id))

            self.context.scheduler.modify_job(job_id, name=updated_params['name'])

        if 'task' in updated_params or 'args' in updated_params:
            task = updated_params.get('task', currjob.args[0])
            args = updated_params.get('args', currjob.args[1:])
            self.context.scheduler.modify_job(job_id, args=[task] + args)

        if 'schedule' in updated_params:
            currjob = self.context.scheduler.get_job(job_id)

            if 'enabled' in updated_params:
                if not updated_params['enabled']:
                    updated_params['schedule']['next_run_time'] = None
            elif not currjob.next_run_time:
                updated_params['schedule']['next_run_time'] = None

            self.context.scheduler.add_job(
                job,
                name=currjob.name,
                trigger='cron',
                id=currjob.id,
                args=currjob.args,
                kwargs=currjob.kwargs,
                replace_existing=True,
                **updated_params['schedule']
            )
        else:
            if 'enabled' in updated_params:
                if updated_params['enabled']:
                    self.context.scheduler.resume_job(job_id)
                else:
                    self.context.scheduler.pause_job(job_id)

    @private
    def run(self, job_id):
        self.context.logger.info('Running job {0} manualy'.format(job_id))
        jb = self.context.scheduler.get_job(job_id)
        self.context.scheduler.add_job(
            job,
            id=job_id + '-temp',
            args=jb.args,
            kwargs=jb.kwargs,
            run_date=datetime.now(timezone.utc)
        )


class Context(object):
    def __init__(self):
        self.logger = logging.getLogger('schedulerd')
        self.config = None
        self.datastore = None
        self.configstore = None
        self.client = None
        self.scheduler = None
        self.active_tasks = {}

    def init_datastore(self):
        try:
            self.datastore = get_datastore(self.config)
        except DatastoreException as err:
            self.logger.error('Cannot initialize datastore: %s', str(err))
            sys.exit(1)

        self.configstore = ConfigStore(self.datastore)

    def init_dispatcher(self):
        def on_error(reason, **kwargs):
            if reason in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
                self.logger.warning('Connection to dispatcher lost')
                self.connect()

        self.client = Client()
        self.client.on_error(on_error)
        self.connect()

    def init_scheduler(self):
        store = MongoDBJobStore(database='freenas', collection='calendar_tasks', client=self.datastore.client)
        self.scheduler = BackgroundScheduler(jobstores={'default': store}, timezone=pytz.utc)
        self.scheduler.start()

    def connect(self):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('schedulerd')
                self.client.enable_server()
                self.client.register_service('scheduler.management', ManagementService(self))
                self.client.register_service('scheduler.debug', DebugService())
                self.client.resume_service('scheduler.management')
                self.client.resume_service('scheduler.debug')
                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

    def run_job(self, *args, **kwargs):
        tid = self.client.call_sync('task.submit_with_env', args[0], args[1:], {
            'RUN_AS_USER': 'root',
            'CALENDAR_TASK_NAME': kwargs.get('name')
        })

        self.active_tasks[kwargs['id']] = tid
        self.client.call_sync('task.wait', tid, timeout=None)
        result = self.client.call_sync('task.status', tid)
        if result['state'] != 'FINISHED':
            try:
                self.client.call_sync('alert.emit', {
                    'name': 'scheduler.task.failed',
                    'severity': 'CRITICAL',
                    'description': 'Task {0} has failed: {1}'.format(
                        kwargs.get('name', tid),
                        result['error']['message']
                    ),
                })
            except RpcException as e:
                self.logger.error('Failed to emit alert', exc_info=True)

        del self.active_tasks[kwargs['id']]
        self.datastore.insert('schedulerd.runs', {
            'job_id': kwargs['id'],
            'task_id': result['id']
        })

    def emit_event(self, name, params):
        self.client.emit_event(name, params)

    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', metavar='CONFIG', default=DEFAULT_CONFIGFILE, help='Middleware config file')
        parser.add_argument('-f', action='store_true', default=False, help='Run in foreground')
        args = parser.parse_args()
        configure_logging('/var/log/schedulerd.log', 'DEBUG')
        setproctitle.setproctitle('schedulerd')
        self.config = args.c
        self.init_datastore()
        self.init_scheduler()
        self.init_dispatcher()
        self.client.wait_forever()


if __name__ == '__main__':
    global ctx

    c = Context()
    ctx = c
    c.main()

