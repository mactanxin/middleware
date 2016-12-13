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

from apscheduler.jobstores.base import BaseJobStore, JobLookupError, ConflictingIdError
from apscheduler.triggers.cron import CronTrigger
from apscheduler.util import datetime_to_utc_timestamp, utc_timestamp_to_datetime
from apscheduler.job import Job
from datastore import get_datastore, DuplicateKeyException


class FreeNASJobStore(BaseJobStore):
    def __init__(self):
        self.ds = get_datastore()
        self._scheduler = None
        self._jobstore_alias = None

    def start(self, scheduler, alias):
        self._scheduler = scheduler
        self._jobstore_alias = alias

    @property
    def connection(self):
        return self.ds

    def lookup_job(self, job_id):
        document = self.ds.get_by_id(job_id)
        return self._reconstitute_job(document) if document else None

    def get_due_jobs(self, now):
        timestamp = datetime_to_utc_timestamp(now)
        return self._get_jobs(('next_run_time', '=<', timestamp))

    def get_next_run_time(self):
        document = self.ds.get_one('calendar_tasks', ('next_run_time', '!=', None), sort='next_run_time')
        return utc_timestamp_to_datetime(document['next_run_time']) if document else None

    def get_all_jobs(self):
        jobs = self._get_jobs()
        self._fix_paused_jobs_sorting(jobs)
        return jobs

    def add_job(self, job):
        try:
            self.ds.insert('calendar_tasks', self._serialize_job(job))
        except DuplicateKeyException:
            raise ConflictingIdError(job.id)

    def update_job(self, job):
        self.ds.update('calendar_tasks', job.id, self._serialize_job(job))

    def remove_job(self, job_id):
        result = self.collection.remove(job_id)
        if result and result['n'] == 0:
            raise JobLookupError(job_id)

    def remove_all_jobs(self):
        for i in self.get_all_jobs():
            self.ds.delete(i.id)

    def shutdown(self):
        self.ds.close()

    def _serialize_job(self, job):
        schedule = {f.name: str(f) for f in job.trigger.fields}
        return {
            'id': job.id,
            'name': job.name,
            'next_run_time': datetime_to_utc_timestamp(job.next_run_time),
            'task': job.args[0],
            'args': job.args[1:],
            'enabled': job.next_run_time is not None,
            'hidden': job.kwargs['hidden'],
            'protected': job.kwargs['protected'],
            'schedule': schedule
        }

    def _reconstitute_job(self, job_state):
        schedule = job_state['schedule']
        schedule.pop('coalesce', None)
        job = Job(
            id=job_state['id'],
            func="__main__:job",
            trigger=CronTrigger(**schedule),
            name=job_state['name'],
            args=[job_state['task']] + job_state['args'],
            scheduler=self._scheduler,
            next_run_time=utc_timestamp_to_datetime(job_state['next_run_time']),
            kwargs={
                'id': job_state['id'],
                'name': job_state['name'],
                'hidden': job_state.get('hidden', False),
                'protected': job_state.get('protected', False)
            }
        )

        job._jobstore_alias = self._alias
        return job

    def _get_jobs(self, *conditions):
        jobs = []
        failed_job_ids = []
        for document in self.ds.query('calendar_tasks', *conditions, sort='next_run_time'):
            try:
                jobs.append(self._reconstitute_job(document))
            except:
                self._logger.exception('Unable to restore job "%s" -- removing it', document['id'])
                failed_job_ids.append(document['id'])

        # Remove all the jobs we failed to restore
        for i in failed_job_ids:
            self.ds.delete('calendar_tasks', i)

        return jobs

    def __repr__(self):
        return '<%s (client=%s)>' % (self.__class__.__name__, self.client)
