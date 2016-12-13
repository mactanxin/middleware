#+
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

import pickle
from calendar import timegm


def datetime_to_utc_timestamp(timeval):
    if timeval is not None:
        return timegm(timeval.utctimetuple()) + timeval.microsecond / 1000000


def probe(obj, ds):
    return 'job_state' in obj and isinstance(obj['job_state'], bytes)


def apply(obj, ds):
    try:
        job = pickle.loads(obj['job_state'])
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
    except:
        return None
