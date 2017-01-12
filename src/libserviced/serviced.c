/*
 * Copyright 2017 iXsystems, Inc.
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <errno.h>
#include <jansson.h>
#include <dispatcher.h>
#include "serviced.h"

static int call_serviced(const char *, json_t *, json_t **);
static void marshal_job(struct serviced_job *, json_t *);

static int
call_serviced(const char *method, json_t *args, json_t **result)
{
	connection_t *conn;
	int err, rpc_err;

	conn = dispatcher_open("unix:///var/run/serviced.sock");
	if (conn == NULL)
		return (-1);

	err = dispatcher_call_sync(conn, method, args, result);
	if (err == RPC_CALL_ERROR) {
		rpc_err = json_integer_value(json_object_get(*result, "code"));
		*result = json_null();
		dispatcher_close(conn);
		errno = rpc_err;
		return (-1);
	}

	if (err != RPC_CALL_DONE) {
		dispatcher_close(conn);
		errno = EINVAL;
		return (-1);
	}

	json_incref(*result);
	dispatcher_close(conn);
	return (0);
}

static void
marshal_job(struct serviced_job *job, json_t *json)
{

	job->sj_label = json_string_value(json_object_get(json, "Label"));
	job->sj_pid = (pid_t)json_integer_value(json_object_get(json, "PID"));
	job->sj_job = json;
}

int
serviced_checkin(void)
{

	return (call_serviced("serviced.job.checkin", json_pack("[]"), NULL));
}

struct serviced_job *
serviced_get_job_by_label(const char *label)
{
	struct serviced_job *result;
	json_t *job;
	int ret;

	ret = call_serviced("serviced.job.get", json_pack("[s]", label), &job);
	if (ret != 0) {
		json_decref(job);
		return (NULL);
	}

	result = calloc(1, sizeof(struct serviced_job));
	marshal_job(result, job);

	return (result);
}

struct serviced_job *
serviced_get_job_by_pid(pid_t pid, bool fuzzy)
{
	struct serviced_job *result;
	json_t *job;
	int ret;

	ret = call_serviced("serviced.job.get_by_pid",
	    json_pack("[ib]", pid, fuzzy), &job);
	if (ret != 0) {
		json_decref(job);
		return (NULL);
	}

	result = calloc(1, sizeof(struct serviced_job));
	marshal_job(result, job);

	return (result);
}

void
serviced_job_free(struct serviced_job *job)
{

	if (job == NULL)
		return;

	json_decref(job->sj_job);
	free(job);
}
