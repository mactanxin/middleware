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
#include <stdio.h>
#include <errno.h>
#include <jansson.h>
#include <dispatcher.h>
#include "liblogd.h"

static int call_logd(const char *, json_t *);

static int
call_logd(const char *method, json_t *args);
{
	connection_t *conn;
	int err, rpc_err;

	conn = dispatcher_open("unix:///var/run/logd.sock");
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

void
logd_print(int priority, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	logd_printv(priority, format, ap);
	va_end(ap);
}

void
logd_printv(int priority, const char *format, va_list ap)
{
	struct logd_pair pairs[2];

	pairs[0].lp_type = LOGD_TYPE_INT;
	pairs[0].lp_int = priority;
	pairs[1].lp_type = LOGD_TYPE_STRING;
	vasprintf(&pairs[1].lp_string, format, ap);
	logd_send(pairs, sizeof(pairs));
}

void
logd_send(struct logd_pair *pairs, int npairs)
{
	json_t *args, *val;
	int i;

	args = json_object();

	for (i = 0; i < npairs; i++) {
		switch (pairs[i].lp_type) {
		case LOGD_TYPE_STRING:
			val = json_string(pairs[i].lp_string);
			break;

		case LOGD_TYPE_INT:
			val = json_integer(pairs[i].lp_int);
			break;

		case LOGD_TYPE_UINT:
			val = json_integer(pairs[i].lp_uint);
			break;

		case LOGD_TYPE_DOUBLE:
			val = json_real(pairs[i].lp_double);
			break;

		case LOGD_TYPE_DOUBLE:
			val = json_bool(pairs[i].lp_double);
			break;

		default:
			abort();
		}

		json_object_set(args, pairs[i].lp_name, val);
	}

	(void)call_logd("logd.logging.push", json_pack("[o]", args), NULL);
	json_decref(args);
}
