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

#include "plugin.h"
#include "cfg.h"
#include "template/simple-function.h"
#include "plugin-types.h"

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <glib.h>
#include <serviced.h>

static void
tf_pid_to_label(LogMessage *msg, gint argc, GString *argv[], GString *result)
{
	struct serviced_job *job;
	pid_t pid;

	pid = (pid_t)strtol(argv[0]->str, (char **)NULL, 10);
	job = serviced_get_job_by_pid(pid, true);

	if (job == NULL) {
		g_string_append_printf(result, "unknown");
		return;
	}

	g_string_append_printf(result, "%s", job->sj_label);
	serviced_job_free(job);
}

TEMPLATE_FUNCTION_SIMPLE(tf_pid_to_label);

static Plugin serviced_plugins[] =
{
    TEMPLATE_FUNCTION_PLUGIN(tf_pid_to_label, "pid-to-label")
};

gboolean
serviced_module_init(GlobalConfig *cfg, CfgArgs *args)
{
	plugin_register(cfg, serviced_plugins, G_N_ELEMENTS(serviced_plugins));
	return TRUE;
}

const ModuleInfo module_info =
{
    .canonical_name = "serviced",
    .version = VERSION,
    .description = "The serviced module provides template function to convert PID into service Label",
    .core_revision = SOURCE_REVISION,
    .plugins = serviced_plugins,
    .plugins_len = G_N_ELEMENTS(serviced_plugins),
};
