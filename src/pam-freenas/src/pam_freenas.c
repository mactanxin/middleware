/*+
 * Copyright 2016 iXsystems, Inc.
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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>
#include <jansson.h>
#include <dispatcher.h>

#define PASSWD_FILE "/etc/passwd.json"
#define PASSWORD_PROMPT "Password:"

static void flat_load_files();
static json_t *flat_find_user(const char *);
static int call_dispatcher(const char *, json_t *, json_t **);
static int emit_event(const char *, json_t *);

static json_t *flat_users;

static void
flat_load_files()
{
	json_error_t err;

	flat_users = json_load_file(PASSWD_FILE, 0, &err);
	if (flat_users == NULL)
		PAM_LOG("Cannot read %s: %s", PASSWD_FILE, err.text);
}

static json_t *
flat_find_user(const char *name)
{
	json_t *user;
	json_t *val;
	size_t index;

	if (flat_users == NULL)
		flat_load_files();

	/* Bail out if still null */
	if (flat_users == NULL)
		return (NULL);

	json_array_foreach(flat_users, index, user) {
		val = json_object_get(user, "username");
		if (val == NULL)
			continue;

		if (strcmp(json_string_value(val), name) == 0) {
			json_incref(user);
			return (user);
		}
	}

	return (NULL);
}

static int
call_dispatcher(const char *method, json_t *args, json_t **result)
{
	connection_t *conn;
	int err;

	conn = dispatcher_open("unix:///var/run/dscached.sock");
	if (conn == NULL) {
		PAM_LOG("Cannot open unix domain socket connection");
		return (-1);
	}

	err = dispatcher_call_sync(conn, method, args, result);
	if (err != RPC_CALL_DONE) {
		PAM_LOG("Cannot call %s: %d", method, err);
		dispatcher_close(conn);
		return (-1);
	}

	if (result != NULL)
		json_incref(*result);

	dispatcher_close(conn);
	return (0);
}

PAM_EXTERN int
pam_sm_open_session(struct pam_handle *pamh, int flags, int argc,
    const char *argv[])
{
	const char *username, *tty, *service;
	json_t *args;
	int err;

	err = pam_get_user(pamh, &username, NULL);
	if (err != PAM_SUCCESS)
		return (err);

	err = pam_get_item(pamh, PAM_TTY, (const void **)&tty);
	if (err != PAM_SUCCESS)
		return (err);

	err = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	if (err != PAM_SUCCESS)
		return (err);

	args = json_pack("[{ssss?ss?}]",
	    "username", username,
	    "tty", tty,
	    "service", service
	);

	if (call_dispatcher("dscached.management.session_open", args, NULL) != 0)
		return (PAM_SERVICE_ERR);

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(struct pam_handle *pamh, int flags, int argc,
    const char *argv[])
{
	const char *username, *tty, *service;
	json_t *args;
	int err;

	err = pam_get_user(pamh, &username, NULL);
	if (err != PAM_SUCCESS)
		return (err);

	err = pam_get_item(pamh, PAM_TTY, (const void **)&tty);
	if (err != PAM_SUCCESS)
		return (err);

	err = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	if (err != PAM_SUCCESS)
		return (err);

	args = json_pack("[{ssss?ss?}]",
	    "username", username,
	    "tty", tty,
	    "service", service
	);

	if (call_dispatcher("dscached.management.session_close", args, NULL) != 0)
		return (PAM_SERVICE_ERR);

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_setcred(struct pam_handle *pamh, int flags, int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(struct pam_handle *pamh, int flags, int argc,
    const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_authenticate(struct pam_handle *pamh, int flags, int argc,
    const char *argv[])
{
	const char *username, *password, *realpw;
	char *result_s;
	json_t *user, *result;
	int err;

	err = pam_get_user(pamh, &username, NULL);
	if (err != PAM_SUCCESS)
		return (err);

	PAM_LOG("Got user: %s", username);

	err = pam_get_authtok(pamh, PAM_AUTHTOK, &password, PASSWORD_PROMPT);
	if (err != PAM_SUCCESS)
		return (err);

	PAM_LOG("Got password");

	if (call_dispatcher("dscached.account.authenticate",
		json_pack("[ss]", username, password), &result) != 0) {
		PAM_LOG("Cannot call dispatcher, trying local file backend");

		/* Try flat file lookup */
		flat_load_files();

		user = flat_find_user(username);
		if (user == NULL) {
			PAM_LOG("User %s not found", username);
			return (PAM_PERM_DENIED);
		}

		realpw = json_string_value(json_object_get(user, "unixhash"));
		if (realpw == NULL || strcmp(realpw, "*") == 0) {
			PAM_LOG("User %s has empty password", username);
			if (openpam_get_option(pamh, PAM_OPT_NULLOK))
				return (PAM_SUCCESS);
			return (PAM_PERM_DENIED);
		}

		if (strcmp(crypt(password, realpw), realpw) == 0)
			return (PAM_SUCCESS);

		return (PAM_AUTH_ERR);
	}

	result_s = json_dumps(result, JSON_ENCODE_ANY);
	PAM_LOG("Result: %s", result_s);
	free(result_s);

	if (json_is_true(result)) {
		json_decref(result);
		return (PAM_SUCCESS);
	}

	json_decref(result);
	return (PAM_AUTH_ERR);
}

PAM_EXTERN int
pam_sm_chauthtok(struct pam_handle *pamh, int flags, int argc,
    const char *argv[])
{
	const char *username, *old_pass, *new_pass;
	json_t *result;
	int retval;

	if (openpam_get_option(pamh, PAM_OPT_AUTH_AS_SELF))
		username = getlogin();
	else {
		retval = pam_get_user(pamh, &username, NULL);
		if (retval != PAM_SUCCESS)
			return (retval);
	}

	PAM_LOG("Got user: %s", username);

	if (flags & PAM_PRELIM_CHECK) {

	}

	if (flags & PAM_UPDATE_AUTHTOK) {
		retval = pam_get_authtok(pamh,
		    PAM_OLDAUTHTOK, &old_pass, NULL);
		if (retval != PAM_SUCCESS)
			return (retval);

		PAM_LOG("Got old password");

		/* get new password */
		for (;;) {
			retval = pam_get_authtok(pamh,
			    PAM_AUTHTOK, &new_pass, NULL);
			if (retval != PAM_TRY_AGAIN)
				break;
			pam_error(pamh, "Mismatch; try again, EOF to quit.");
		}

		PAM_LOG("Got new password");

		if (retval != PAM_SUCCESS) {
			PAM_VERBOSE_ERROR("Unable to get new password");
			return (retval);
		}

		if (call_dispatcher("dscached.account.change_password",
		    json_pack("[ss]", username, new_pass), &result) != 0) {
			retval = PAM_SERVICE_ERR;
		} else
			retval = PAM_SUCCESS;

	}

	json_decref(result);
	return (retval);
}

PAM_MODULE_ENTRY("pam_freenas");
