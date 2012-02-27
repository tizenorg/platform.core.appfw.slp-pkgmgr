/*
 * slp-pkgmgr
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <ail.h>
#include <aul.h>

#include "package-manager.h"
#include "pkgmgr-internal.h"
#include "pkgmgr-info.h"
#include "pkgmgr-api.h"
#include "comm_client.h"
#include "comm_status_broadcast_server.h"

static int _get_request_id()
{
	static int internal_req_id = 1;

	return internal_req_id++;
}

typedef struct _req_cb_info {
	int request_id;
	char *req_key;
	pkgmgr_handler event_cb;
	void *data;
	struct _req_cb_info *next;
} req_cb_info;

typedef struct _listen_cb_info {
	int request_id;
	pkgmgr_handler event_cb;
	void *data;
	struct _listen_cb_info *next;
} listen_cb_info;

typedef struct _pkgmgr_client_t {
	client_type ctype;
	union {
		struct _request {
			comm_client *cc;
			req_cb_info *rhead;
		} request;
		struct _listening {
			comm_client *cc;
			listen_cb_info *lhead;
		} listening;
		struct _broadcast {
			DBusConnection *bc;
		} broadcast;
	} info;
} pkgmgr_client_t;

typedef struct _iter_data {
	pkgmgr_iter_fn iter_fn;
	void *data;
} iter_data;

static void __add_op_cbinfo(pkgmgr_client_t * pc, int request_id,
			    const char *req_key, pkgmgr_handler event_cb,
			    void *data)
{
	req_cb_info *cb_info;
	req_cb_info *current;
	req_cb_info *prev;

	cb_info = (req_cb_info *) calloc(1, sizeof(req_cb_info));
	if (cb_info == NULL) {
		_LOGD("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->req_key = strdup(req_key);
	cb_info->event_cb = event_cb;
	cb_info->data = data;
	cb_info->next = NULL;

	if (pc->info.request.rhead == NULL)
		pc->info.request.rhead = cb_info;
	else {
		current = prev = pc->info.request.rhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static req_cb_info *__find_op_cbinfo(pkgmgr_client_t *pc, const char *req_key)
{
	req_cb_info *tmp;

	tmp = pc->info.request.rhead;

	if (tmp == NULL) {
		_LOGE("tmp is NULL");
		return NULL;
	}

	_LOGD("tmp->req_key %s, req_key %s", tmp->req_key, req_key);

	while (tmp) {
		if (strncmp(tmp->req_key, req_key, strlen(tmp->req_key)) == 0)
			return tmp;
		tmp = tmp->next;
	}
	return NULL;
}

static void __remove_op_cbinfo(pkgmgr_client_t *pc, req_cb_info *info)
{
	req_cb_info *tmp;

	if (pc == NULL || pc->info.request.rhead == NULL || info == NULL)
		return;

	tmp = pc->info.request.rhead;
	while (tmp) {
		if (tmp->next == info) {
			tmp->next = info->next;
			free(info);
			return;
		}
		tmp = tmp->next;
	}
}


static void __add_stat_cbinfo(pkgmgr_client_t *pc, int request_id,
			      pkgmgr_handler event_cb, void *data)
{
	listen_cb_info *cb_info;
	listen_cb_info *current;
	listen_cb_info *prev;

	cb_info = (listen_cb_info *) calloc(1, sizeof(listen_cb_info));
	if (cb_info == NULL) {
		_LOGD("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->event_cb = event_cb;
	cb_info->data = data;
	cb_info->next = NULL;

	/* TODO - check the order of callback - FIFO or LIFO => Should be changed to LIFO */
	if (pc->info.listening.lhead == NULL)
		pc->info.listening.lhead = cb_info;
	else {
		current = prev = pc->info.listening.lhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static listen_cb_info *__find_stat_cbinfo(pkgmgr_client_t *pc, int request_id)
{
	listen_cb_info *tmp;

	tmp = pc->info.listening.lhead;

	_LOGD("tmp->request_id %d, request_id %d", tmp->request_id, request_id);

	while (tmp) {
		if (tmp->request_id == request_id)
			return tmp;
		tmp = tmp->next;
	}
	return NULL;
}

static void __remove_stat_cbinfo(pkgmgr_client_t *pc, listen_cb_info *info)
{
	listen_cb_info *tmp;

	if (pc == NULL || pc->info.listening.lhead == NULL || info == NULL)
		return;

	tmp = pc->info.listening.lhead;
	while (tmp) {
		if (tmp->next == info) {
			tmp->next = info->next;
			free(info);
			return;
		}
		tmp = tmp->next;
	}
}

static void __operation_callback(void *cb_data, const char *req_id,
				 const char *pkg_type, const char *pkg_name,
				 const char *key, const char *val)
{
	pkgmgr_client_t *pc;
	req_cb_info *cb_info;

	_LOGD("__operation_callback() req_id[%s] pkg_type[%s] pkg_name[%s]"
	      "key[%s] val[%s]\n", req_id, pkg_type, pkg_name, key, val);

	pc = (pkgmgr_client_t *) cb_data;

	/* find callback info */
	cb_info = __find_op_cbinfo(pc, req_id);
	if (cb_info == NULL)
		return;

	_LOGD("__find_op_cbinfo");

	/* call callback */
	if (cb_info->event_cb) {
		cb_info->event_cb(cb_info->request_id, pkg_type, pkg_name, key,
				  val, NULL, cb_info->data);
		_LOGD("event_cb is called");
	}

	/*remove callback for last call 
	   if (strcmp(key, "end") == 0) {
	   __remove_op_cbinfo(pc, cb_info);
	   _LOGD("__remove_op_cbinfo");
	   }
	 */

	return;
}

static void __status_callback(void *cb_data, const char *req_id,
			      const char *pkg_type, const char *pkg_name,
			      const char *key, const char *val)
{
	pkgmgr_client_t *pc;
	listen_cb_info *tmp;

	_LOGD("__status_callback() req_id[%s] pkg_type[%s] pkg_name[%s]"
	      "key[%s] val[%s]\n", req_id, pkg_type, pkg_name, key, val);

	pc = (pkgmgr_client_t *) cb_data;

	tmp = pc->info.listening.lhead;
	while (tmp) {
		if (tmp->event_cb(tmp->request_id, pkg_type, pkg_name, key, val,
				  NULL, tmp->data) != 0)
			break;
		tmp = tmp->next;
	}

	return;
}

API pkgmgr_client *pkgmgr_client_new(client_type ctype)
{
	pkgmgr_client_t *pc = NULL;
	int ret = -1;

	if (ctype != PC_REQUEST && ctype != PC_LISTENING
	    && ctype != PC_BROADCAST)
		return NULL;

	/* Allocate memory for ADT:pkgmgr_client */
	pc = calloc(1, sizeof(pkgmgr_client_t));
	if (pc == NULL) {
		_LOGE("No memory");
		return NULL;
	}

	/* Manage pc */
	pc->ctype = ctype;

	if (pc->ctype == PC_REQUEST) {
		pc->info.request.cc = comm_client_new();
		if (pc->info.request.cc == NULL) {
			_LOGE("client creation failed");
			goto err;
		}
		ret = comm_client_set_status_callback(pc->info.request.cc,
						      __operation_callback, pc);
		if (ret < 0) {
			_LOGE("comm_client_set_status_callback() failed - %d",
			      ret);
			goto err;
		}
	} else if (pc->ctype == PC_LISTENING) {
		pc->info.listening.cc = comm_client_new();
		if (pc->info.listening.cc == NULL) {
			_LOGE("client creation failed");
			goto err;
		}
		ret = comm_client_set_status_callback(pc->info.request.cc,
						      __status_callback, pc);
		if (ret < 0) {
			_LOGE("comm_client_set_status_callback() failed - %d",
			      ret);
			goto err;
		}
	} else if (pc->ctype == PC_BROADCAST) {
		pc->info.broadcast.bc = comm_status_broadcast_server_connect();
		if (pc->info.broadcast.bc == NULL) {
			_LOGE("client creation failed");
			goto err;
		}
		ret = 0;
	}

	return (pkgmgr_client *) pc;

 err:
	if (pc)
		free(pc);
	return NULL;
}

API int pkgmgr_client_free(pkgmgr_client *pc)
{
	int ret = -1;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	if (mpc == NULL) {
		_LOGE("Invalid argument");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype == PC_REQUEST) {
		req_cb_info *tmp;
		req_cb_info *prev;
		for (tmp = mpc->info.request.rhead; tmp;) {
			prev = tmp;
			tmp = tmp->next;
			free(prev);
		}

		ret = comm_client_free(mpc->info.request.cc);
		if (ret < 0) {
			_LOGE("comm_client_free() failed - %d", ret);
			goto err;
		}
	} else if (mpc->ctype == PC_LISTENING) {
		listen_cb_info *tmp;
		listen_cb_info *prev;
		for (tmp = mpc->info.listening.lhead; tmp;) {
			prev = tmp;
			tmp = tmp->next;
			free(prev);
		}

		ret = comm_client_free(mpc->info.listening.cc);
		if (ret < 0) {
			_LOGE("comm_client_free() failed - %d", ret);
			goto err;
		}
	} else if (mpc->ctype == PC_BROADCAST) {
		comm_status_broadcast_server_disconnect(mpc->info.broadcast.bc);
		ret = 0;
	} else {
		_LOGE("Invalid client type\n");
		return PKGMGR_R_EINVAL;
	}

	free(mpc);
	mpc = NULL;
	return PKGMGR_R_OK;

 err:
	if (mpc) {
		free(mpc);
		mpc = NULL;
	}
	return PKGMGR_R_ERROR;
}

static char *__get_req_key(const char *pkg_path)
{
	struct timeval tv;
	long curtime;
	char timestr[PKG_STRING_LEN_MAX];
	char *str_req_key;
	int size;

	gettimeofday(&tv, NULL);
	curtime = tv.tv_sec * 1000000 + tv.tv_usec;
	snprintf(timestr, sizeof(timestr), "%ld", curtime);

	size = strlen(pkg_path) + strlen(timestr) + 2;
	str_req_key = (char *)calloc(size, sizeof(char));
	if (str_req_key == NULL) {
		_LOGD("calloc failed");
		return NULL;
	}
	snprintf(str_req_key, size, "%s_%s", pkg_path, timestr);

	return str_req_key;
}

static char *__get_type_from_path(const char *pkg_path)
{
	int ret;
	char mimetype[255] = { '\0', };
	char extlist[256] = { '\0', };
	char *pkg_type;

	ret = aul_get_mime_from_file(pkg_path, mimetype, sizeof(mimetype));
	if (ret) {
		_LOGE("aul_get_mime_from_file() failed - error code[%d]\n",
		      ret);
		return NULL;
	}

	ret = aul_get_mime_extension(mimetype, extlist, sizeof(extlist));
	if (ret) {
		_LOGE("aul_get_mime_extension() failed - error code[%d]\n",
		      ret);
		return NULL;
	}

	if (strlen(extlist) == 0)
		return NULL;

	if (strchr(extlist, ',')) {
		extlist[strlen(extlist) - strlen(strchr(extlist, ','))] = '\0';
	}
	pkg_type = strchr(extlist, '.') + 1;
	return strdup(pkg_type);
}

API int pkgmgr_client_install(pkgmgr_client * pc, const char *pkg_type,
			      const char *descriptor_path, const char *pkg_path,
			      const char *optional_file, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data)
{
	char *pkgtype;
	char *installer_path;
	char *req_key;
	int req_id;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret;
	char *cookie = NULL;

	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_REQUEST)
		return PKGMGR_R_EINVAL;

	/* 1. check argument */
	if (descriptor_path) {
		if (strlen(descriptor_path) >= PKG_STRING_LEN_MAX)
			return PKGMGR_R_EINVAL;

		if (access(descriptor_path, F_OK) != 0)
			return PKGMGR_R_EINVAL;
	}

	if (pkg_path == NULL)
		return PKGMGR_R_EINVAL;
	else {
		if (strlen(pkg_path) >= PKG_STRING_LEN_MAX)
			return PKGMGR_R_EINVAL;

		if (access(pkg_path, F_OK) != 0)
			return PKGMGR_R_EINVAL;
	}

	if (optional_file) {
		if (strlen(optional_file) >= PKG_STRING_LEN_MAX)
			return PKGMGR_R_EINVAL;

		if (access(optional_file, F_OK) != 0)
			return PKGMGR_R_EINVAL;
	}

	/* 2. get installer path using pkg_path */
	if (pkg_type) {
		installer_path = _get_backend_path_with_type(pkg_type);
		pkgtype = strdup(pkg_type);
	} else {
		installer_path = _get_backend_path(pkg_path);
		pkgtype = __get_type_from_path(pkg_path);
	}

	if (installer_path == NULL) {
		free(pkgtype);
		return PKGMGR_R_EINVAL;
	}

	/* 3. generate req_key */
	req_key = __get_req_key(pkg_path);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, data);

	/* 5. generate argv */

	/*  argv[0] installer path */
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-i");
	/* argv[(4)] if exists */
	if (descriptor_path)
		argv[argcnt++] = strdup(descriptor_path);
	/* argv[4] */
	argv[argcnt++] = strdup(pkg_path);
	/* argv[5] -q option should be located at the end of command !! */
	if (mode == PM_QUIET)
		argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	if (args == NULL) {
		_LOGD("calloc failed");

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		free(pkgtype);
		return PKGMGR_R_ERROR;
	}
	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_INSTALLER, pkgtype, pkg_path,
				  args, cookie, 0);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);

		for (i = 0; i < argcnt; i++)
			free(argv[i]);
		free(args);
		free(pkgtype);
		return PKGMGR_R_ECOMM;
	}

	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	free(args);
	free(pkgtype);

	return req_id;
}

int __iterfunc(const aul_app_info *info, void *data)
{
	char pkgname[PKG_STRING_LEN_MAX];
	const char *pkg_name;

	pkg_name = (const char *)data;

	aul_app_get_pkgname_bypid(info->pid, pkgname, sizeof(pkgname));

	if (strncmp(pkg_name, pkgname, strlen(pkg_name)) == 0) {
		if (aul_terminate_pid(info->pid) < 0)
			kill(info->pid, SIGKILL);
	}

	return 0;
}

API int pkgmgr_client_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkg_name, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data)
{
	const char *pkgtype;
	char *installer_path;
	char *req_key;
	int req_id;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret;
	char *cookie = NULL;

	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_REQUEST)
		return PKGMGR_R_EINVAL;

	/* 1. check argument */
	if (pkg_name == NULL)
		return PKGMGR_R_EINVAL;

	if (aul_app_is_running(pkg_name)) {
		ret =
		    aul_app_get_running_app_info(__iterfunc, (void *)pkg_name);
		if (ret < 0)
			return PKGMGR_R_ERROR;
	}

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkg_name);
		if (pkgtype == NULL)
			return PKGMGR_R_EINVAL;
	} else
		pkgtype = pkg_type;

	if (strlen(pkg_name) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	/* 2. get installer path using pkg_path */
	installer_path = _get_backend_path_with_type(pkgtype);
	if (installer_path == NULL)
		return PKGMGR_R_EINVAL;

	/* 3. generate req_key */
	req_key = __get_req_key(pkg_name);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, data);

	/* 5. generate argv */

	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-d");
	/* argv[4] */
	argv[argcnt++] = strdup(pkg_name);
	/* argv[5] -q option should be located at the end of command !! */
	if (mode == PM_QUIET)
		argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	if (args == NULL) {
		_LOGD("calloc failed");

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		return PKGMGR_R_ERROR;
	}
	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_INSTALLER, pkgtype, pkg_name,
				  args, cookie, 0);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		free(args);
		return PKGMGR_R_ECOMM;
	}

	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	free(args);

	return req_id;
}

API int pkgmgr_client_activate(pkgmgr_client * pc, const char *pkg_type,
			       const char *pkg_name)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_REQUEST)
		return PKGMGR_R_EINVAL;

	/* 1. check argument */
	if (pkg_name == NULL)
		return PKGMGR_R_EINVAL;

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkg_name);
		if (pkgtype == NULL)
			return PKGMGR_R_EINVAL;
	} else
		pkgtype = pkg_type;

	if (strlen(pkg_name) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	/* 2. generate req_key */
	req_key = __get_req_key(pkg_name);

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_ACTIVATOR, pkgtype,
				  pkg_name, "1", cookie, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);
		free(req_key);
		return PKGMGR_R_ECOMM;
	}

	free(req_key);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkg_name)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_REQUEST)
		return PKGMGR_R_EINVAL;

	/* 1. check argument */
	if (pkg_name == NULL)
		return PKGMGR_R_EINVAL;

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkg_name);
		if (pkgtype == NULL)
			return PKGMGR_R_EINVAL;
	} else
		pkgtype = pkg_type;

	if (strlen(pkg_name) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	/* 2. generate req_key */
	req_key = __get_req_key(pkg_name);

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_ACTIVATOR, pkgtype,
				  pkg_name, "0", cookie, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);
		free(req_key);
		return PKGMGR_R_ECOMM;
	}

	free(req_key);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				      const char *pkg_name, pkgmgr_mode mode)
{
	const char *pkgtype;
	char *installer_path;
	char *req_key;
	int req_id;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret;
	char *cookie = NULL;

	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_REQUEST)
		return PKGMGR_R_EINVAL;

	/* 1. check argument */
	if (pkg_name == NULL)
		return PKGMGR_R_EINVAL;

/*
	if( aul_app_is_running(pkg_name) ) {
		ret = aul_app_get_running_app_info(__iterfunc, (void *) pkg_name);
		if(ret < 0)
			return PKGMGR_R_ERROR;
	}
*/

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkg_name);
		if (pkgtype == NULL)
			return PKGMGR_R_EINVAL;
	} else
		pkgtype = pkg_type;

	if (strlen(pkg_name) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	/* 2. get installer path using pkg_path */
	installer_path = _get_backend_path_with_type(pkgtype);
	if (installer_path == NULL)
		return PKGMGR_R_EINVAL;

	/* 3. generate req_key */
	req_key = __get_req_key(pkg_name);

	/* 4. generate argv */

	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-c");
	/* argv[4] */
	argv[argcnt++] = strdup(pkg_name);
	/* argv[5] -q option should be located at the end of command !! */
	if (mode == PM_QUIET)
		argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	if (args == NULL) {
		_LOGD("calloc failed");

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		return PKGMGR_R_ERROR;
	}
	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);
	/******************* end of quote ************************/

	/* 6. request clear */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_CLEARER, pkgtype, pkg_name,
				  args, cookie, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		free(args);
		return PKGMGR_R_ECOMM;
	}

	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	free(args);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_listen_status(pkgmgr_client *pc, pkgmgr_handler event_cb,
				    void *data)
{
	int req_id;
	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_LISTENING)
		return PKGMGR_R_EINVAL;

	/* 1. check argument */
	if (event_cb == NULL)
		return PKGMGR_R_EINVAL;

	/* 2. add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_stat_cbinfo(mpc, req_id, event_cb, data);

	return req_id;
}

API int pkgmgr_client_broadcast_status(pkgmgr_client *pc, const char *pkg_type,
				       const char *pkg_name, const char *key,
				       const char *val)
{
	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	/* Check for valid arguments. NULL parameter causes DBUS to abort */
	if (pkg_name == NULL || pkg_type == NULL || key == NULL || val == NULL) {
		_LOGD("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_BROADCAST)
		return PKGMGR_R_EINVAL;

	comm_status_broadcast_server_send_signal(mpc->info.broadcast.bc,
						 PKG_STATUS, pkg_type,
						 pkg_name, key, val);

	return PKGMGR_R_OK;
}

ail_cb_ret_e __appinfo_func(const ail_appinfo_h appinfo, void *user_data)
{
	char *type;
	char *package;
	char *version;

	iter_data *udata = (iter_data *) user_data;

	ail_appinfo_get_str(appinfo, AIL_PROP_X_SLP_PACKAGETYPE_STR, &type);
	if (type == NULL)
		type = "";
	ail_appinfo_get_str(appinfo, AIL_PROP_PACKAGE_STR, &package);
	if (package == NULL)
		package = "";
	ail_appinfo_get_str(appinfo, AIL_PROP_VERSION_STR, &version);
	if (version == NULL)
		version = "";

	if (udata->iter_fn(type, package, version, udata->data) != 0)
		return AIL_CB_RET_CANCEL;

	return AIL_CB_RET_CONTINUE;
}

API int pkgmgr_get_pkg_list(pkgmgr_iter_fn iter_fn, void *data)
{
	int cnt = -1;
	ail_filter_h filter;
	ail_error_e ret;

	if (iter_fn == NULL)
		return PKGMGR_R_EINVAL;

	ret = ail_filter_new(&filter);
	if (ret != AIL_ERROR_OK) {
		return PKGMGR_R_ERROR;
	}

	ret = ail_filter_add_str(filter, AIL_PROP_TYPE_STR, "Application");
	if (ret != AIL_ERROR_OK) {
		ail_filter_destroy(filter);
		return PKGMGR_R_ERROR;
	}

	ret = ail_filter_add_bool(filter, AIL_PROP_X_SLP_REMOVABLE_BOOL, true);
	if (ret != AIL_ERROR_OK) {
		ail_filter_destroy(filter);
		return PKGMGR_R_ERROR;
	}

	ret = ail_filter_count_appinfo(filter, &cnt);
	if (ret != AIL_ERROR_OK) {
		ail_filter_destroy(filter);
		return PKGMGR_R_ERROR;
	}

	iter_data *udata = calloc(1, sizeof(iter_data));
	if (udata == NULL) {
		_LOGE("calloc failed");
		ail_filter_destroy(filter);

		return PKGMGR_R_ERROR;
	}
	udata->iter_fn = iter_fn;
	udata->data = data;

	ail_filter_list_appinfo_foreach(filter, __appinfo_func, udata);

	free(udata);

	ret = ail_filter_destroy(filter);
	if (ret != AIL_ERROR_OK) {
		return PKGMGR_R_ERROR;
	}

	return PKGMGR_R_OK;
}

API pkgmgr_info *pkgmgr_info_new(const char *pkg_type, const char *pkg_name)
{
	const char *pkgtype;
	pkg_plugin_set *plugin_set = NULL;
	package_manager_pkg_detail_info_t *pkg_detail_info = NULL;

	/* 1. check argument */
	if (pkg_name == NULL)
		return NULL;

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkg_name);
		if (pkgtype == NULL)
			return NULL;
	} else
		pkgtype = pkg_type;

	if (strlen(pkg_name) >= PKG_STRING_LEN_MAX)
		return NULL;

	pkg_detail_info = calloc(1, sizeof(package_manager_pkg_detail_info_t));
	if (pkg_detail_info == NULL) {
		_LOGE("*** Failed to alloc package_handler_info.\n");
		return NULL;
	}

	plugin_set = _package_manager_load_library(pkgtype);
	if (plugin_set == NULL) {
		free(pkg_detail_info);
		return NULL;
	}

	if (plugin_set->pkg_is_installed) {
		if (plugin_set->pkg_is_installed(pkg_name) != 0) {
			free(pkg_detail_info);
			return NULL;
		}

		if (plugin_set->get_pkg_detail_info) {
			if (plugin_set->get_pkg_detail_info(pkg_name,
							    pkg_detail_info) != 0) {
				free(pkg_detail_info);
				return NULL;
			}
		}
	}

	return (pkgmgr_info *) pkg_detail_info;
}

API char * pkgmgr_info_get_string(pkgmgr_info * pkg_info, const char *key)
{
	package_manager_pkg_detail_info_t *pkg_detail_info;

	if (pkg_info == NULL)
		return NULL;
	if (key == NULL)
		return NULL;

	pkg_detail_info = (package_manager_pkg_detail_info_t *) pkg_info;

	return _get_info_string(key, pkg_detail_info);
}

API pkgmgr_info *pkgmgr_info_new_from_file(const char *pkg_type,
					   const char *pkg_path)
{
	pkg_plugin_set *plugin_set = NULL;
	package_manager_pkg_detail_info_t *pkg_detail_info = NULL;
	char *pkgtype;
	if (pkg_path == NULL) {
		_LOGE("pkg_path is NULL\n");
		return NULL;
	}

	if (strlen(pkg_path) > PKG_URL_STRING_LEN_MAX) {
		_LOGE("length of pkg_path is too long - %d.\n",
		      strlen(pkg_path));
		return NULL;
	}

	pkg_detail_info = calloc(1, sizeof(package_manager_pkg_detail_info_t));
	if (pkg_detail_info == NULL) {
		_LOGE("*** Failed to alloc package_handler_info.\n");
		return NULL;
	}

	if (pkg_type == NULL)
		pkgtype = __get_type_from_path(pkg_path);
	else
		pkgtype = strdup(pkg_type);

	plugin_set = _package_manager_load_library(pkgtype);
	if (plugin_set == NULL) {
		free(pkg_detail_info);
		free(pkgtype);
		return NULL;
	}

	if (plugin_set->get_pkg_detail_info_from_package) {
		if (plugin_set->get_pkg_detail_info_from_package(pkg_path,
								 pkg_detail_info) != 0) {
			free(pkg_detail_info);
			free(pkgtype);
			return NULL;
		}
	}

	free(pkgtype);
	return (pkgmgr_info *) pkg_detail_info;
}

API int pkgmgr_info_free(pkgmgr_info * pkg_info)
{
	if (pkg_info == NULL)
		return PKGMGR_R_EINVAL;

	free(pkg_info);
	pkg_info = NULL;

	return 0;
}
