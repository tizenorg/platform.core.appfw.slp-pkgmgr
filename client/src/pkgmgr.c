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
#include <vconf.h>
#include <db-util.h>

#include "package-manager.h"
#include "pkgmgr-internal.h"
#include "pkgmgr-info.h"
#include "pkgmgr-api.h"
#include "comm_client.h"
#include "pkgmgr_parser.h"
#include "comm_status_broadcast_server.h"

#define MANIFEST_DB		"/opt/dbspace/.pkgmgr_parser.db"
#define MAX_QUERY_LEN	4096

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

typedef struct _pkgmgr_pkginfo_x {
	int pkg_handle_id;
	manifest_x *manifest_info;
} pkgmgr_pkginfo_x;

typedef struct _pkgmgr_appinfo_x {
	int app_handle_id;
	char *app_component;
	uiapplication_x *uiapp_info;
	serviceapplication_x *svcapp_info;
} pkgmgr_appinfo_x;

char *pkgtype = "rpm";
sqlite3 *manifest_db = NULL;

static int __open_manifest_db();
static int __exec_pkginfo_query(char *query, void *data);
static int __exec_appinfo_query(char *query, void *data);
static int __pkginfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __appinfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __validate_cb(void *data, int ncols, char **coltxt, char **colname);
static int __uiapp_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __svcapp_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __pkg_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __pkgmgr_appinfo_new_handle_id();
static int __pkgmgr_pkginfo_new_handle_id();
static void __cleanup_pkginfo(pkgmgr_pkginfo_x *data);
static void __cleanup_appinfo(pkgmgr_appinfo_x *data);
static char* __convert_system_locale_to_manifest_locale(char *syslocale);

static int __pkgmgr_pkginfo_new_handle_id()
{
	static int pkginfo_handle_id = 0;
	return pkginfo_handle_id++;
}

static int __pkgmgr_appinfo_new_handle_id()
{
	static int appinfo_handle_id = 0;
	return appinfo_handle_id++;
}

static char* __convert_system_locale_to_manifest_locale(char *syslocale)
{
	if (syslocale == NULL)
		return strdup(DEFAULT_LOCALE);
	char *locale = NULL;
	locale = (char *)calloc(1, 6);
	if (!locale) {
		_LOGE("Malloc Failed\n");
		return NULL;
	}
	strncpy(locale, syslocale, 2);
	strncat(locale, "-", 1);
	locale[3] = syslocale[3] + 32;
	locale[4] = syslocale[4] + 32;
	return locale;
}

static void __cleanup_pkginfo(pkgmgr_pkginfo_x *data)
{
	if (data == NULL)
		return;
	pkgmgr_parser_free_manifest_xml(data->manifest_info);
	free((void *)data);
	data = NULL;
	return;
}

static void __cleanup_appinfo(pkgmgr_appinfo_x *data)
{
	if (data == NULL)
		return;
	if (data->app_component) {
		free((void *)data->app_component);
		data->app_component = NULL;
	}
	manifest_x *mfx = calloc(1, sizeof(manifest_x));
	mfx->uiapplication = data->uiapp_info;
	mfx->serviceapplication = data->svcapp_info;
	pkgmgr_parser_free_manifest_xml(mfx);
	free((void *)data);
	data = NULL;
	return;
}

static int __open_manifest_db()
{
	int ret = -1;
	if (access(MANIFEST_DB, F_OK) == 0) {
		ret =
		    db_util_open_with_options(MANIFEST_DB, &manifest_db,
				 SQLITE_OPEN_READONLY, NULL);
		if (ret != SQLITE_OK) {
			_LOGE("connect db [%s] failed!\n", MANIFEST_DB);
			return -1;
		}
		return 0;
	}
	_LOGE("Manifest DB does not exists !!\n");
	return -1;
}

static int __pkg_list_cb(void *data, int ncols, char **coltxt, char **colname)
{
	char *pkg_name = NULL;
	char *pkg_type = NULL;
	char *pkg_version = NULL;
	int i = 0;
	iter_data *udata = (iter_data *)data;
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "package") == 0) {
			if (coltxt[i])
				pkg_name = strdup(coltxt[i]);
		} else if (strcmp(colname[i], "package_type") == 0) {
			if (coltxt[i])
				pkg_type = strdup(coltxt[i]);
		} else if (strcmp(colname[i], "package_version") == 0 ){
			if (coltxt[i])
				pkg_version = strdup(coltxt[i]);
		} else
			continue;
	}
	udata->iter_fn(pkg_type, pkg_name, pkg_version, udata->data);
	if (pkg_name) {
		free(pkg_name);
		pkg_name = NULL;
	}
	if (pkg_type) {
		free(pkg_type);
		pkg_type = NULL;
	}
	if (pkg_version) {
		free(pkg_version);
		pkg_version = NULL;
	}
	return 0;
}

static int __uiapp_list_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	uiapplication_x *uiapp = NULL;
	uiapp = calloc(1, sizeof(uiapplication_x));
	LISTADD(info->manifest_info->uiapplication, uiapp);
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_id") == 0) {
			if (coltxt[i])
				info->manifest_info->uiapplication->appid = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->appid = NULL;
		} else if (strcmp(colname[i], "app_exec") == 0) {
			if (coltxt[i])
				info->manifest_info->uiapplication->exec = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->exec = NULL;
		} else if (strcmp(colname[i], "app_type") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->type = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->type = NULL;
		} else if (strcmp(colname[i], "app_nodisplay") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->nodisplay = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->nodisplay = NULL;
		} else if (strcmp(colname[i], "app_multiple") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->multiple = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->multiple = NULL;
		} else if (strcmp(colname[i], "app_taskmanage") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->taskmanage = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->taskmanage = NULL;
		} else
			continue;
	}
	return 0;
}

static int __svcapp_list_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	serviceapplication_x *svcapp = NULL;
	svcapp = calloc(1, sizeof(serviceapplication_x));
	LISTADD(info->manifest_info->serviceapplication, svcapp);
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_id") == 0) {
			if (coltxt[i])
				info->manifest_info->serviceapplication->appid = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->appid = NULL;
		} else if (strcmp(colname[i], "app_exec") == 0) {
			if (coltxt[i])
				info->manifest_info->serviceapplication->exec = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->exec = NULL;
		} else if (strcmp(colname[i], "app_type") == 0 ){
			if (coltxt[i])
				info->manifest_info->serviceapplication->type = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->type = NULL;
		} else if (strcmp(colname[i], "app_onboot") == 0 ){
			if (coltxt[i])
				info->manifest_info->serviceapplication->onboot = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->onboot = NULL;
		} else if (strcmp(colname[i], "app_autorestart") == 0 ){
			if (coltxt[i])
				info->manifest_info->serviceapplication->autorestart = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->autorestart = NULL;
		} else
			continue;
	}
	return 0;
}

static int __validate_cb(void *data, int ncols, char **coltxt, char **colname)
{
	int *p = (int*)data;
	*p = atoi(coltxt[0]);
	_LOGE("exist value is %d\n", *p);
	return 0;
}

static int __pkginfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	author_x *author = NULL;
	icon_x *icon = NULL;
	label_x *label = NULL;
	description_x *description = NULL;

	author = calloc(1, sizeof(author_x));
	LISTADD(info->manifest_info->author, author);
	icon = calloc(1, sizeof(icon_x));
	LISTADD(info->manifest_info->icon, icon);
	label = calloc(1, sizeof(label_x));
	LISTADD(info->manifest_info->label, label);
	description = calloc(1, sizeof(description_x));
	LISTADD(info->manifest_info->description, description);
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "package_version") == 0) {
			if (coltxt[i])
				info->manifest_info->version = strdup(coltxt[i]);
			else
				info->manifest_info->version = NULL;
		} else if (strcmp(colname[i], "package_type") == 0) {
			if (coltxt[i])
				info->manifest_info->type = strdup(coltxt[i]);
			else
				info->manifest_info->type = NULL;
		} else if (strcmp(colname[i], "install_location") == 0) {
			if (coltxt[i])
				info->manifest_info->installlocation = strdup(coltxt[i]);
			else
				info->manifest_info->installlocation = NULL;
		} else if (strcmp(colname[i], "author_email") == 0 ){
			if (coltxt[i])
				info->manifest_info->author->email = strdup(coltxt[i]);
			else
				info->manifest_info->author->email = NULL;
		} else if (strcmp(colname[i], "author_href") == 0 ){
			if (coltxt[i])
				info->manifest_info->author->href = strdup(coltxt[i]);
			else
				info->manifest_info->author->href = NULL;
		} else if (strcmp(colname[i], "package_label") == 0 ){
			if (coltxt[i])
				info->manifest_info->label->text = strdup(coltxt[i]);
			else
				info->manifest_info->label->text = NULL;
		} else if (strcmp(colname[i], "package_icon") == 0 ){
			if (coltxt[i])
				info->manifest_info->icon->name = strdup(coltxt[i]);
			else
				info->manifest_info->icon->name = NULL;
		} else if (strcmp(colname[i], "package_description") == 0 ){
			if (coltxt[i])
				info->manifest_info->description->text = strdup(coltxt[i]);
			else
				info->manifest_info->description->text = NULL;
		} else if (strcmp(colname[i], "package_author") == 0 ){
			if (coltxt[i])
				info->manifest_info->author->text = strdup(coltxt[i]);
			else
				info->manifest_info->author->text = NULL;
		} else if (strcmp(colname[i], "package_removable") == 0 ){
			if (coltxt[i])
				info->manifest_info->removable = strdup(coltxt[i]);
			else
				info->manifest_info->removable = NULL;
		} else if (strcmp(colname[i], "package_preload") == 0 ){
			if (coltxt[i])
				info->manifest_info->preload = strdup(coltxt[i]);
			else
				info->manifest_info->preload = NULL;
		} else if (strcmp(colname[i], "package_readonly") == 0 ){
			if (coltxt[i])
				info->manifest_info->readonly = strdup(coltxt[i]);
			else
				info->manifest_info->readonly = NULL;
		} else if (strcmp(colname[i], "package_locale") == 0 ){
			if (coltxt[i]) {
				info->manifest_info->author->lang = strdup(coltxt[i]);
				info->manifest_info->icon->lang = strdup(coltxt[i]);
				info->manifest_info->label->lang = strdup(coltxt[i]);
				info->manifest_info->description->lang = strdup(coltxt[i]);
			}
			else {
				info->manifest_info->author->lang = NULL;
				info->manifest_info->icon->lang = NULL;
				info->manifest_info->label->lang = NULL;
				info->manifest_info->description->lang = NULL;
			}
		} else
			continue;
	}
	return 0;
}

static int __appinfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)data;
	int i = 0;
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_exec") == 0) {
			if (coltxt[i])
				info->uiapp_info->exec = strdup(coltxt[i]);
			else
				info->uiapp_info->exec = NULL;
		} else if (strcmp(colname[i], "app_component") == 0) {
			if (coltxt[i])
				info->app_component = strdup(coltxt[i]);
			else
				info->app_component = NULL;
		} else if (strcmp(colname[i], "app_nodisplay") == 0) {
			if (coltxt[i])
				info->uiapp_info->nodisplay = strdup(coltxt[i]);
			else
				info->uiapp_info->nodisplay = NULL;
		} else if (strcmp(colname[i], "app_type") == 0 ){
			if (coltxt[i])
				info->uiapp_info->type = strdup(coltxt[i]);
			else
				info->uiapp_info->type = NULL;
		} else if (strcmp(colname[i], "app_multiple") == 0 ){
			if (coltxt[i])
				info->uiapp_info->multiple = strdup(coltxt[i]);
			else
				info->uiapp_info->multiple = NULL;
		} else if (strcmp(colname[i], "app_onboot") == 0 ){
			if (coltxt[i])
				info->svcapp_info->onboot = strdup(coltxt[i]);
			else
				info->svcapp_info->onboot = NULL;
		} else if (strcmp(colname[i], "app_autorestart") == 0 ){
			if (coltxt[i])
				info->svcapp_info->autorestart = strdup(coltxt[i]);
			else
				info->svcapp_info->autorestart = NULL;
		} else if (strcmp(colname[i], "app_taskmanage") == 0 ){
			if (coltxt[i])
				info->uiapp_info->taskmanage = strdup(coltxt[i]);
			else
				info->uiapp_info->taskmanage = NULL;
		} else
			continue;
	}
	return 0;
}

static int __exec_pkginfo_query(char *query, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __pkginfo_cb, data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __exec_appinfo_query(char *query, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __appinfo_cb, data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

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
				  args, cookie, 1);
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
		_LOGE("*** Failed to load library");
		free(pkg_detail_info);
		return NULL;
	}

	if (plugin_set->pkg_is_installed) {
		if (plugin_set->pkg_is_installed(pkg_name) != 0) {
			_LOGE("*** Failed to call pkg_is_installed()");
			free(pkg_detail_info);
			return NULL;
		}

		if (plugin_set->get_pkg_detail_info) {
			if (plugin_set->get_pkg_detail_info(pkg_name,
							    pkg_detail_info) != 0) {
				_LOGE("*** Failed to call get_pkg_detail_info()");
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

API int pkgmgr_get_pkginfo_type(pkgmgr_pkginfo_h handle, char **type)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (type == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->type)
		*type = info->manifest_info->type;
	else
		*type = pkgtype;
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_version(pkgmgr_pkginfo_h handle, char **version)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (version == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*version = (char *)info->manifest_info->version;
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_install_location(pkgmgr_pkginfo_h handle, pkgmgr_install_location *location)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (location == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->installlocation;
	if (val) {
		if (strcmp(val, "internal-only") == 0)
			*location = 0;
		else if (strcmp(val, "prefer-external") == 0)
			*location = 1;
		else
			*location = 1;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_icon(pkgmgr_pkginfo_h handle, char **icon)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (icon == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *save = NULL;
	icon_x *ptr = NULL;
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	save = locale;
	*icon = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	for(ptr = info->manifest_info->icon; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*icon = (char *)ptr->name;
				if (strcmp(*icon, "(null)") == 0) {
					locale = DEFAULT_LOCALE;
					continue;
				} else
					break;
			} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
				*icon = (char *)ptr->text;
				break;
			}
		}
	}
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	locale = save;
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_label(pkgmgr_pkginfo_h handle, char **label)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (label == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *save = NULL;
	label_x *ptr = NULL;
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	save = locale;
	*label = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	for(ptr = info->manifest_info->label; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*label = (char *)ptr->text;
				if (strcmp(*label, "(null)") == 0) {
					locale = DEFAULT_LOCALE;
					continue;
				} else
					break;
			} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
				*label = (char *)ptr->text;
				break;
			}
		}
	}
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	locale = save;
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_description(pkgmgr_pkginfo_h handle, char **description)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (description == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *save = NULL;
	description_x *ptr = NULL;
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	save = locale;
	*description = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	for(ptr = info->manifest_info->description; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*description = (char *)ptr->text;
				if (strcmp(*description, "(null)") == 0) {
					locale = DEFAULT_LOCALE;
					continue;
				} else
					break;
			} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
				*description = (char *)ptr->text;
				break;
			}
		}
	}
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	locale = save;
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_author_name(pkgmgr_pkginfo_h handle, char **author_name)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (author_name == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *save = NULL;
	author_x *ptr = NULL;
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	save = locale;
	*author_name = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	for(ptr = info->manifest_info->author; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*author_name = (char *)ptr->text;
				if (strcmp(*author_name, "(null)") == 0) {
					locale = DEFAULT_LOCALE;
					continue;
				} else
					break;
			} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
				*author_name = (char *)ptr->text;
				break;
			}
		}
	}
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	locale = save;
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_author_email(pkgmgr_pkginfo_h handle, char **author_email)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (author_email == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*author_email = (char *)info->manifest_info->author->email;
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_author_href(pkgmgr_pkginfo_h handle, char **author_href)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (author_href == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*author_href = (char *)info->manifest_info->author->href;
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_removable(pkgmgr_pkginfo_h handle, bool *removable)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (removable == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->removable;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*removable = 1;
		else if (strcasecmp(val, "false") == 0)
			*removable = 0;
		else
			*removable = 1;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_preload(pkgmgr_pkginfo_h handle, bool *preload)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (preload == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->preload;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*preload = 1;
		else if (strcasecmp(val, "false") == 0)
			*preload = 0;
		else
			*preload = 0;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_readonly(pkgmgr_pkginfo_h handle, bool *readonly)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (readonly == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->readonly;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*readonly = 1;
		else if (strcasecmp(val, "false") == 0)
			*readonly = 0;
		else
			*readonly = 0;
	}
	return PKGMGR_R_OK;
}


API int pkgmgr_get_pkginfo_exec(pkgmgr_appinfo_h  handle, char **exec)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (exec == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	if (info->app_component) {
		if (strcasecmp(info->app_component, "uiapp") == 0)
			*exec = (char *)info->uiapp_info->exec;
		if (strcasecmp(info->app_component, "svcapp") == 0)
			*exec = (char *)info->svcapp_info->exec;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_component(pkgmgr_appinfo_h  handle, char **component)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (component == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	*component = (char *)info->app_component;
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_apptype(pkgmgr_appinfo_h  handle, char **app_type)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (app_type == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	if (info->app_component) {
		if (strcasecmp(info->app_component, "uiapp") == 0)
			*app_type = (char *)info->uiapp_info->type;
		if (strcasecmp(info->app_component, "svcapp") == 0)
			*app_type = (char *)info->svcapp_info->type;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_nodisplay(pkgmgr_appinfo_h  handle, bool *nodisplay)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (nodisplay == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->uiapp_info->nodisplay;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*nodisplay = 1;
		else if (strcasecmp(val, "false") == 0)
			*nodisplay = 0;
		else
			*nodisplay = 0;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_multiple(pkgmgr_appinfo_h  handle, bool *multiple)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (multiple == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->uiapp_info->multiple;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*multiple = 1;
		else if (strcasecmp(val, "false") == 0)
			*multiple = 0;
		else
			*multiple = 0;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_onboot(pkgmgr_appinfo_h  handle, bool *onboot)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (onboot == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->svcapp_info->onboot;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*onboot = 1;
		else if (strcasecmp(val, "false") == 0)
			*onboot = 0;
		else
			*onboot = 0;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_autorestart(pkgmgr_appinfo_h  handle, bool *autorestart)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (autorestart == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->svcapp_info->autorestart;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*autorestart = 1;
		else if (strcasecmp(val, "false") == 0)
			*autorestart = 0;
		else
			*autorestart = 0;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo_taskmanage(pkgmgr_appinfo_h  handle, bool *taskmanage)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (taskmanage == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->uiapp_info->taskmanage;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*taskmanage = 1;
		else if (strcasecmp(val, "false") == 0)
			*taskmanage = 0;
		else
			*taskmanage = 0;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_get_pkginfo(const char *pkg_name, pkgmgr_pkginfo_h *handle)
{
	if (pkg_name == NULL) {
		_LOGE("package name is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (handle == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_pkginfo_x *pkginfo = NULL;
	char *error_message = NULL;
	int ret = PKGMGR_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *syslocale = NULL;
	char *locale = NULL;
	int exist = 0;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	author_x *tmp4 = NULL;

	/*validate pkgname*/
	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_info where package='%s')", pkg_name);
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		return PKGMGR_R_ERROR;
	}
	if (exist == 0) {
		_LOGE("Package not found in DB\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}

	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		ret = PKGMGR_R_EINVAL;
		goto err;
	}
	pkginfo = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	if (pkginfo == NULL) {
		_LOGE("Failed to allocate memory for pkginfo\n");
		return PKGMGR_R_ERROR;
	}
	pkginfo->pkg_handle_id = __pkgmgr_pkginfo_new_handle_id();
	pkginfo->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	if (pkginfo->manifest_info == NULL) {
		_LOGE("Failed to allocate memory for manifest info\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}
	pkginfo->manifest_info->package = strdup(pkg_name);
	/*populate manifest_info from DB*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_info where package='%s' ", pkg_name);
	ret = __exec_pkginfo_query(query, (void *)pkginfo);
	if (ret == -1) {
		_LOGE("Package Info DB Information retrieval failed\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
		" package='%s' and package_locale='%s'", pkg_name, locale);
	ret = __exec_pkginfo_query(query, (void *)pkginfo);
	if (ret == -1) {
		_LOGE("Package Info DB Information retrieval failed\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}
	/*Also store the values corresponding to default locales*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
		" package='%s' and package_locale='%s'", pkg_name, DEFAULT_LOCALE);
	ret = __exec_pkginfo_query(query, (void *)pkginfo);
	if (ret == -1) {
		_LOGE("Package Info DB Information retrieval failed\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}
	if (pkginfo->manifest_info->label) {
		LISTHEAD(pkginfo->manifest_info->label, tmp1);
		pkginfo->manifest_info->label = tmp1;
	}
	if (pkginfo->manifest_info->icon) {
		LISTHEAD(pkginfo->manifest_info->icon, tmp2);
		pkginfo->manifest_info->icon = tmp2;
	}
	if (pkginfo->manifest_info->description) {
		LISTHEAD(pkginfo->manifest_info->description, tmp3);
		pkginfo->manifest_info->description = tmp3;
	}
	if (pkginfo->manifest_info->author) {
		LISTHEAD(pkginfo->manifest_info->author, tmp4);
		pkginfo->manifest_info->author = tmp4;
	}
	*handle = (void *)pkginfo;
	sqlite3_close(manifest_db);
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PKGMGR_R_OK;

err:
	*handle = NULL;
	__cleanup_pkginfo(pkginfo);
	sqlite3_close(manifest_db);
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return ret;
}

API int pkgmgr_get_info_list(pkgmgr_iter_fn iter_fn, void *user_data)
{
	if (iter_fn == NULL) {
		_LOGE("callback function is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	char *error_message = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};

	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		return PKGMGR_R_ERROR;
	}
	iter_data *udata = calloc(1, sizeof(iter_data));
	if (udata == NULL) {
		_LOGE("calloc failed");
		sqlite3_close(manifest_db);
		return PKGMGR_R_ERROR;
	}
	udata->iter_fn = iter_fn;
	udata->data = user_data;
	snprintf(query, MAX_QUERY_LEN, "select * from package_info");
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __pkg_list_cb, (void *)udata, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		return PKGMGR_R_ERROR;
	}
	sqlite3_close(manifest_db);
	return PKGMGR_R_OK;
}

API int pkgmgr_get_info_app(pkgmgr_pkginfo_h handle, pkgmgr_app_component component,
								pkgmgr_info_app_list_cb app_func, void *user_data)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (app_func == NULL) {
		_LOGE("callback pointer is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (component != PM_UI_APP && component != PM_SVC_APP) {
		_LOGE("Invalid App Component Type\n");
		return PKGMGR_R_EINVAL;
	}
	char *error_message = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	pkgmgr_appinfo_x *appinfo = NULL;

	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	if (appinfo == NULL) {
		_LOGE("Failed to allocate memory for appinfo\n");
		return PKGMGR_R_ERROR;
	}
	if (component == PM_UI_APP)
		appinfo->app_component = strdup("uiapp");
	if (component == PM_SVC_APP)
		appinfo->app_component = strdup("svcapp");
	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		return PKGMGR_R_ERROR;
	}
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where package='%s' and app_component='%s'", info->manifest_info->package, appinfo->app_component);
	switch(component) {
	case PM_UI_APP:
		if (SQLITE_OK !=
		sqlite3_exec(manifest_db, query, __uiapp_list_cb, (void *)info, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		return PKGMGR_R_ERROR;
		}
		uiapplication_x *tmp = NULL;
		if (info->manifest_info->uiapplication) {
			LISTHEAD(info->manifest_info->uiapplication, tmp);
			info->manifest_info->uiapplication = tmp;
		}
		/*If the callback func return < 0 we break and no more call back is called*/
		while(tmp != NULL)
		{
			appinfo->uiapp_info = tmp;
			ret = app_func((void *)appinfo, tmp->appid, user_data);
			if (ret < 0)
				break;
			tmp = tmp->next;
		}
		break;
	case PM_SVC_APP:
		if (SQLITE_OK !=
		sqlite3_exec(manifest_db, query, __svcapp_list_cb, (void *)info, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		return PKGMGR_R_ERROR;
		}
		serviceapplication_x *tmp1 = NULL;
		if (info->manifest_info->serviceapplication) {
			LISTHEAD(info->manifest_info->serviceapplication, tmp1);
			info->manifest_info->serviceapplication = tmp1;
		}
		/*If the callback func return < 0 we break and no more call back is called*/
		while(tmp1 != NULL)
		{
			appinfo->svcapp_info = tmp1;
			ret = app_func((void *)appinfo, tmp1->appid, user_data);
			if (ret < 0)
				break;
			tmp1 = tmp1->next;
		}
		break;
	default:
		_LOGE("Invalid App Component Type\n");
		break;
	}

	if (appinfo->app_component) {
		free(appinfo->app_component);
		appinfo->app_component = NULL;
	}
	if (appinfo) {
		free(appinfo);
		appinfo = NULL;
	}
	sqlite3_close(manifest_db);
	return PKGMGR_R_OK;
}

API int pkgmgr_destroy_pkginfo(pkgmgr_pkginfo_h handle)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	__cleanup_pkginfo(info);
	return PKGMGR_R_OK;
}

API int pkgmgr_get_appinfo(const char *appid, pkgmgr_appinfo_h *handle)
{
	if (appid == NULL) {
		_LOGE("appid is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (handle == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_appinfo_x *appinfo = NULL;
	char *error_message = NULL;
	int ret = -1;
	int exist = 0;
	char query[MAX_QUERY_LEN] = {'\0'};

	/*Validate appid*/
	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", appid);
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		return PKGMGR_R_ERROR;
	}
	if (exist == 0) {
		_LOGE("Appid not found in DB\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}

	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	if (appinfo == NULL) {
		_LOGE("Failed to allocate memory for appinfo\n");
		return PKGMGR_R_ERROR;
	}
	appinfo->app_handle_id = __pkgmgr_appinfo_new_handle_id();
	appinfo->uiapp_info = (uiapplication_x *)calloc(1, sizeof(uiapplication_x));
	if (appinfo->uiapp_info == NULL) {
		_LOGE("Failed to allocate memory for uiapp info\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}

	appinfo->svcapp_info = (serviceapplication_x *)calloc(1, sizeof(serviceapplication_x));
	if (appinfo->svcapp_info == NULL) {
		_LOGE("Failed to allocate memory for svcapp info\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}

	/*populate uiapp_info from DB*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' ", appid);
	ret = __exec_appinfo_query(query, (void *)appinfo);
	if (ret == -1) {
		_LOGE("App Info DB Information retrieval failed\n");
		ret = PKGMGR_R_ERROR;
		goto err;
	}

	*handle = (void*)appinfo;
	sqlite3_close(manifest_db);
	return PKGMGR_R_OK;
err:
	*handle = NULL;
	__cleanup_appinfo(appinfo);
	sqlite3_close(manifest_db);
	return ret;
}

API int pkgmgr_destroy_appinfo(pkgmgr_appinfo_h  handle)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	__cleanup_appinfo(info);
	return PKGMGR_R_OK;
}
