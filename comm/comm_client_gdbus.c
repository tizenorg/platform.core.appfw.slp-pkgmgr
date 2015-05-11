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


/*
 * comm_client_gdbus.c
 * comm_client library using gdbus
 */

#include <glib.h>
#include <gio/gio.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <gio/gio.h>

#include "comm_config.h"
#include "comm_client.h"
#include "comm_pkg_mgr_client_gdbus_generated.h"
#include "comm_debug.h"

/*******************
 * ADT description
 */

/* Storing status_cb */
struct signal_callback_data {
	status_cb cb;
	void *cb_data;
};

/* comm_client ADT */
struct comm_client {
	guint subscription_id;
	GDBusConnection *conn;
	struct signal_callback_data *sig_cb_data;
};

#define COMM_CLIENT_RETRY_MAX 	5

static int __retry_request(comm_client *cc,
	const gchar *req_id,
	gint req_type,
	const gchar *pkg_type,
	const gchar *pkgid,
	const gchar *args,
	uid_t uid,
	gint *ret)
{	
	OrgTizenSlpPkgmgr *proxy;
	GError *error = NULL;
	int rc = 0;

	proxy = org_tizen_slp_pkgmgr_proxy_new_sync(cc->conn,
			G_DBUS_PROXY_FLAGS_NONE, COMM_PKG_MGR_DBUS_SERVICE,
			COMM_PKG_MGR_DBUS_PATH,
			NULL, &error);
	if (proxy == NULL) {
		ERR("Unable to create proxy[rc=%d, err=%s]\n", rc, error->message);
		return FALSE;
	}

	rc = org_tizen_slp_pkgmgr_call_request_sync(proxy,
			req_id, req_type, pkg_type, pkgid, args, uid, &ret, NULL, &error);
	if (!rc) {
		ERR("Failed to send request[rc=%d, err=%s]\n", rc, error->message);
		return FALSE;
	}
	return TRUE;
}

static const gchar *__get_interface(int status_type)
{
	char *ifc = NULL;

	switch (status_type) {
		case COMM_STATUS_BROADCAST_ALL:
			ifc = COMM_STATUS_BROADCAST_DBUS_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_INSTALL:
			ifc = COMM_STATUS_BROADCAST_DBUS_INSTALL_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_UNINSTALL:
			ifc = COMM_STATUS_BROADCAST_DBUS_UNINSTALL_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_MOVE:
			ifc = COMM_STATUS_BROADCAST_DBUS_MOVE_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_INSTALL_PROGRESS:
			ifc = COMM_STATUS_BROADCAST_DBUS_INSTALL_PROGRESS_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_UPGRADE:
			ifc = COMM_STATUS_BROADCAST_DBUS_UPGRADE_INTERFACE;
			break;

		default:
			break;
	}
	return ifc;
}

/**
 * signal handler filter
 * Filter signal, and run user callback
 */
void _on_signal_handle_filter(GDBusConnection *conn,
		const gchar *sender_name,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *signal_name,
		GVariant *parameters,
		gpointer user_data)
{
	if (interface_name && strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_INSTALL_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_UNINSTALL_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_UPGRADE_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_MOVE_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_INSTALL_PROGRESS_INTERFACE)) {
		DBG("Interface name did not match. Drop the message");
		return;
	}
	if (signal_name && strcmp(signal_name, COMM_STATUS_BROADCAST_SIGNAL_STATUS) &&
		strcmp(signal_name, COMM_STATUS_BROADCAST_EVENT_INSTALL) &&
		strcmp(signal_name, COMM_STATUS_BROADCAST_EVENT_UNINSTALL) &&
		strcmp(signal_name, COMM_STATUS_BROADCAST_EVENT_UPGRADE) &&
		strcmp(signal_name, COMM_STATUS_BROADCAST_EVENT_MOVE) &&
		strcmp(signal_name, COMM_STATUS_BROADCAST_EVENT_INSTALL_PROGRESS)) {
		DBG("Signal name did not match. Drop the message");
		return;
	}
	/* Values to be received by signal */
	uid_t target_uid;
	char *req_id = NULL;
	char *pkg_type = NULL;
	char *pkgid = NULL;
	char *key = NULL;
	char *val = NULL;

	/* User's signal handler */
	struct signal_callback_data *sig_cb_data;
	if (user_data)
		sig_cb_data = (struct signal_callback_data *)user_data;
	else
		return;

	g_variant_get(parameters, "(u&s&s&s&s&s)",
				&target_uid, &req_id, &pkg_type, &pkgid, &key, &val);
	/* Got signal! */
	SECURE_LOGD("Got signal: [%s] %u / %s / %s / %s / %s / %s", signal_name, target_uid, req_id,
	    pkg_type, pkgid, key, val);

	/* Run signal callback if exist */
	if (sig_cb_data && sig_cb_data->cb) {
		sig_cb_data->cb(sig_cb_data->cb_data, target_uid, req_id,
				pkg_type, pkgid, key, val);
		DBG("callback function is end");
	}
	DBG("Handled signal. Exit function");
	return;
}

/**
 * signal_callback_data free function
 * Just free it!
 */
void _free_sig_cb_data(void *data)
{
	struct signal_callback_data *sig_cb_data = NULL;
	sig_cb_data = (struct signal_callback_data *)data;
	free(sig_cb_data);
}

/*******************
 * API description
 */

/**
 * Create a new comm_client object
 */
comm_client *comm_client_new(void)
{
	GError *error = NULL;
	comm_client *cc = NULL;

	/* Allocate memory for ADT:comm_client */
	g_type_init();
	cc = calloc(1, sizeof(comm_client));
	if (NULL == cc) {
		ERR("No memory");
		return NULL;
	}

	/* Connect to gdbus. Gets shared BUS */
	cc->conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (error) {
		ERR("gdbus connection error (%s)", error->message);
		g_error_free(error);
		goto ERROR_CLEANUP;
	}
	if (NULL == cc->conn) {
		ERR("gdbus connection is not set, even gdbus error isn't raised");
		goto ERROR_CLEANUP;
	}
	return cc;

 ERROR_CLEANUP:
	if (cc)
		free(cc);
	return NULL;
}

/**
 * Free comm_client object
 */
int comm_client_free(comm_client *cc)
{
	if (!cc)
		return -1;
	if (!(cc->conn) || g_dbus_connection_is_closed(cc->conn)) {
		ERR("Invalid gdbus connection");
		return -2;
	}

	if (cc->sig_cb_data) {
		g_dbus_connection_signal_unsubscribe(cc->conn, cc->subscription_id);
		/* TODO: Is it needed to free cc->sig_cb_data here? */
		/* _free_sig_cb_data(cc->sig_cb_data); */
	}

	/* Cleanup ADT */
	/* flush remaining buffer: blocking mode */
	g_dbus_connection_flush_sync(cc->conn, NULL, NULL);

	/* Free signal filter if signal callback is exist */

	/* just unref because it is shared BUS.
	If ref count is 0 it will get free'd automatically
	*/
	g_object_unref(cc->conn);
	free(cc);

	return 0;
}

/**
 * Request a message
 */
int
comm_client_request(
		comm_client *cc,
		const char *req_id,
		const int req_type,
		const char *pkg_type,
		const char *pkgid,
		const char *args,
		uid_t uid,
		int is_block)
{
	GError *error = NULL;
	int rc = 0;
	int ret = 0;
	int retry_cnt = 0;

	OrgTizenSlpPkgmgr *proxy;
	if (!cc){
		ERR("Invalid gdbus input");
		return COMM_RET_ERROR;
	}
	proxy = org_tizen_slp_pkgmgr_proxy_new_sync(cc->conn,
			G_DBUS_PROXY_FLAGS_NONE, COMM_PKG_MGR_DBUS_SERVICE,
			COMM_PKG_MGR_DBUS_PATH,
			NULL, &error);
	if (proxy == NULL) {
		ERR("Unable to create proxy[rc=%d, err=%s]\n", rc, error->message);
		return COMM_RET_ERROR;
	}

	/* Assign default values if NULL (NULL is not allowed) */
	if (req_id == NULL)
		req_id = "tmp_reqid";
	if (pkg_type == NULL)
		pkg_type = "none";
	if (pkgid == NULL)
		pkgid = "";
	if (args == NULL)
		args = "";

	rc = org_tizen_slp_pkgmgr_call_request_sync(proxy,
			req_id, req_type, pkg_type, pkgid, args, uid, &ret, NULL, &error);

	while ((rc == FALSE) && (retry_cnt < COMM_CLIENT_RETRY_MAX)) {
		ERR("Failed to send request, sleep and retry[rc=%d, err=%s]\n", rc, error->message);
		sleep(1);

		retry_cnt++;

		rc = __retry_request(cc, req_id, req_type, pkg_type, pkgid, args, uid, &ret);
		if(rc == TRUE) {
			ERR("__retry_request is success[retry_cnt=%d]\n", retry_cnt);
		}
	}
	
	return rc == TRUE ? COMM_RET_OK : COMM_RET_ERROR;
}

/**
 * Set a callback for status signal
 */
int
comm_client_set_status_callback(int comm_status_type, comm_client *cc, status_cb cb, void *cb_data)
{
	int r = COMM_RET_ERROR;
	char *ifc = NULL;

	if (NULL == cc)
		return NULL;

	ifc = __get_interface(comm_status_type);
	if (ifc == NULL) {
		ERR("Invalid interface name\n");
		return COMM_RET_ERROR;
	}

	/* Create new sig_cb_data */
	cc->sig_cb_data = calloc(1, sizeof(struct signal_callback_data));
	if ( cc->sig_cb_data ) {
		(cc->sig_cb_data)->cb = cb;
		(cc->sig_cb_data)->cb_data = cb_data;
	} else {
		r = COMM_RET_ERROR;
		goto ERROR_CLEANUP;
	}
	/* Add a filter for signal */
	cc->subscription_id = g_dbus_connection_signal_subscribe(cc->conn, NULL, ifc,
		NULL, NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
		_on_signal_handle_filter, (gpointer)cc->sig_cb_data, _free_sig_cb_data);
	if (!cc->subscription_id) {
		ERR("Failed to add filter\n");
		r = COMM_RET_ERROR;
		goto ERROR_CLEANUP;
	}

	return COMM_RET_OK;

 ERROR_CLEANUP:
	ERR("General error");
	return r;
}

