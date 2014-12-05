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





#include "comm_config.h"
#include "comm_client.h"
#include "comm_pkg_mgr_client_dbus_bindings.h"
#include "comm_status_broadcast_client_dbus_bindings.h"
#include "comm_status_broadcast_signal_marshaller.h"
#include <stdlib.h>
#include <string.h>

struct comm_client {
	/* Resources to be freed */
	DBusGConnection *conn;
	GError *err;
	DBusGProxy *request_proxy;
	DBusGProxy *signal_proxy;
	char *pkgid;

	status_cb signal_cb;
	void *signal_cb_data;
};

comm_client *comm_client_new(void)
{
	comm_client *cc = NULL;

	cc = calloc(1, sizeof(comm_client));
	if (NULL == cc)
		return NULL;

	cc->conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &(cc->err));
	if (NULL == cc->conn) {
		g_printerr("Failed to open connection to dbus: %s\n",
			   cc->err->message);
		g_error_free(cc->err);
		cc->err = NULL;
		comm_client_free(cc);
		return NULL;
	}

	cc->request_proxy = dbus_g_proxy_new_for_name(cc->conn,
						COMM_PKG_MGR_DBUS_SERVICE,
				/* name : written in service file */
						COMM_PKG_MGR_DBUS_PATH,
				/* path : written as a node in xml */
						COMM_PKG_MGR_DBUS_INTERFACE
			/* interface : written as an interface in xml */
	    );

	return cc;
}

int comm_client_free(comm_client *cc)
{
	if (NULL == cc)
		return -1;

	if (cc->err)
		g_error_free(cc->err);
	if (cc->conn)
		dbus_g_connection_unref(cc->conn);
	if (cc->request_proxy)
		g_object_unref(cc->request_proxy);
	if (cc->signal_proxy)
		g_object_unref(cc->signal_proxy);
	if (cc->pkgid)
		free(cc->pkgid);

	free(cc);

	return 0;
}

static void
status_signal_handler(DBusGProxy *proxy,
		      const char *req_id,
		      const char *pkg_type,
		      const char *pkgid,
		      const char *key, const char *val, gpointer data)
{
	comm_client *cc = (comm_client *) data;

	dbg("Got signal: %s/%s/%s/%s/%s", req_id, pkg_type,
				 pkgid, key, val);
	if (cc->signal_cb) {
		if (cc->pkgid && pkgid &&
			0 == strncmp(cc->pkgid, pkgid,
				     strlen(cc->pkgid))) {
			dbg("Run signal handler");
			cc->signal_cb(cc->signal_cb_data, req_id, pkg_type,
				      pkgid, key, val);
		} else {
			dbg("pkgid is different. (My pkgid:%s)"
			" Though pass signal to user callback.", cc->pkgid);
			cc->signal_cb(cc->signal_cb_data, req_id, pkg_type,
				      pkgid, key, val);
		}
	} else {
		dbg("No signal handler is set. Do nothing.");
	}
}

int
comm_client_request(comm_client *cc, const char *req_id, const int req_type,
		    const char *pkg_type, const char *pkgid,
		    const char *args, const char *cookie)
{
	gboolean r;
	gint ret = COMM_RET_ERROR;

	dbg("got request:%s/%d/%s/%s/%s/%s\n", req_id, req_type, pkg_type,
	    pkgid, args, cookie);

	if (!pkgid)
		pkgid = "";	/* NULL check */

	r = org_tizen_slp_pkgmgr_request(cc->request_proxy, req_id, req_type,
					   pkg_type, pkgid, args, cookie,
					   &ret, &(cc->err));
	if (TRUE == r) {
		ret = COMM_RET_OK;
	} else {
		g_printerr("Failed to send request via dbus: %s\n",
			   cc->err->message);
		if (cc->err) {
			g_error_free(cc->err);
			cc->err = NULL;
		}
		return ret;
	}
	dbg("request sent");

	if (cc->pkgid) {
		dbg("freeing pkgid");
		free(cc->pkgid);
		dbg("freed pkgid");
	}
	cc->pkgid = strdup(pkgid);

	dbg("ret:%d", ret);

	return ret;
}

int
comm_client_set_status_callback(comm_client *cc, status_cb cb, void *cb_data)
{
	/* set callback */
	if (!cc->signal_proxy) {
		dbg("signal_proxy is NULL. Try to create a proxy for signal.");
		cc->signal_proxy = dbus_g_proxy_new_for_name(cc->conn,
				     COMM_STATUS_BROADCAST_DBUS_SERVICE_PREFIX,
				     COMM_STATUS_BROADCAST_DBUS_PATH,
				     COMM_STATUS_BROADCAST_DBUS_INTERFACE);
		if (NULL == cc->signal_proxy) {
			g_printerr("Failed to create proxy for signal\n", NULL);
			return COMM_RET_ERROR;
		} else {
		}
	} else {
		/* Proxy is existing. Do nothing. */
	}

	cc->signal_cb = cb;
	cc->signal_cb_data = cb_data;

	dbg("Register signal-type marshaller.");
	dbus_g_object_register_marshaller(
	g_cclosure_user_marshal_VOID__STRING_STRING_STRING_STRING_STRING,
		/* marshaller */
	G_TYPE_NONE, /* return type */
	G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
	G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);	/* termination flag */

	dbg("Add signal to proxy.");
	dbus_g_proxy_add_signal(cc->signal_proxy,
				COMM_STATUS_BROADCAST_SIGNAL_STATUS,
				G_TYPE_STRING,
				G_TYPE_STRING,
				G_TYPE_STRING,
				G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);

	dbg("Connect signal to proxy.");

	dbus_g_proxy_connect_signal(cc->signal_proxy,
				    COMM_STATUS_BROADCAST_SIGNAL_STATUS,
				    G_CALLBACK(status_signal_handler),
				    cc, NULL);

	return 0;
}

