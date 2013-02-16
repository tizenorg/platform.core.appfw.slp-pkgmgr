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
#include "comm_status_broadcast_server.h"
#include <dbus/dbus.h>

/********************************************
 * pure dbus signal service for internal use
 ********************************************/

API DBusConnection *comm_status_broadcast_server_connect(void)
{
	DBusError err;
	DBusConnection *conn;

	dbus_error_init(&err);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err)) {
		dbg("Connection error: %s", err.message);
		dbus_error_free(&err);
	}
	dbus_error_free(&err);
	if (NULL == conn)
		exit(1);
	dbus_bus_request_name(conn,
			      COMM_STATUS_BROADCAST_DBUS_SERVICE_PREFIX,
			      DBUS_NAME_FLAG_ALLOW_REPLACEMENT, &err);
	if (dbus_error_is_set(&err)) {
		dbg("Failed to request name: %s", err.message);
		dbus_error_free(&err);
		exit(1);
	}

	return conn;
}

API void
comm_status_broadcast_server_send_signal(DBusConnection *conn,
					 const char *req_id,
					 const char *pkg_type,
					 const char *pkgid, const char *key,
					 const char *val)
{
	dbus_uint32_t serial = 0;
	DBusMessage *msg;
	DBusMessageIter args;

	const char *values[] = {
		req_id,
		pkg_type,
		pkgid,
		key,
		val
	};
	int i;

	msg = dbus_message_new_signal(COMM_STATUS_BROADCAST_DBUS_PATH,
				      COMM_STATUS_BROADCAST_DBUS_INTERFACE,
				      COMM_STATUS_BROADCAST_SIGNAL_STATUS);
	if (NULL == msg) {
		dbg("msg NULL");
		exit(1);
	}

	dbus_message_iter_init_append(msg, &args);

	for (i = 0; i < 5; i++) {
		if (!dbus_message_iter_append_basic
		    (&args, DBUS_TYPE_STRING, &(values[i]))) {
			dbg("dbus_message_iter_append_basic failed:"
			" Out of memory");
			exit(1);
		}
	}
	if (!dbus_connection_send(conn, msg, &serial)) {
		dbg("dbus_connection_send failed: Out of memory");
		exit(1);
	}
	dbus_connection_flush(conn);
	dbus_message_unref(msg);
}

API void comm_status_broadcast_server_disconnect(DBusConnection *conn)
{
	if (!conn)
		return;
	dbus_connection_unref(conn);
}

