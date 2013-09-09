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
static char *__get_prifix(int status_type)
{
	char *prifix = NULL;

	switch (status_type) {
		case COMM_STATUS_BROADCAST_ALL:
			prifix = COMM_STATUS_BROADCAST_DBUS_SERVICE_PREFIX;
			break;

		case COMM_STATUS_BROADCAST_INSTALL:
			prifix = COMM_STATUS_BROADCAST_DBUS_INSTALL_SERVICE_PREFIX;
			break;

		case COMM_STATUS_BROADCAST_UNINSTALL:
			prifix = COMM_STATUS_BROADCAST_DBUS_UNINSTALL_SERVICE_PREFIX;
			break;

		case COMM_STATUS_BROADCAST_MOVE:
			prifix = COMM_STATUS_BROADCAST_DBUS_MOVE_SERVICE_PREFIX;
			break;

		case COMM_STATUS_BROADCAST_INSTALL_PROGRESS:
			prifix = COMM_STATUS_BROADCAST_DBUS_INSTALL_PROGRESS_SERVICE_PREFIX;
			break;

		case COMM_STATUS_BROADCAST_UPGRADE:
			prifix = COMM_STATUS_BROADCAST_DBUS_UPGRADE_SERVICE_PREFIX;
			break;

		default:
			prifix = NULL;
	}
	return prifix;
}

static char *__get_path(int status_type)
{
	char *path = NULL;

	switch (status_type) {
		case COMM_STATUS_BROADCAST_ALL:
			path = COMM_STATUS_BROADCAST_DBUS_PATH;
			break;

		case COMM_STATUS_BROADCAST_INSTALL:
			path = COMM_STATUS_BROADCAST_DBUS_INSTALL_PATH;
			break;

		case COMM_STATUS_BROADCAST_UNINSTALL:
			path = COMM_STATUS_BROADCAST_DBUS_UNINSTALL_PATH;
			break;

		case COMM_STATUS_BROADCAST_MOVE:
			path = COMM_STATUS_BROADCAST_DBUS_MOVE_PATH;
			break;

		case COMM_STATUS_BROADCAST_INSTALL_PROGRESS:
			path = COMM_STATUS_BROADCAST_DBUS_INSTALL_PROGRESS_PATH;
			break;

		case COMM_STATUS_BROADCAST_UPGRADE:
			path = COMM_STATUS_BROADCAST_DBUS_UPGRADE_PATH;
			break;

		default:
			path = NULL;
	}
	return path;
}

static char *__get_interface(int status_type)
{
	char *interface = NULL;

	switch (status_type) {
		case COMM_STATUS_BROADCAST_ALL:
			interface = COMM_STATUS_BROADCAST_DBUS_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_INSTALL:
			interface = COMM_STATUS_BROADCAST_DBUS_INSTALL_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_UNINSTALL:
			interface = COMM_STATUS_BROADCAST_DBUS_UNINSTALL_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_MOVE:
			interface = COMM_STATUS_BROADCAST_DBUS_MOVE_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_INSTALL_PROGRESS:
			interface = COMM_STATUS_BROADCAST_DBUS_INSTALL_PROGRESS_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_UPGRADE:
			interface = COMM_STATUS_BROADCAST_DBUS_UPGRADE_INTERFACE;
			break;

		default:
			interface = NULL;
	}
	return interface;
}

static char *__get_name(int status_type)
{
	char *name = NULL;

	switch (status_type) {
		case COMM_STATUS_BROADCAST_ALL:
			name = COMM_STATUS_BROADCAST_SIGNAL_STATUS;
			break;

		case COMM_STATUS_BROADCAST_INSTALL:
			name = COMM_STATUS_BROADCAST_EVENT_INSTALL;
			break;

		case COMM_STATUS_BROADCAST_UNINSTALL:
			name = COMM_STATUS_BROADCAST_EVENT_UNINSTALL;
			break;

		case COMM_STATUS_BROADCAST_MOVE:
			name = COMM_STATUS_BROADCAST_EVENT_MOVE;
			break;

		case COMM_STATUS_BROADCAST_INSTALL_PROGRESS:
			name = COMM_STATUS_BROADCAST_EVENT_INSTALL_PROGRESS;
			break;

		case COMM_STATUS_BROADCAST_UPGRADE:
			name = COMM_STATUS_BROADCAST_EVENT_UPGRADE;
			break;

		default:
			name = NULL;
	}
	return name;
}

API DBusConnection *comm_status_broadcast_server_connect(int status_type)
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
	if (NULL == conn) {
		dbg("conn is NULL");
		return NULL;
	}

	dbus_bus_request_name(conn, __get_prifix(status_type), DBUS_NAME_FLAG_ALLOW_REPLACEMENT, &err);
	if (dbus_error_is_set(&err)) {
		dbg("Failed to request name: %s", err.message);
		dbus_error_free(&err);
		return NULL;
	}

	return conn;
}

API void
comm_status_broadcast_server_send_signal(int comm_status_type, DBusConnection *conn,
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

	msg = dbus_message_new_signal(__get_path(comm_status_type), __get_interface(comm_status_type), __get_name(comm_status_type));
	if (NULL == msg) {
		dbg("msg NULL");
		return;
	}

	dbus_message_iter_init_append(msg, &args);

	for (i = 0; i < 5; i++) {
		if (!dbus_message_iter_append_basic
		    (&args, DBUS_TYPE_STRING, &(values[i]))) {
			dbg("dbus_message_iter_append_basic failed:"
			" Out of memory");
			return;
		}
	}
	if (!dbus_connection_send(conn, msg, &serial)) {
		dbg("dbus_connection_send failed: Out of memory");
		return;
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
