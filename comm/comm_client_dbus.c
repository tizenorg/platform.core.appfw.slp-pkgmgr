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
 * comm_client_dbus.c
 * comm_client library using pure dbus 
 * (dbus-glib is used only to register into g_main_loop)
 */

#include "comm_config.h"
#include "comm_client.h"
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <stdbool.h>
#include <stdio.h>

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
	DBusConnection *conn;
	struct signal_callback_data *sig_cb_data;
};

/*********************************
 * Internal function description
 */

/**
 * signal handler filter
 * Filter signal, and run user callback
 */
DBusHandlerResult
_on_signal_handle_filter(DBusConnection *conn,
			 DBusMessage *msg, void *user_data)
{
	DBusError err;

	dbg("start function");

	dbus_error_init(&err);

	/* Values to be received by signal */
	char *req_id = NULL;
	char *pkg_type = NULL;
	char *pkg_name = NULL;
	char *key = NULL;
	char *val = NULL;

	/* User's signal handler */
	struct signal_callback_data *sig_cb_data;
	sig_cb_data = (struct signal_callback_data *)user_data;

	/* Signal check */
	if (dbus_message_is_signal(msg,
				   COMM_STATUS_BROADCAST_DBUS_INTERFACE,
				   COMM_STATUS_BROADCAST_SIGNAL_STATUS)) {

		/* Signal type check */
		if (dbus_message_get_args(msg, &err,
					  DBUS_TYPE_STRING, &req_id,
					  DBUS_TYPE_STRING, &pkg_type,
					  DBUS_TYPE_STRING, &pkg_name,
					  DBUS_TYPE_STRING, &key,
					  DBUS_TYPE_STRING, &val,
					  DBUS_TYPE_INVALID)) {
			/* Got signal! */
			dbg("Got signal: %s / %s / %s / %s / %s", req_id,
			    pkg_type, pkg_name, key, val);

			/* Run signal callback if exist */
			if (sig_cb_data && sig_cb_data->cb) {
				sig_cb_data->cb(sig_cb_data->cb_data, req_id,
						pkg_type, pkg_name, key, val);

				dbg("callback function is end");
			}

			dbg("handled signal. exit function");
			return DBUS_HANDLER_RESULT_HANDLED;
		}
	}
	dbg("Didn't handled signal. anyway exit function");
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/**
 * signal_callback_data free function
 * Just free it!
 */
void _free_sig_cb_data(void *memory)
{
	struct signal_callback_data *sig_cb_data;
	sig_cb_data = (struct signal_callback_data *)memory;
	if (!sig_cb_data)
		return;
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
	DBusError err;
	comm_client *cc = NULL;

	/* Allocate memory for ADT:comm_client */
	cc = calloc(1, sizeof(comm_client));
	if (NULL == cc) {
		ERR("No memory");
		goto ERROR_CLEANUP;
	}

	/* Connect to dbus */
	dbus_error_init(&err);
	cc->conn = dbus_bus_get_private(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err)) {
		ERR("dbus connection error (%s)", err.message);
		dbus_error_free(&err);
		goto ERROR_CLEANUP;
	}
	if (NULL == cc->conn) {
		ERR("dbus connection is not set, even dbus error isn't raised");
		goto ERROR_CLEANUP;
	}

	/* TODO: requesting name for dbus is needed? */

	/* Register my connection to g_main_loop (with default context) */
	dbus_connection_setup_with_g_main(cc->conn, NULL);

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
	if (!(cc->conn) || !dbus_connection_get_is_connected(cc->conn)) {
		ERR("Invalid dbus connection");
		return -2;
	}

	/* Cleanup ADT */
	/* flush remaining buffer: blocking mode */
	dbus_connection_flush(cc->conn);	

	/* Free signal filter if signal callback is exist */
	if (cc->sig_cb_data) {
		dbus_connection_remove_filter(cc->conn,
					      _on_signal_handle_filter,
					      cc->sig_cb_data);
		/* TODO: Is it needed to free cc->sig_cb_data here? */
		/* _free_sig_cb_data(cc->sig_cb_data); */
	}

	dbus_connection_close(cc->conn);
	dbus_connection_unref(cc->conn);

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
		const char *pkg_name,
		const char *args,
		const char *cookie,
		int is_block)
{
	DBusMessage *msg = NULL;
	int r = COMM_RET_ERROR;	/* Default return */

	if (!cc)
		return COMM_RET_ERROR;

	/* Create a dbus message */
	msg = dbus_message_new_method_call(COMM_PKG_MGR_DBUS_SERVICE,
					   COMM_PKG_MGR_DBUS_PATH,
					   COMM_PKG_MGR_DBUS_INTERFACE,
					   COMM_PKG_MGR_METHOD_REQUEST);
	if (NULL == msg) {
		r = COMM_RET_NOMEM;
		goto ERROR_CLEANUP;
	}

	/* Assign default values if NULL (NULL is not allowed) */
	if (NULL == req_id)
		req_id = "tmp_reqid";
	if (NULL == pkg_type)
		pkg_type = "none";
	if (NULL == pkg_name)
		pkg_name = "";
	if (NULL == args)
		args = "";
	if (NULL == cookie)
		cookie = "";

	/* Append arguments */
	if (!dbus_message_append_args(msg,
				      DBUS_TYPE_STRING, &req_id,
				      DBUS_TYPE_INT32, &req_type,
				      DBUS_TYPE_STRING, &pkg_type,
				      DBUS_TYPE_STRING, &pkg_name,
				      DBUS_TYPE_STRING, &args,
				      DBUS_TYPE_STRING, &cookie,
				      DBUS_TYPE_INVALID)) {
		r = COMM_RET_NOMEM;
		goto ERROR_CLEANUP;
	}

	/* Send message */
	if (is_block == 1){
		if(!dbus_connection_send_with_reply_and_block(cc->conn, msg,
							      5000, NULL)) {
			r = COMM_RET_NOMEM; 
			goto ERROR_CLEANUP;
		}
	} else {
		if (!dbus_connection_send(cc->conn, msg, NULL)) {
			r = COMM_RET_NOMEM;
			goto ERROR_CLEANUP;
		}
	}
	dbus_connection_flush(cc->conn);

	/* Cleanup and return */
	dbus_message_unref(msg);
	/* NOTE: It is not needed to free DBusMessageIter. */

	return 0;

 ERROR_CLEANUP:
	if (COMM_RET_NOMEM == r)
		ERR("No memory!");
	else
		ERR("General error!");

	if (msg)
		dbus_message_unref(msg);

	return r;
}

/**
 * Set a callback for status signal
 */
int
comm_client_set_status_callback(comm_client *cc, status_cb cb, void *cb_data)
{
	DBusError err;
	char buf[256] = { 0, };
	int r = COMM_RET_ERROR;

	dbus_error_init(&err);

	if (NULL == cc)
		goto ERROR_CLEANUP;

	/* Add a rule for signal */
	snprintf(buf, 255, "type='signal',interface='%s'",
		 COMM_STATUS_BROADCAST_DBUS_INTERFACE);
	dbus_bus_add_match(cc->conn, buf, &err);
	if (dbus_error_is_set(&err)) {
		ERR("dbus error:%s", err.message);
		r = COMM_RET_ERROR;
		goto ERROR_CLEANUP;
	}

	/* If previous signal handler is set already, remove filter first */
	if (cc->sig_cb_data) {
		dbus_connection_remove_filter(cc->conn,
					      _on_signal_handle_filter,
					      cc->sig_cb_data);
		/* TODO: Is it needed to free cc->sig_cb_data here? */
	}

	/* Create new sig_cb_data */
	cc->sig_cb_data = calloc(1, sizeof(struct signal_callback_data));
	(cc->sig_cb_data)->cb = cb;
	(cc->sig_cb_data)->cb_data = cb_data;

	/* Add signal filter */
	if (!dbus_connection_add_filter(cc->conn,
					_on_signal_handle_filter,
					cc->sig_cb_data, _free_sig_cb_data)) {
		r = COMM_RET_NOMEM;
		goto ERROR_CLEANUP;
	}

	/* Cleanup and return */
	dbus_error_free(&err);
	return COMM_RET_OK;

 ERROR_CLEANUP:
	if (COMM_RET_NOMEM == r)
		ERR("No memory");
	else
		ERR("General error");

	dbus_error_free(&err);
	return r;
}

