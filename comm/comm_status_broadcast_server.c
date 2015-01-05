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
#include <stdlib.h>
#include <unistd.h>
#include <dbus/dbus.h>

#include "comm_status_broadcast_server.h"
#include "comm_debug.h"

/***************************
 * dbus-glib API for server
 ***************************/
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-bindings.h>

/* object class def: do nothing on this */
struct StatusBroadcastObjectClass {
	GObjectClass parent_class;

	guint signal;
};

/* object def: has connection */
struct StatusBroadcastObject {
	GObject parent;

	DBusGConnection *bus;
	char *dbus_service_name;
};

#define STATUS_BROADCAST_OBJECT(object) \
(G_TYPE_CHECK_INSTANCE_CAST((object), \
	STATUS_BROADCAST_TYPE_OBJECT, StatusBroadcastObject))
#define STATUS_BROADCAST_OBJECT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
	 STATUS_BROADCAST_TYPE_OBJECT, StatusBroadcastObjectClass))
#define STATUS_BROADCAST_IS_OBJECT(object) \
	(G_TYPE_CHECK_INSTANCE_TYPE((object), \
	STATUS_BROADCAST_TYPE_OBJECT))
#define STATUS_BROADCAST_IS_OBJECT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), \
	 STATUS_BROADCAST_TYPE_OBJECT))
#define STATUS_BROADCAST_OBJECT_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
	STATUS_BROADCAST_TYPE_OBJECT, StatusBroadcastObjectClass))

/* Macro that creates follwoing functions automatically;
 *   - status_broadcast_object_get_type()
 *   - status_broadcast_object_parent_class
 */
G_DEFINE_TYPE(StatusBroadcastObject, status_broadcast_object, G_TYPE_OBJECT);

/* method/signal declarations
 * Used for binding stub.
 */

/* Include stub header */
#include "comm_status_broadcast_server_dbus_bindings.h"

static void
__status_broadcast_object_class_init(StatusBroadcastObjectClass *klass);
static void __status_broadcast_object_init(StatusBroadcastObject *obj);
static void __status_broadcast_object_finalize(GObject *self);

static void
__status_broadcast_object_class_init(StatusBroadcastObjectClass *klass)
{
	DBG("called");

	g_assert(NULL != klass);

	klass->signal = g_signal_new(COMM_STATUS_BROADCAST_SIGNAL_STATUS,
				     G_OBJECT_CLASS_TYPE(klass),
				     G_SIGNAL_RUN_LAST,
				     0,
				     NULL,
				     NULL,
				     g_cclosure_marshal_VOID__STRING,
				     G_TYPE_NONE,
				     3,
				     G_TYPE_STRING,
				     G_TYPE_STRING, G_TYPE_STRING);

	dbus_g_object_type_install_info(STATUS_BROADCAST_TYPE_OBJECT,
				&dbus_glib_status_broadcast_object_info);

	DBG("done");
}

static void __status_broadcast_object_init(StatusBroadcastObject *obj)
{
	DBG("called");
	g_assert(NULL != obj);

	GError *err = NULL;

	/* Establish dbus session  */
	obj->bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);
	if (NULL == obj->bus) {
		DBG("Failed to open connection to dbus: %s", err->message);
		return;
	}

	/* Create a proxy to resgister, connecting dbus daemon */
	DBusGProxy *proxy = NULL;
	proxy = dbus_g_proxy_new_for_name(obj->bus,
					  DBUS_SERVICE_DBUS,
					  DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
	if (NULL == proxy) {
		DBG("Failed to get a proxy");
		return;
	}
	/* Register service name
	 * NOTE: refer to 
	http://dbus.freedesktop.org/doc/dbus-specification.html 
	 */

	guint result;
	if (!dbus_g_proxy_call(proxy, "RequestName", &err,
		/* input vars */
		G_TYPE_STRING, COMM_STATUS_BROADCAST_DBUS_SERVICE_PREFIX,
		/* service name */
		G_TYPE_UINT, 0,	/* default flag */
		G_TYPE_INVALID,
		/* output vars */
		G_TYPE_UINT, &result, G_TYPE_INVALID)) {
		g_printerr("dbus RequestName RPC failed", err->message, TRUE);
		return;
	}
	DBG("RequestName returns: %d", result);

	dbus_g_connection_register_g_object(obj->bus,
					    COMM_STATUS_BROADCAST_DBUS_PATH,
					    G_OBJECT(obj));
	DBG("Ready to serve requests");

	g_object_unref(proxy);

	DBG("done");
}

static void __status_broadcast_object_finalize(GObject *self)
{
	StatusBroadcastObjectClass *klass =
	    (StatusBroadcastObjectClass *) G_OBJECT_CLASS(self);

	/* Call parent's finalize function
	 * 'server_object_parent_class' comes from G_DEFINE_TYPE() macro. 
	 */
	G_OBJECT_CLASS(status_broadcast_object_parent_class)->finalize(self);
}

/* dbus-glib methods/signals */

void
status_broadcast_emit_status(StatusBroadcastObject *obj,
			     const char *pkg, const char *key, const char *val)
{
	StatusBroadcastObjectClass *klass;
	klass = STATUS_BROADCAST_OBJECT_GET_CLASS(obj);

	DBG("Send signal: %s/%s/%s", pkg, key, val);
	g_signal_emit(obj, klass->signal, 0, pkg, key, val);

}

