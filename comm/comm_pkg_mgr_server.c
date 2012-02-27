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
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-bindings.h>
#include <stdlib.h>
#include <unistd.h>

#include "comm_pkg_mgr_server.h"

/* object class def: do nothing on this */
struct PkgMgrObjectClass {
	GObjectClass parent_class;
};

/* object def: has connection */
struct PkgMgrObject {
	GObject parent;

	DBusGConnection *bus;

	request_callback req_cb;
	void *req_cb_data;
};

#define PKG_MGR_OBJECT(object) \
(G_TYPE_CHECK_INSTANCE_CAST((object), \
	PKG_MGR_TYPE_OBJECT, PkgMgrObject))
#define PKG_MGR_OBJECT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
	 PKG_MGR_TYPE_OBJECT, PkgMgrObjectClass))
#define PKG_MGR_IS_OBJECT(object) \
	(G_TYPE_CHECK_INSTANCE_TYPE((object), \
	PKG_MGR_TYPE_OBJECT))
#define PKG_MGR_IS_OBJECT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), \
	 PKG_MGR_TYPE_OBJECT))
#define PKG_MGR_OBJECT_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
	PKG_MGR_TYPE_OBJECT, PkgMgrObjectClass))

/* Macro that creates follwoing functions automatically;
 *   - pkgmgr_object_get_type()
 *   - pkgmgr_object_parent_class
 */
G_DEFINE_TYPE(PkgMgrObject, pkg_mgr_object, G_TYPE_OBJECT);

/* Method declarations
 * Used for binding stub.
 */
GCallback pkgmgr_request(PkgMgrObject *obj, const gchar *req_id,
			 const gint req_type, const gchar *pkg_type,
			 const gchar *pkg_name, const gchar *args,
			 const gchar *cookie, gint *ret, GError *err);

/* Include stub header */
#include "comm_pkg_mgr_server_dbus_bindings.h"

static void pkg_mgr_object_finalize(GObject *self);
static void pkg_mgr_object_init(PkgMgrObject *obj);
static void pkg_mgr_object_class_init(PkgMgrObjectClass *klass);
static void pkg_mgr_object_init(PkgMgrObject *obj)
{
	dbg("called");
	g_assert(NULL != obj);

	GError *err = NULL;

	/* Establish dbus session  */
	obj->bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);
	if (NULL == obj->bus) {
		dbg("Failed to open connection to dbus: %s", err->message);
		return;
	}

	/* Create a proxy to resgister, connecting dbus daemon */
	DBusGProxy *proxy = NULL;
	proxy = dbus_g_proxy_new_for_name(obj->bus,
					  DBUS_SERVICE_DBUS,
					  DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
	if (NULL == proxy) {
		dbg("Failed to get a proxy");
		return;
	}
	/* Register service name
	 * NOTE: refer to 
	http://dbus.freedesktop.org/doc/dbus-specification.html 
	 */
	guint result;
	if (!dbus_g_proxy_call(proxy, "RequestName", &err,
			       /* input vars */
			       G_TYPE_STRING, COMM_PKG_MGR_DBUS_SERVICE,
				/* service name */
			       G_TYPE_UINT, 0,	/* default flag */
			       G_TYPE_INVALID,
			       /* output vars */
			       G_TYPE_UINT, &result, G_TYPE_INVALID)) {
		g_printerr("dbus RequestName RPC failed %s %d", err->message, TRUE);
		return;
	}
	dbg("RequestName returns: %d", result);

	dbus_g_connection_register_g_object(obj->bus,
					    COMM_PKG_MGR_DBUS_PATH,
					    G_OBJECT(obj));
	dbg("Ready to serve requests");

	g_object_unref(proxy);

	dbg("done");
}

static void pkg_mgr_object_class_init(PkgMgrObjectClass *klass)
{
	dbg("called");

	g_assert(NULL != klass);

	dbus_g_object_type_install_info(PKG_MGR_TYPE_OBJECT,
					&dbus_glib_pkgmgr_object_info);

	dbg("done");
}

static void pkg_mgr_object_finalize(GObject *self)
{
	/* PkgMgrObjectClass *klass = (PkgMgrObjectClass *) G_OBJECT_CLASS(self); */

	/* Call parent's finalize function
	 * 'server_object_parent_class' comes from G_DEFINE_TYPE() macro. 
	 */
	G_OBJECT_CLASS(pkg_mgr_object_parent_class)->finalize(self);
}

/* dbus-glib methods */

GCallback
pkgmgr_request(PkgMgrObject *obj,
	       const gchar *req_id,
	       const gint req_type,
	       const gchar *pkg_type,
	       const gchar *pkg_name,
	       const gchar *args,
	       const gchar *cookie, gint *ret, GError *err)
{
	dbg("Called");
	*ret = COMM_RET_OK;	/* TODO: fix this! */

	/* TODO: Add business logic 
	 * - add to queue, or remove from queue
	 * */

	if (obj->req_cb) {
		dbg("Call request callback(obj, %s, %d, %s, %s, %s, *ret)",
		    req_id, req_type, pkg_type, pkg_name, args);
		obj->req_cb(obj->req_cb_data, req_id, req_type, pkg_type,
			    pkg_name, args, cookie, ret);
	} else {
		dbg("Attempt to call request callback,"
		" but request callback is not set. Do nothing.\n"
		"Use pkg_mgr_set_request_callback()"
		" to register your callback.");
	}

	return (GCallback) TRUE;
}

/* Other APIs
 */

/**
 * Set request callback function
 */
void pkg_mgr_set_request_callback(PkgMgrObject *obj, request_callback req_cb,
			     void *cb_data)
{
	obj->req_cb = req_cb;
	obj->req_cb_data = cb_data;
}
