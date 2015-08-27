#include <sys/types.h>

#include <glib.h>
#include <gio/gio.h>

#include "comm_config.h"
#include "pm-queue.h"
#include "pkgmgr-server.h"
#include "package-manager-debug.h"

static const char instropection_xml[] =
	"<node>"
	"  <interface name='org.tizen.pkgmgr'>"
	"    <method name='install'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgpath' direction='in'/>"
	"      <arg type='s' name='args' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='reinstall'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='s' name='args' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='uninstall'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='s' name='args' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='cleardata'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='s' name='args' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='move'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='s' name='args' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='activate'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='s' name='args' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='deactivate'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='s' name='args' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='getsize'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='s' name='args' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='clearcache'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='kill'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='check'>"
	"      <arg type='s' name='reqid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"  </interface>"
	"</node>";
static GDBusNodeInfo *instropection_data;
static guint reg_id;
static guint owner_id;

static int __handle_request_install(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgpath;
	gchar *args;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s&s)", &reqid, &pkgtype, &pkgpath,
			&args);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_TO_INSTALLER,
			pkgtype, pkgpath, args);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static int __handle_request_reinstall(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgid;
	gchar *args;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s&s)", &reqid, &pkgtype, &pkgid,
			&args);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_TO_INSTALLER,
			pkgtype, pkgid, args);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static int __handle_request_uninstall(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgid;
	gchar *args;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s&s)", &reqid, &pkgtype, &pkgid,
			&args);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_TO_INSTALLER,
			pkgtype, pkgid, args);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static int __handle_request_cleardata(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgid;
	gchar *args;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s&s)", &reqid, &pkgtype, &pkgid,
			&args);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_TO_CLEARER,
			pkgtype, pkgid, args);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static int __handle_request_move(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgid;
	gchar *args;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s&s)", &reqid, &pkgtype, &pkgid,
			&args);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_TO_MOVER,
			pkgtype, pkgid, args);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static int __handle_request_activate(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgid;
	gchar *args;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s&s)", &reqid, &pkgtype, &pkgid,
			&args);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_TO_ACTIVATOR,
			pkgtype, pkgid, args);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static int __handle_request_deactivate(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgid;
	gchar *args;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s&s)", &reqid, &pkgtype, &pkgid,
			&args);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_TO_ACTIVATOR,
			pkgtype, pkgid, args);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static int __handle_request_getsize(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgid;
	gchar *args;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s&s)", &reqid, &pkgtype, &pkgid,
			&args);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_GET_SIZE,
			pkgtype, pkgid, args);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static int __handle_request_clearcache(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgid;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s)", &reqid, &pkgtype, &pkgid);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_CLEAR_CACHE_DIR,
			pkgtype, pkgid, NULL);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static int __handle_request_kill(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgid;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s)", &reqid, &pkgtype, &pkgid);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_KILL_APP,
			pkgtype, pkgid, NULL);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static int __handle_request_check(uid_t uid, GVariant *parameters)
{
	gchar *reqid;
	gchar *pkgtype;
	gchar *pkgid;
	pm_dbus_msg *item;

	g_variant_get(parameters, "(&s&s&s)", &reqid, &pkgtype, &pkgid);

	item = _pm_queue_create_item(uid, reqid, COMM_REQ_CHECK_APP,
			pkgtype, pkgid, NULL);
	if (item == NULL)
		return -1;

	if (_pm_queue_push(item))
		return -1;

	return 0;
}

static uid_t __get_caller_uid(GDBusConnection *connection, const char *name)
{
	GError *err = NULL;
	GVariant *result;
	uid_t uid;

	result = g_dbus_connection_call_sync(connection,
			"org.freedesktop.DBus", "/org/freedesktop/DBus",
			"org.freedesktop.DBus", "GetConnectionUnixUser",
			g_variant_new("(s)", name), NULL,
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
	if (result == NULL) {
		ERR("failed to get caller uid: %s", err->message);
		g_error_free(err);
		return (uid_t)-1;
	}

	g_variant_get(result, "(u)", &uid);

	return uid;
}

static void __handle_method_call(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path,
		const gchar *interface_name, const gchar *method_name,
		GVariant *parameters, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	int ret;
	uid_t uid;

	uid = __get_caller_uid(connection,
		g_dbus_method_invocation_get_sender(invocation));
	if (uid == (uid_t)-1)
		return;

	if (g_strcmp0(method_name, "install") == 0)
		ret = __handle_request_install(uid, parameters);
	else if (g_strcmp0(method_name, "reinstall") == 0)
		ret = __handle_request_reinstall(uid, parameters);
	else if (g_strcmp0(method_name, "uninstall") == 0)
		ret = __handle_request_uninstall(uid, parameters);
	else if (g_strcmp0(method_name, "cleardata") == 0)
		ret = __handle_request_cleardata(uid, parameters);
	else if (g_strcmp0(method_name, "move") == 0)
		ret = __handle_request_move(uid, parameters);
	else if (g_strcmp0(method_name, "activate") == 0)
		ret = __handle_request_activate(uid, parameters);
	else if (g_strcmp0(method_name, "deactivate") == 0)
		ret = __handle_request_deactivate(uid, parameters);
	else if (g_strcmp0(method_name, "getsize") == 0)
		ret = __handle_request_getsize(uid, parameters);
	else if (g_strcmp0(method_name, "clearcache") == 0)
		ret = __handle_request_clearcache(uid, parameters);
	else if (g_strcmp0(method_name, "kill") == 0)
		ret = __handle_request_kill(uid, parameters);
	else if (g_strcmp0(method_name, "check") == 0)
		ret = __handle_request_check(uid, parameters);
	else
		ret = -1;

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(i)", ret));

	if (ret == 0)
		g_idle_add(queue_job, NULL);
}

static const GDBusInterfaceVTable interface_vtable =
{
	__handle_method_call,
	NULL,
	NULL,
};

static void __on_bus_acquired(GDBusConnection *connection, const gchar *name,
		gpointer user_data)
{

	DBG("on bus acquired");

	reg_id = g_dbus_connection_register_object(connection,
			COMM_PKGMGR_DBUS_OBJECT_PATH,
			instropection_data->interfaces[0],
			&interface_vtable, NULL, NULL, NULL);

	if (reg_id < 0)
		ERR("failed to register object");
}

static void __on_name_acquired(GDBusConnection *connection, const gchar *name,
		gpointer user_data)
{
	DBG("on name acquired: %s", name);
}

static void __on_name_lost(GDBusConnection *connection, const gchar *name,
		gpointer user_data)
{
	DBG("on name lost: %s", name);
}

int __init_request_handler(void)
{
	instropection_data = g_dbus_node_info_new_for_xml(instropection_xml, NULL);

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM, COMM_PKGMGR_DBUS_SERVICE,
			G_BUS_NAME_OWNER_FLAGS_NONE, __on_bus_acquired,
			__on_name_acquired, __on_name_lost, NULL, NULL);

	return 0;
}

void __fini_request_handler(void)
{
	g_bus_unown_name(owner_id);
	g_dbus_node_info_unref(instropection_data);
}
