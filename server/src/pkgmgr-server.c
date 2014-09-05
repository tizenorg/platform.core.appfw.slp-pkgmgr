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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <glib.h>
#include <signal.h>
#include <Elementary.h>
#include <appcore-efl.h>
#ifdef HAVE_X11
#include <Ecore_X.h>
#include <X11/Xatom.h>
#include <X11/Xutil.h>
#endif
#include <Ecore_File.h>
#include <ail.h>
#include <pkgmgr-info.h>
#include <pkgmgr/pkgmgr_parser.h>

#include <security-server.h>

#include <vconf.h>

/* For multi-user support */
#include <tzplatform_config.h>

#include "pkgmgr_installer.h"
#include "comm_pkg_mgr_server.h"
#include "pkgmgr-server.h"
#include "pm-queue.h"
#include "comm_config.h"

/* debug output */
#if defined(NDEBUG)
#define DBG(fmt, args...)
#define __SET_DBG_OUTPUT(fp)
#elif defined(PRINT)
#include <stdio.h>
FILE *___log = NULL;
#define DBG(fmt, args...) \
	{if (!___log) ___log = stderr; \
	 fprintf(___log, "[DBG:PMS]%s:%d:%s(): " fmt "\n",\
	 basename(__FILE__), __LINE__, __func__, ##args); fflush(___log); }
#define __SET_DBG_OUTPUT(fp) \
	(___log = fp)
#else
#include <dlog.h>
#undef LOG_TAG
#define LOG_TAG "PKGMGR_SERVER"

#define DBGE(fmt, arg...) LOGE(fmt,##arg)
#define DBG(fmt, arg...) LOGD(fmt,##arg)
#endif

#if !defined(PACKAGE)
#define PACKAGE "package-manager"
#endif

#if !defined(LOCALEDIR)
#define LOCALEDIR "/usr/share/locale"
#endif

#define PACKAGE_RECOVERY_DIR tzplatform_mkpath(TZ_SYS_RW_PACKAGES, ".recovery/pkgmgr")

#define DESKTOP_W   720.0

#define NO_MATCHING_FILE 11

static int backend_flag = 0;	/* 0 means that backend process is not running */
static int drawing_popup = 0;	/* 0 means that pkgmgr-server has no popup now */

typedef struct  {
	char **env;
	uid_t uid;
	gid_t gid;
} user_ctx;


/* For pkgs with no desktop file, inotify callback wont be called.
*  To handle that case ail_db_update is initialized as 1
*  This flag will be used to ensure that pkgmgr server does not exit
*  before the db is updated. */
int ail_db_update = 1;

/*
8 bit value to represent maximum 8 backends.
Each bit position corresponds to a queue slot which
is dynamically determined.
*/
char backend_busy = 0;
/*
8 bit value to represent quiet mode operation for maximum 8 backends
1->quiet 0->non-quiet
Each bit position corresponds to a queue slot which
is dynamically determined.
*/
char backend_mode = 63; /*00111111*/
extern int num_of_backends;

backend_info *begin;
extern queue_info_map *start;
extern int entries;
int pos = 0;
/*To store info in case of backend crash*/
char pname[MAX_PKG_NAME_LEN] = {'\0'};
char ptype[MAX_PKG_TYPE_LEN] = {'\0'};
char args[MAX_PKG_ARGS_LEN] = {'\0'};

GMainLoop *mainloop = NULL;


/* operation_type */
typedef enum {
	OPERATION_INSTALL = 0,
	OPERATION_UNINSTALL,
	OPERATION_ACTIVATE,
	OPERATION_REINSTALL,
	OPERATION_MAX
} OPERATION_TYPE;

typedef enum {
	PMSVC_ALL_APP = 0,
	PMSVC_UI_APP,
	PMSVC_SVC_APP
}pkgmgr_svc_app_component;

struct appdata {
	Evas_Object *win;
	Evas_Object *notify;
	pm_dbus_msg *item;
	OPERATION_TYPE op_type;
};

struct pm_desktop_notifier_t {
	int ifd;
	Ecore_Fd_Handler *handler;
};
typedef struct pm_desktop_notifier_t pm_desktop_notifier;

pm_desktop_notifier desktop_notifier;
pm_inotify_paths paths[DESKTOP_FILE_DIRS_NUM];
static int __check_backend_status_for_exit();
static int __check_queue_status_for_exit();
static int __check_backend_mode();
static int __is_backend_busy(int position);
static void __set_backend_busy(int position);
static void __set_backend_free(int position);
static int __is_backend_mode_quiet(int position);
static void __set_backend_mode(int position);
static void __unset_backend_mode(int position);
static void response_cb1(void *data, Evas_Object *notify, void *event_info);
static void response_cb2(void *data, Evas_Object *notify, void *event_info);
static int create_popup(struct appdata *ad);
static void sighandler(int signo);
static int __get_position_from_pkg_type(char *pkgtype);
static int __is_efl_tpk_app(char *pkgpath);
static int __xsystem(const char *argv[]);

gboolean queue_job(void *data);
gboolean send_fail_signal(void *data);
gboolean exit_server(void *data);
static Eina_Bool __directory_notify(void *data, Ecore_Fd_Handler *fd_handler);

/* To check whether a particular backend is free/busy*/
static int __is_backend_busy(int position)
{
	return backend_busy & 1<<position;
}
/*To set a particular backend as busy*/
static void __set_backend_busy(int position)
{
	backend_busy = backend_busy | 1<<position;
}
/*To set a particular backend as free */
static void __set_backend_free(int position)
{
	backend_busy = backend_busy & ~(1<<position);
}
/* To check whether a particular backend is running in quiet mode*/
static int __is_backend_mode_quiet(int position)
{
	return backend_mode & 1<<position;
}
/*To set a particular backend mode as quiet*/
static void __set_backend_mode(int position)
{
	backend_mode = backend_mode | 1<<position;
}
/*To unset a particular backend mode */
static void __unset_backend_mode(int position)
{
	backend_mode = backend_mode & ~(1<<position);
}

static void __set_recovery_mode(char *pkgid, char *pkg_type)
{
	char recovery_file[MAX_PKG_NAME_LEN] = { 0, };
	char buffer[MAX_PKG_NAME_LEN] = { 0 };
	char *pkgid_tmp = NULL;
	FILE *rev_file = NULL;

	if (pkgid == NULL) {
		DBG("pkgid is null\n");
		return;
	}

	/*if pkgid has a "/"charactor, that is a path name for installation, then extract pkgid from absolute path*/
	if (strstr(pkgid, "/")) {
		pkgid_tmp = strrchr(pkgid, '/') + 1;
		if (pkgid_tmp == NULL) {
			DBG("pkgid_tmp[%s] is null\n", pkgid);
			return;
		}
		snprintf(recovery_file, MAX_PKG_NAME_LEN, "%s/%s", PACKAGE_RECOVERY_DIR, pkgid_tmp);
	} else {
		snprintf(recovery_file, MAX_PKG_NAME_LEN, "%s/%s", PACKAGE_RECOVERY_DIR, pkgid);
	}

	rev_file = fopen(recovery_file, "w");
	if (rev_file== NULL) {
		DBG("rev_file[%s] is null\n", recovery_file);
		return;
	}

	snprintf(buffer, MAX_PKG_NAME_LEN, "pkgid : %s\n", pkgid);
	fwrite(buffer, sizeof(char), strlen(buffer), rev_file);

	fclose(rev_file);
}

static void __unset_recovery_mode(char *pkgid, char *pkg_type)
{
	int ret = -1;
	char recovery_file[MAX_PKG_NAME_LEN] = { 0, };
	char *pkgid_tmp = NULL;

	if (pkgid == NULL) {
		DBG("pkgid is null\n");
		return;
	}

	/*if pkgid has a "/"charactor, that is a path name for installation, then extract pkgid from absolute path*/
	if (strstr(pkgid, "/")) {
		pkgid_tmp = strrchr(pkgid, '/') + 1;
		if (pkgid_tmp == NULL) {
			DBG("pkgid_tmp[%s] is null\n", pkgid);
			return;
		}
		snprintf(recovery_file, MAX_PKG_NAME_LEN, "%s/%s", PACKAGE_RECOVERY_DIR, pkgid_tmp);
	} else {
		snprintf(recovery_file, MAX_PKG_NAME_LEN, "%s/%s", PACKAGE_RECOVERY_DIR, pkgid);
	}

	ret = remove(recovery_file);
	if (ret < 0)
		DBG("remove recovery_file[%s] fail\n", recovery_file);
}

static int __check_privilege_by_cookie(const char *e_cookie, int req_type)
{
	guchar *cookie = NULL;
	gsize size;
	int ret = PMINFO_R_OK;	//temp to success , it should be PMINFO_R_ERROR

	if (e_cookie == NULL)	{
		DBG("e_cookie is NULL!!!\n");
		return PMINFO_R_ERROR;
	}

	cookie = g_base64_decode(e_cookie, &size);
	if (cookie == NULL)	{
		DBG("Unable to decode cookie!!!\n");
		return PMINFO_R_ERROR;
	}

	switch (req_type) {
		case COMM_REQ_TO_INSTALLER:
			if (SECURITY_SERVER_API_SUCCESS == security_server_check_privilege_by_cookie(cookie, "pkgmgr::svc", "r"))
				ret = PMINFO_R_OK;

			break;

		case COMM_REQ_TO_MOVER:
			if (SECURITY_SERVER_API_SUCCESS == security_server_check_privilege_by_cookie(cookie, "pkgmgr::svc", "x"))
				ret = PMINFO_R_OK;
			break;

		case COMM_REQ_GET_SIZE:
			if (SECURITY_SERVER_API_SUCCESS == security_server_check_privilege_by_cookie(cookie, "pkgmgr::info", "r"))
				ret = PMINFO_R_OK;
			break;

		default:
			DBG("Check your request[%d]..\n", req_type);
			break;
	}

	DBG("security_server[req-type:%d] check cookie result = %d, \n", req_type, ret);

	if (cookie){
		g_free(cookie);
		cookie = NULL;
	}

	return ret;
}

static int __get_position_from_pkg_type(char *pkgtype)
{
	int i = 0;
	queue_info_map *ptr;
	ptr = start;
	for(i = 0; i < entries; i++)
	{
		if (!strncmp(ptr->pkgtype, pkgtype, MAX_PKG_TYPE_LEN))
			return ptr->queue_slot;
		else
			ptr++;

	}
	return -1;
}

static int __xsystem(const char *argv[])
{
        int err = 0;
        int status = 0;
        pid_t pid;

        pid = fork();

        switch (pid) {
        case -1:
                DBG("fork() failed");
                return -1;
        case 0:
                if (execvp(argv[0], (char *const *)argv) == -1) {
                        DBG("execvp() failed");
                }
                _exit(100);
        default:
                /* parent */
		do {
			err = waitpid(pid, &status, WUNTRACED | WCONTINUED);
			if (err == -1) {
				DBG("waitpid failed\n");
				return -1;
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
                break;
        }
	if (WIFEXITED(status))
	        return WEXITSTATUS(status);
	else
		return -1;
}

static int __is_efl_tpk_app(char *pkgid)
{
        int ret = 0;
        char *type = NULL;
	const char *unzip_argv[] = { "/usr/bin/unzip", "-j", pkgid, "usr/share/packages/*", "-d", "/tmp/efltpk-unzip", NULL };
	const char *unzip_opt_argv[] = { "/usr/bin/unzip", "-j", pkgid, "opt/share/packages/*", "-d", "/tmp/efltpk-unzip", NULL };
	const char *delete_argv[] = { "/bin/rm", "-rf", "/tmp/efltpk-unzip", NULL };
        pkgmgrinfo_pkginfo_h handle;
        /*Check for uninstall case. If we fail to get handle then request is for installation*/
        ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
        if (ret == PMINFO_R_OK) {
                ret = pkgmgrinfo_pkginfo_get_type(handle, &type);
                if (ret != PMINFO_R_OK) {
                        DBG("Failed to get package type\n");
                        pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
                        return -1;
                }
                if (strcmp(type, "efltpk") == 0) {
                        pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
                        return 1;
                } else {
                        pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
                        return 0;
                }
        }
        /*Install request*/
	if (strstr(pkgid, ".tpk") == NULL) {
		DBG("TPK package");
		return 0;
	}
        __xsystem(delete_argv);
        ret = mkdir("/tmp/efltpk-unzip", 0755);
        if (ret != 0) {
                DBG("Failed to create temporary directory to unzip tpk package\n");
                return -1;
        }
	/*In case of installation request, pkgid contains the pkgpath*/
	ret = __xsystem(unzip_argv);
	if (ret) {
		ret = __xsystem(unzip_opt_argv);
		if (ret) {
			DBG("Unzip of tpk package failed. error:%d\n", ret);
			if (ret == NO_MATCHING_FILE) /*no matching file found*/
				ret = 0;
			else
				ret = -1;
			goto err;
		} else
			ret = 1;
	} else
		ret = 1;
err:
        __xsystem(delete_argv);
        return ret;
}


static Eina_Bool __directory_notify(void *data, Ecore_Fd_Handler *fd_handler)
{
	ail_db_update = 0;
	char *buf = NULL;
	ssize_t read_size = 0;
	ssize_t len = 0;
	ssize_t i = 0;
	int fd = -1;

	fd = ecore_main_fd_handler_fd_get(fd_handler);
	DBG("ifd [%d]\n", fd);

	if (ioctl(fd, FIONREAD, &read_size) < 0) {
		DBG("Failed to get byte size\n");
		ail_db_update = 1;
		return ECORE_CALLBACK_CANCEL;
	}

	if (read_size <= 0) {
		DBG("Buffer is not ready!!!\n");
		ail_db_update = 1;
		return ECORE_CALLBACK_RENEW;
	}

	buf = calloc(1, read_size+1);
	if (!buf) {
		DBG("Failed to allocate memory for event handling\n");
		ail_db_update = 1;
		return ECORE_CALLBACK_RENEW;
	}

	len = read(fd, buf, read_size);
	if (len < 0) {
		free(buf);
		/*Stop monitoring about this invalid file descriptor */
		ail_db_update = 1;
		return ECORE_CALLBACK_CANCEL;
	}

	buf[len] = 0;

	while (i < len) {
		struct inotify_event *event = (struct inotify_event*) &buf[i];
		char *str_potksed = "potksed.";
		char *cut;
		char *package = NULL;
		ssize_t idx;
		int nev_name;

		/* 1. check the extension of a file */
		nev_name = strlen(event->name) - 1;
		for (idx = 0; nev_name >= 0 && str_potksed[idx]; idx++) {
			if (event->name[nev_name] != str_potksed[idx]) {
				break;
			}
			nev_name --;
		}

		if (str_potksed[idx] != '\0') {
			DBG("This is not a desktop file : %s\n", event->name);
			i += sizeof(struct inotify_event) + event->len;
			continue;
		}

		package = strdup(event->name);
		if (package == NULL)
			continue;

		cut = strstr(package, ".desktop");
		if (cut)
			*cut = '\0';
		DBG("Package : %s\n", package);

		/* add & update */
		if (event->mask & IN_CLOSE_WRITE || event->mask & IN_MOVED_TO) {
			ail_appinfo_h ai = NULL;
			ail_error_e ret;

			ret = ail_package_get_appinfo(package, &ai);
			if (ai)
				ail_package_destroy_appinfo(ai);

			if (AIL_ERROR_NO_DATA == ret) {
				if (ail_desktop_add(package) < 0) {
					DBG("Failed to add a new package (%s)\n", event->name);
				}
			} else if (AIL_ERROR_OK == ret) {
				if (ail_desktop_update(package) < 0) {
					DBG("Failed to add a new package (%s)\n", event->name);
				}
			} else;
			/* delete */
		} else if (event->mask & IN_DELETE) {
			if (ail_desktop_remove(package) < 0)
				DBG("Failed to remove a package (%s)\n",
				    event->name);
		} else {
			DBG("this event is not dealt with inotify\n");
		}

		free(package);

		i += sizeof(struct inotify_event) + event->len;
	}

	free(buf);
	ail_db_update = 1;
	return ECORE_CALLBACK_RENEW;
}

static
void response_cb1(void *data, Evas_Object *notify, void *event_info)
{
	struct appdata *ad = (struct appdata *)data;
	int p = 0;
	int ret = 0;
	DBG("start of response_cb()\n");

	/* YES  */
	DBG("Uninstalling... [%s]\n", ad->item->pkgid);

	if (strlen(ad->item->pkgid) == 0) {
		DBG("package_name is empty\n");
	}

	if (strlen(ad->item->pkg_type) == 0) {
		DBG("Fail :  Uninstalling... [%s]\n",
		    ad->item->pkgid);
		free(ad->item);
		evas_object_del(ad->notify);
		evas_object_del(ad->win);
		drawing_popup = 0;

		return;
	}

	DBG("pkg_type = [%s]\n", ad->item->pkg_type);

	ret = _pm_queue_push(ad->item);
	p = __get_position_from_pkg_type(ad->item->pkg_type);
	__unset_backend_mode(p);

	/* Free resource */
	free(ad->item);
	evas_object_del(ad->notify);
	evas_object_del(ad->win);
	/***************/
	if (ret == 0)
		g_idle_add(queue_job, NULL);

	DBG("end of response_cb()\n");

	drawing_popup = 0;

	return;
}

static
void response_cb2(void *data, Evas_Object *notify, void *event_info)
{
	int p = 0;
	struct appdata *ad = (struct appdata *)data;

	DBG("start of response_cb()\n");

	/* NO  */
	pkgmgr_installer *pi;
	gboolean ret_parse;
	gint argcp;
	gchar **argvp;
	GError *gerr = NULL;

	pi = pkgmgr_installer_new();
	if (!pi) {
		DBG("Failure in creating the pkgmgr_installer object");
		return;
	}

	ret_parse = g_shell_parse_argv(ad->item->args,
				       &argcp, &argvp, &gerr);
	if (FALSE == ret_parse) {
		DBG("Failed to split args: %s", ad->item->args);
		DBG("messsage: %s", gerr->message);
		pkgmgr_installer_free(pi);
		return;
	}

	pkgmgr_installer_receive_request(pi, argcp, argvp);

	pkgmgr_installer_send_signal(pi, ad->item->pkg_type,
				     ad->item->pkgid, "end",
				     "cancel");

	pkgmgr_installer_free(pi);
	p = __get_position_from_pkg_type(ad->item->pkg_type);
        __set_backend_mode(p);

	/* Free resource */
	free(ad->item);
	evas_object_del(ad->notify);
	evas_object_del(ad->win);
	/***************/
	/* queue_job should be called for every request that is pushed
	into queue. In "NO" case, request is not pushed so no need of
	calling queue_job*/

	DBG("end of response_cb()\n");

	drawing_popup = 0;

	return;
}

#if 0
static char *__get_exe_path(const char *pkgid)
{
	ail_appinfo_h handle;
	ail_error_e ret;
	char *str;
	char *exe_path;

	ret = ail_package_get_appinfo(pkgid, &handle);
	if (ret != AIL_ERROR_OK) {
		DBGE("ail_package_get_appinfo() failed");
		return NULL;
	}

	ret = ail_appinfo_get_str(handle, AIL_PROP_X_SLP_EXE_PATH, &str);
	if (ret != AIL_ERROR_OK) {
		DBGE("ail_appinfo_get_str() failed");
		ail_package_destroy_appinfo(handle);
		return NULL;
	}

	exe_path = strdup(str);
	if (exe_path == NULL) {
		DBGE("strdup() failed");
		ail_package_destroy_appinfo(handle);
		return NULL;
	}

	ret = ail_package_destroy_appinfo(handle);
	if (ret != AIL_ERROR_OK) {
		DBGE("ail_package_destroy_appinfo() failed");
		free(exe_path);
		return NULL;
	}

	return exe_path;
}
#endif

#ifdef HAVE_X11
static int __X_rotate_disable_focus(Display *dpy, Window win)
{
	XWMHints *hints;

	hints = XAllocWMHints();
	if (!hints) return -1;

	hints->flags = InputHint | StateHint;
	hints->input = 0;
	hints->initial_state = NormalState;

	XSetWMHints(dpy, win, hints);
	XFree(hints);

	return 0;
}

static int __X_rotate_get_window_property(Display *dpy, Window win, Atom atom,
					  Atom type, unsigned int *val,
					  unsigned int len)
{
	unsigned char *prop_ret;
	Atom type_ret;
	unsigned long bytes_after;
	unsigned long  num_ret;
	int format_ret;
	unsigned int i;
	int num;

	prop_ret = NULL;
	if (XGetWindowProperty(dpy, win, atom, 0, 0x7fffffff, False,
			       type, &type_ret, &format_ret, &num_ret,
			       &bytes_after, &prop_ret) != Success)
		return -1;

	if (type_ret != type || format_ret != 32)
		num = -1;
	else if (num_ret == 0 || !prop_ret)
		num = 0;
	else {
		if (num_ret < len)
			len = num_ret;
		for (i = 0; i < len; i++) {
			val[i] = ((unsigned long *)prop_ret)[i];
		}
		num = len;
	}

	if (prop_ret)
		XFree(prop_ret);

	return num;
}

static int __X_rotate_get_rotation(Display *dpy)
{
	Window active_win;
	Window root_win;
	int rotation = -1;
	int ret;


	Atom atom_active_win;
	Atom atom_win_rotate_angle;

	root_win = XDefaultRootWindow(dpy);

	atom_active_win = XInternAtom(dpy, "_NET_ACTIVE_WINDOW", False);
	ret = __X_rotate_get_window_property(dpy, root_win, atom_active_win,
					     XA_WINDOW,
					     (unsigned int *)&active_win, 1);
	if (ret < 0)
		return ret;

	atom_win_rotate_angle =
		XInternAtom(dpy, "_E_ILLUME_ROTATE_ROOT_ANGLE", False);
	ret = __X_rotate_get_window_property(dpy, root_win,
					  atom_win_rotate_angle, XA_CARDINAL,
					  (unsigned int *)&rotation, 1);

	if (ret != -1)
		return rotation;

	return -1;
}

static int __X_rotate_do_rotation(Window win)
{
	Display *d;
	int rotation;

	d = XOpenDisplay(NULL);

	rotation = __X_rotate_get_rotation(d);

	if (rotation == -1) {
		rotation = 0;
	}

	if (rotation >= 0)
		elm_win_rotation_with_resize_set(win, rotation);

	XCloseDisplay(d);

	return 0;
}

static Eina_Bool __X_rotate_cb(void *data, int type, void *event)
{
	Window win = (Window)data;
	Ecore_X_Event_Client_Message *ev = event;

	if (!event)
		return ECORE_CALLBACK_RENEW;

	if (ev->message_type == ECORE_X_ATOM_E_ILLUME_ROTATE_ROOT_ANGLE)
		__X_rotate_do_rotation(win);

	return ECORE_CALLBACK_RENEW;
}
#endif // HAVE_X11

static
int create_popup(struct appdata *ad)
{
	DBG("start of create_popup()\n");

	drawing_popup = 1;

	char sentence[MAX_PKG_ARGS_LEN] = { '\0' };
	char *pkgid = NULL;
	char app_name[MAX_PKG_NAME_LEN] = { '\0' };

	ad->win = elm_win_add(NULL, PACKAGE, ELM_WIN_DIALOG_BASIC);
	if (!ad->win) {
		DBG("Failed to create a new window\n");
		drawing_popup = 0;
		return -1;
	}

	elm_win_alpha_set(ad->win, EINA_TRUE);
	elm_win_title_set(ad->win, "test");
	elm_win_borderless_set(ad->win, EINA_TRUE);
	elm_win_raise(ad->win);

	int rotation = 0;
	int w;
	int h;
	int x;
	int y;
	unsigned char *prop_data = NULL;
	int count;
    int ret;

#ifdef HAVE_X11
	ecore_x_window_geometry_get(ecore_x_window_root_get(
					    ecore_x_window_focus_get()),
				    &x, &y, &w, &h);
	ret =
	    ecore_x_window_prop_property_get(ecore_x_window_root_get
				     (ecore_x_window_focus_get()),
				     ECORE_X_ATOM_E_ILLUME_ROTATE_ROOT_ANGLE,
				     ECORE_X_ATOM_CARDINAL,
				     32, &prop_data, &count);
	if (ret && prop_data)
		memcpy(&rotation, prop_data, sizeof(int));
	if (prop_data)
		free(prop_data);
	evas_object_resize(ad->win, w, h);
	evas_object_move(ad->win, x, y);
	if (rotation != -1)
		elm_win_rotation_with_resize_set(ad->win, rotation);

	__X_rotate_disable_focus(ecore_x_display_get(), ad->win);

	ecore_event_handler_add(ECORE_X_EVENT_CLIENT_MESSAGE,
				__X_rotate_cb, ad->win);
#endif // HAVE_X11

	double s;
	s = w / DESKTOP_W;
	elm_config_scale_set(s);

	evas_object_show(ad->win);

	ad->notify = elm_popup_add(ad->win);
	if (!ad->notify) {
		DBG("failed to create notify object\n");
		evas_object_del(ad->win);
		drawing_popup = 0;
		return -1;
	}

	/* Sentence of popup */
	pkgid = strrchr(ad->item->pkgid, '/') == NULL ?
	    ad->item->pkgid : strrchr(ad->item->pkgid, '/') + 1;

	if (ad->op_type == OPERATION_INSTALL) {
		snprintf(sentence, sizeof(sentence) - 1, _("Install?"));
	} else if (ad->op_type == OPERATION_UNINSTALL) {
		char *label = NULL;
		pkgmgrinfo_pkginfo_h handle;
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
		if (ret < 0){
			drawing_popup = 0;
			evas_object_del(ad->notify);
			evas_object_del(ad->win);
			return -1;
		}
		ret = pkgmgrinfo_pkginfo_get_label(handle, &label);
		if (ret < 0){
			drawing_popup = 0;
			evas_object_del(ad->notify);
			evas_object_del(ad->win);
			return -1;
		}

		snprintf(app_name, sizeof(app_name) - 1, label);
		ret = pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		if (ret < 0){
			drawing_popup = 0;
			evas_object_del(ad->notify);
			evas_object_del(ad->win);
			return -1;
		}

		pkgid = app_name;

		snprintf(sentence, sizeof(sentence) - 1, _("Uninstall?"));
	} else if (ad->op_type == OPERATION_REINSTALL) {
		snprintf(sentence, sizeof(sentence) - 1, _("Reinstall?"));
	} else
		snprintf(sentence, sizeof(sentence) - 1, _("Invalid request"));

	elm_object_part_text_set(ad->notify, "title,text", pkgid);
	evas_object_size_hint_weight_set(ad->notify, EVAS_HINT_EXPAND,
					 EVAS_HINT_EXPAND);

	evas_object_show(ad->notify);
	/***********************************/

	elm_object_text_set(ad->notify, sentence);

	Evas_Object *button1 = NULL;
	Evas_Object *button2 = NULL;

	button1 = elm_button_add(ad->notify);
	elm_object_text_set(button1, dgettext("sys_string", "IDS_COM_SK_YES"));
	elm_object_part_content_set(ad->notify, "button1", button1);
	evas_object_smart_callback_add(button1, "clicked", response_cb1, ad);

	button2 = elm_button_add(ad->notify);
	elm_object_text_set(button2, dgettext("sys_string", "IDS_COM_SK_NO"));
	elm_object_part_content_set(ad->notify, "button2", button2);
	evas_object_smart_callback_add(button2, "clicked", response_cb2, ad);

	evas_object_show(ad->notify);

	DBG("end of create_popup()\n");
	return 0;
}

gboolean send_fail_signal(void *data)
{
	DBG("send_fail_signal start\n");
	gboolean ret_parse;
	gint argcp;
	gchar **argvp;
	GError *gerr = NULL;
	pkgmgr_installer *pi;
	pi = pkgmgr_installer_new();
	if (!pi) {
		DBG("Failure in creating the pkgmgr_installer object");
		return FALSE;
	}
	ret_parse = g_shell_parse_argv(args,
				       &argcp, &argvp, &gerr);
	if (FALSE == ret_parse) {
		DBG("Failed to split args: %s", args);
		DBG("messsage: %s", gerr->message);
		pkgmgr_installer_free(pi);
		return FALSE;
	}

	pkgmgr_installer_receive_request(pi, argcp, argvp);
	pkgmgr_installer_send_signal(pi, ptype, pname, "end", "fail");
	pkgmgr_installer_free(pi);
	return FALSE;
}

static void sighandler(int signo)
{
	int status;
	pid_t cpid;
	int i = 0;
	backend_info *ptr = NULL;
	ptr = begin;

	while ((cpid = waitpid(-1, &status, WNOHANG)) > 0) {
		DBG("child exit [%d]\n", cpid);
		if (WIFEXITED(status)) {
			DBG("child NORMAL exit [%d]\n", cpid);
			for(i = 0; i < num_of_backends; i++)
			{
				if (cpid == (ptr + i)->pid) {
					__set_backend_free(i);
					__set_backend_mode(i);
					__unset_recovery_mode((ptr + i)->pkgid, (ptr + i)->pkgtype);
					break;
				}
			}
		}
		else if (WIFSIGNALED(status)) {
			DBG("child SIGNALED exit [%d]\n", cpid);
			/*get the pkgid and pkgtype to send fail signal*/
			for(i = 0; i < num_of_backends; i++)
			{
				if (cpid == (ptr + i)->pid) {
					__set_backend_free(i);
					__set_backend_mode(i);
					__unset_recovery_mode((ptr + i)->pkgid, (ptr + i)->pkgtype);
					strncpy(pname, (ptr + i)->pkgid, MAX_PKG_NAME_LEN-1);
					strncpy(ptype, (ptr + i)->pkgtype, MAX_PKG_TYPE_LEN-1);
					strncpy(args, (ptr + i)->args, MAX_PKG_ARGS_LEN-1);
					g_idle_add(send_fail_signal, NULL);
					break;
				}
			}
		}
	}

}

void req_cb(void *cb_data, uid_t uid, const char *req_id, const int req_type,
	    const char *pkg_type, const char *pkgid, const char *args,
	    const char *cookie, int *ret)
{
	static int sig_reg = 0;
	int err = -1;
	int p = 0;
	int cookie_result = 0;

	DBG(">> in callback >> Got request: [%s] [%d] [%s] [%s] [%s] [%s]",
	    req_id, req_type, pkg_type, pkgid, args, cookie);

	struct appdata *ad = (struct appdata *)cb_data;

	pm_dbus_msg *item = calloc(1, sizeof(pm_dbus_msg));
	memset(item, 0x00, sizeof(pm_dbus_msg));

	strncpy(item->req_id, req_id, sizeof(item->req_id) - 1);
	item->req_type = req_type;
	strncpy(item->pkg_type, pkg_type, sizeof(item->pkg_type) - 1);
	strncpy(item->pkgid, pkgid, sizeof(item->pkgid) - 1);
	strncpy(item->args, args, sizeof(item->args) - 1);
	strncpy(item->cookie, cookie, sizeof(item->cookie) - 1);
	item->uid = uid;
	if (sig_reg == 0) {
		struct sigaction act;

		act.sa_handler = sighandler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = SA_NOCLDSTOP;

		if (sigaction(SIGCHLD, &act, NULL) < 0) {
			DBG("signal: SIGCHLD failed\n");
		} else
			DBG("signal: SIGCHLD succeed\n");
		if (g_timeout_add_seconds(2, exit_server, NULL))
			DBG("g_timeout_add_seconds() Added to Main Loop");

		sig_reg = 1;
	}

	DBG("req_type=(%d) drawing_popup=(%d) backend_flag=(%d)\n", req_type,
	    drawing_popup, backend_flag);

	char *quiet = NULL;

	switch (item->req_type) {
	case COMM_REQ_TO_INSTALLER:
		/* check caller privilege */
		cookie_result = __check_privilege_by_cookie(cookie, item->req_type);
		if (cookie_result < 0){
			DBG("__check_privilege_by_cookie result fail[%d]\n", cookie_result);
			*ret = COMM_RET_ERROR;
			goto err;
		}

		/* -q option should be located at the end of command !! */
		if (((quiet = strstr(args, " -q")) &&
		     (quiet[strlen(quiet)] == '\0')) ||
		    ((quiet = strstr(args, " '-q'")) &&
		     (quiet[strlen(quiet)] == '\0'))) {
			/* quiet mode */
			err = _pm_queue_push(item);
			p = __get_position_from_pkg_type(item->pkg_type);
			__set_backend_mode(p);
			/* Free resource */
			free(item);
			if (err == 0)
				g_idle_add(queue_job, NULL);
			*ret = COMM_RET_OK;
		} else {
			/* non quiet mode */
			p = __get_position_from_pkg_type(item->pkg_type);
			if (drawing_popup == 0 &&
				!__is_backend_busy(p) &&
				__check_backend_mode()) {
				/* if there is no popup */
				ad->item = item;

				if (strstr(args, " -i ")
				    || strstr(args, " '-i' "))
					ad->op_type = OPERATION_INSTALL;
				else if (strstr(args, " -d ")
					 || strstr(args, " '-d' ")) {
					ad->op_type = OPERATION_UNINSTALL;

					/* 2011-04-01 
		   Change the mode temporarily. This should be removed */
					/*strncat(item->args, " -q",
						strlen(" -q"));*/
				} else if (strstr(args, " -r ")
					|| strstr(args, " '-r' "))
					ad->op_type = OPERATION_REINSTALL;
				else
					ad->op_type = OPERATION_MAX;

				err = create_popup(ad);
				if (err != 0) {
					*ret = COMM_RET_ERROR;
					DBG("create popup failed\n");
					/*queue_job(NULL);*/
					goto err;
				} else {
					*ret = COMM_RET_OK;
				}
			} else {
					DBG("info drawing_popup:%d, __is_backend_busy(p):%d, __check_backend_mode():%d\n",
					drawing_popup, __is_backend_busy(p), __check_backend_mode());
				/* if popup is already being drawn */
				*ret = COMM_RET_ERROR;
				goto err;
			}
		}
		break;
	case COMM_REQ_TO_ACTIVATOR:
		/* In case of activate, there is no popup */
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		/* Free resource */
		free(item);

/*		g_idle_add(queue_job, NULL); */
		if (err == 0)
			queue_job(NULL);
		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_TO_CLEARER:
		/* In case of clearer, there is no popup */
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		/*the backend shows the success/failure popup
		so this request is non quiet*/
		__unset_backend_mode(p);
		/* Free resource */
		free(item);

/*		g_idle_add(queue_job, NULL); */
		if (err == 0)
			queue_job(NULL);
		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_TO_MOVER:
		/* check caller privilege */
		cookie_result = __check_privilege_by_cookie(cookie, item->req_type);
		if (cookie_result < 0){
			DBG("__check_privilege_by_cookie result fail[%d]\n", cookie_result);
			*ret = COMM_RET_ERROR;
			goto err;
		}

		/* In case of mover, there is no popup */
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		/*the backend shows the success/failure popup
		so this request is non quiet*/
		__unset_backend_mode(p);
		/* Free resource */
		free(item);
		if (err == 0)
			queue_job(NULL);
		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_CANCEL:
		ad->item = item;
		_pm_queue_delete(ad->item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__unset_backend_mode(p);
		free(item);
		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_GET_SIZE:
		/* check caller privilege */
		cookie_result = __check_privilege_by_cookie(cookie, item->req_type);
		if (cookie_result < 0){
			DBG("__check_privilege_by_cookie result fail[%d]\n", cookie_result);
			*ret = COMM_RET_ERROR;
			goto err;
		}

		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		/* Free resource */
		free(item);
		if (err == 0)
			g_idle_add(queue_job, NULL);
		*ret = COMM_RET_OK;
		break;

	case COMM_REQ_CHECK_APP:
	case COMM_REQ_KILL_APP:
		/* In case of activate, there is no popup */
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		/* Free resource */
		free(item);

/*		g_idle_add(queue_job, NULL); */
		if (err == 0)
			queue_job(NULL);
		*ret = COMM_RET_OK;
		break;

	default:
		DBG("Check your request..\n");
		*ret = COMM_RET_ERROR;
		break;
	}
err:
	if (*ret == COMM_RET_ERROR) {
		DBG("Failed to handle request %s %s\n",item->pkg_type, item->pkgid);
		pkgmgr_installer *pi;
		gboolean ret_parse;
		gint argcp;
		gchar **argvp;
		GError *gerr = NULL;

		pi = pkgmgr_installer_new();
		if (!pi) {
			DBG("Failure in creating the pkgmgr_installer object");
			free(item);
			return;
		}

		ret_parse = g_shell_parse_argv(args, &argcp, &argvp, &gerr);
		if (FALSE == ret_parse) {
			DBG("Failed to split args: %s", args);
			DBG("messsage: %s", gerr->message);
			pkgmgr_installer_free(pi);
			free(item);
			return;
		}

		pkgmgr_installer_receive_request(pi, argcp, argvp);

		pkgmgr_installer_send_signal(pi, item->pkg_type,
					     item->pkgid, "end",
					     "fail");

		pkgmgr_installer_free(pi);

		free(item);
	}
	return;
}

static int __check_backend_mode()
{
	int i = 0;
	for(i = 0; i < num_of_backends; i++)
	{
		if (__is_backend_mode_quiet(i))
			continue;
		else
			return 0;
	}
	return 1;
}
static int __check_backend_status_for_exit()
{
	int i = 0;
	for(i = 0; i < num_of_backends; i++)
	{
		if (!__is_backend_busy(i))
			continue;
		else
			return 0;
	}
	return 1;
}

static int __check_queue_status_for_exit()
{
	pm_queue_data *head[MAX_QUEUE_NUM] = {NULL,};
	queue_info_map *ptr = NULL;
	ptr = start;
	int i = 0;
	int c = 0;
	int slot = -1;
	for(i = 0; i < entries; i++)
	{
		if (ptr->queue_slot <= slot) {
			ptr++;
			continue;
		}
		else {
			head[c] = ptr->head;
			slot = ptr->queue_slot;
			c++;
			ptr++;
		}
	}
	for(i = 0; i < num_of_backends; i++)
	{
		if (!head[i])
			continue;
		else
			return 0;
	}
	return 1;
}
gboolean exit_server(void *data)
{
	DBG("exit_server Start\n");
	if (__check_backend_status_for_exit() &&
                __check_queue_status_for_exit() &&
			drawing_popup == 0) {
                        if (!getenv("PMS_STANDALONE") && ail_db_update) {
                                ecore_main_loop_quit();
                                return FALSE;
                        }
        }
	return TRUE;
}


int __app_func(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int ret = 0;
	char *appid = NULL;
	int *data = (int *)user_data;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret != PMINFO_R_OK) {
		perror("fail to activate/deactivte package");
		exit(1);
	}

	ret = pkgmgrinfo_appinfo_set_state_enabled(appid, (*data));
	if (ret != PMINFO_R_OK) {
		perror("fail to activate/deactivte package");
		exit(1);
	}

	ret = ail_desktop_appinfo_modify_bool(appid,
				AIL_PROP_X_SLP_ENABLED_BOOL,
				(*data), TRUE);
	if (ret != AIL_ERROR_OK) {
		perror("fail to activate/deactivte package");
		exit(1);
	}
	return 0;
}

static int __pkgcmd_read_proc(const char *path, char *buf, int size)
{
	int fd;
	int ret;
	if (buf == NULL || path == NULL)
		return -1;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;
	close(fd);
	return ret;
}

static int __pkgcmd_find_pid_by_cmdline(const char *dname,
			const char *cmdline, const char *apppath)
{
	int pid = 0;

	if (strcmp(cmdline, apppath) == 0) {
		pid = atoi(dname);
		if (pid != getpgid(pid))
			pid = 0;
	}
	return pid;
}

static int __pkgcmd_proc_iter_kill_cmdline(const char *apppath, int option)
{
	DIR *dp;
	struct dirent *dentry;
	int pid;
	int ret;
	char buf[1024] = {'\0'};
	int pgid;

	dp = opendir("/proc");
	if (dp == NULL) {
		return -1;
	}

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		snprintf(buf, sizeof(buf), "/proc/%s/cmdline", dentry->d_name);
		ret = __pkgcmd_read_proc(buf, buf, sizeof(buf));
		if (ret <= 0)
			continue;

		pid = __pkgcmd_find_pid_by_cmdline(dentry->d_name, buf, apppath);
		if (pid > 0) {
			if (option == 0) {
				closedir(dp);
				return pid;
			}
			pgid = getpgid(pid);
			if (pgid <= 1) {
				closedir(dp);
				return -1;
			}
			if (killpg(pgid, SIGKILL) < 0) {
				closedir(dp);
				return -1;
			}
			closedir(dp);
			return pid;
		}
	}
	closedir(dp);
	return 0;
}

static int __pkgcmd_app_cb(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *exec = NULL;
	int ret = 0;
	int pid = -1;
	if (handle == NULL) {
		perror("appinfo handle is NULL\n");
		exit(1);
	}
	ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	if (ret) {
		perror("Failed to get app exec path\n");
		exit(1);
	}

	if (strcmp(user_data, "kill") == 0)
		pid = __pkgcmd_proc_iter_kill_cmdline(exec, 1);
	else if(strcmp(user_data, "check") == 0)
		pid = __pkgcmd_proc_iter_kill_cmdline(exec, 0);

	vconf_set_int(VCONFKEY_PKGMGR_STATUS, pid);

	return 0;
}


user_ctx* getUserContext(uid_t uid)
{
	/* we can use getpwnam because this is used only after a
	 * fork and just before an execv
	 * No concurrencial call can corrupt the data
	 * returned by getpwuid
	 */
	user_ctx *context_res;
	char ** env;
	struct passwd * pwd;
	int len;
	int ret = 0;

	pwd = getpwuid(uid);
	if (!pwd)
		return NULL;
	
	do {
		context_res = (user_ctx *)malloc(sizeof(user_ctx));
		if (!context_res) {
			ret = -1;
			break;
		}
		env = (char**)malloc(3* sizeof(char *));
		if (!env) {
			ret = -1;
			break;
		}
		// Build environment context
		len = snprintf(NULL,0, "HOME=%s", pwd->pw_dir);
		env[0] = (char*)malloc((len+1)* sizeof(char));
		if(env[0] == NULL) {
			ret = -1;
			break;
		}
		snprintf(env[0],len, "HOME=%s", pwd->pw_dir);
		len = snprintf(NULL,0, "USER=%s", pwd->pw_name);
		env[1] = (char*)malloc((len+1)* sizeof(char));
		if(env[1] == NULL) {
			ret = -1;
			break;
		}
		
		snprintf(env[1],len, "USER=%s", pwd->pw_name);
		env[2] = NULL;
	} while (0);
	
	if(ret == -1) {
		free(context_res);
		context_res = NULL;
		int i = 0;
		//env variable ends by NULL element
		while (env[i]) {
			free(env[i]);
			i++;
		}
		free(env);
		env = NULL;
	} else {
		context_res->env = env;
		context_res->uid = uid;
		context_res->gid = pwd->pw_gid;
	}
	return context_res;
}
  

gboolean queue_job(void *data)
{
	/* DBG("queue_job start"); */
	pm_dbus_msg *item;
	backend_info *ptr = NULL;
	ptr = begin;
	int x = 0;
	/* Pop a job from queue */
pop:
	if (!__is_backend_busy(pos % num_of_backends)) {
		item = _pm_queue_pop(pos % num_of_backends);
		pos = (pos + 1) % num_of_backends;
	}
	else {
		pos = (pos + 1) % num_of_backends;
		goto pop;
	}

	int ret = 0;
	char *backend_cmd = NULL;

	/* queue is empty and backend process is not running */
	if ( (item == NULL) || (item->req_type == -1) ) {
		if(item)
			free(item);
		goto pop;
	}
	__set_backend_busy((pos + num_of_backends - 1) % num_of_backends);
	__set_recovery_mode(item->pkgid, item->pkg_type);

	switch (item->req_type) {
	case COMM_REQ_TO_INSTALLER:
		DBG("installer start");
		_save_queue_status(item, "processing");
		DBG("saved queue status. Now try fork()");
		/*save pkg type and pkg name for future*/
		x = (pos + num_of_backends - 1) % num_of_backends;
		strncpy((ptr + x)->pkgtype, item->pkg_type, MAX_PKG_TYPE_LEN-1);
		strncpy((ptr + x)->pkgid, item->pkgid, MAX_PKG_NAME_LEN-1);
		strncpy((ptr + x)->args, item->args, MAX_PKG_ARGS_LEN-1);
		(ptr + x)->pid = fork();
		DBG("child forked [%d]\n", (ptr + x)->pid);

		switch ((ptr + x)->pid) {
		case 0:	/* child */
			DBG("before run _get_backend_cmd()");
			user_ctx* user_context; 
			/*Check for efl-tpk app*/
			backend_cmd = _get_backend_cmd(item->pkg_type);

			if (strcmp(item->pkg_type, "tpk") == 0) {
				ret = __is_efl_tpk_app(item->pkgid);
				if (ret == 1) {
					if (backend_cmd)
						free(backend_cmd);
					backend_cmd = _get_backend_cmd("efltpk");
				}
			}

			if (NULL == backend_cmd)
				break;

			DBG("Try to exec [%s][%s]", item->pkg_type,
			    backend_cmd);
			fprintf(stdout, "Try to exec [%s][%s]\n",
				item->pkg_type, backend_cmd);

			/* Create args vector
			 * req_id + pkgid + args
			 *
			 * vector size = # of args +
			 *(req_id + pkgid + NULL termination = 3)
			 * Last value must be NULL for execv.
			 */
			gboolean ret_parse;
			gint argcp;
			gchar **argvp;
			GError *gerr = NULL;
			ret_parse = g_shell_parse_argv(item->args,
						       &argcp, &argvp, &gerr);
			if (FALSE == ret_parse) {
				DBG("Failed to split args: %s", item->args);
				DBG("messsage: %s", gerr->message);
				exit(1);
			}

			/* Setup argument !!! */
			/*char **args_vector =
			   calloc(argcp + 4, sizeof(char *)); */
			char **args_vector = calloc(argcp + 1, sizeof(char *));
			/*args_vector[0] = strdup(backend_cmd);
			   args_vector[1] = strdup(item->req_id);
			   args_vector[2] = strdup(item->pkgid); */
			int arg_idx;
			for (arg_idx = 0; arg_idx < argcp; arg_idx++) {
				/* args_vector[arg_idx+3] = argvp[arg_idx]; */
				args_vector[arg_idx] = argvp[arg_idx];
			}

			/* dbg */
			/*for(arg_idx = 0; arg_idx < argcp+3; arg_idx++) { */
			for (arg_idx = 0; arg_idx < argcp + 1; arg_idx++) {
				DBG(">>>>>> args_vector[%d]=%s",
				    arg_idx, args_vector[arg_idx]);
			}

			/* Execute backend !!! */
			user_context = getUserContext(item->uid);
			if(user_context) {
				setgid(user_context->gid);
				setuid(item->uid);
				ret = execve(backend_cmd, args_vector,user_context->env);
			} else {
				ret = -1;
				perror("fail to retreive user context");
				exit(1);
			}
			/* Code below: exec failure. Should not be happened! */
			DBG(">>>>>> OOPS 2!!!");

			/* g_strfreev(args_vector); *//* FIXME: causes error */

			if (ret == -1) {
				perror("fail to exec");
				exit(1);
			}
			_save_queue_status(item, "done");
			if (NULL != backend_cmd)
				free(backend_cmd);
			exit(0);	/* exit */
			break;

		case -1:	/* error */
			fprintf(stderr, "Fail to execute fork()\n");
			exit(1);
			break;

		default:	/* parent */
			DBG("parent \n");
			_save_queue_status(item, "done");
			break;
		}
		break;
	case COMM_REQ_TO_ACTIVATOR:
		DBG("activator start");
		int val = 0;
		_save_queue_status(item, "processing");
		DBG("saved queue status. Now try fork()");
		/*save pkg type and pkg name for future*/
		x = (pos + num_of_backends - 1) % num_of_backends;
		strncpy((ptr + x)->pkgtype, item->pkg_type, MAX_PKG_TYPE_LEN-1);
		strncpy((ptr + x)->pkgid, item->pkgid, MAX_PKG_NAME_LEN-1);
		strncpy((ptr + x)->args, item->args, MAX_PKG_ARGS_LEN-1);
		(ptr + x)->pid = fork();
		DBG("child forked [%d]\n", (ptr + x)->pid);

		switch ((ptr + x)->pid) {
		case 0:	/* child */
			if (item->args[0] == '1')	/* activate */
				val = 1;
			else if (item->args[0] == '0')	/* deactivate */
				val = 0;
			else {
				DBG("error in args parameter:[%c]\n",
				    item->args[0]);
				exit(1);
			}

			DBG("activated val %d", val);

			gboolean ret_parse;
			gint argcp;
			gchar **argvp;
			GError *gerr = NULL;
			char *label = NULL;
			ret_parse = g_shell_parse_argv(item->args,
						       &argcp, &argvp, &gerr);
			if (FALSE == ret_parse) {
				DBG("Failed to split args: %s", item->args);
				DBG("messsage: %s", gerr->message);
				exit(1);
			}

			if (!strcmp(argvp[1], "APP")) { /* in case of application */
				DBG("(De)activate APP");
				int opt;
				while ((opt = getopt(argcp, argvp, "l:")) != -1) {
					switch (opt) {
					case 'l':
						label = strdup(optarg);
						DBG("activated label %s", label);
						break;
					default: /* '?' */
						DBGE("Incorrect argument %s\n", item->args);
						exit(1);
					}
				}

				ret = pkgmgrinfo_appinfo_set_state_enabled(item->pkgid, val);
				if (ret != PMINFO_R_OK) {
					perror("fail to activate/deactivte package");
					exit(1);
				}

				if (label) {
					ret = pkgmgrinfo_appinfo_set_default_label(item->pkgid, label);
					if (ret != PMINFO_R_OK) {
						perror("fail to activate/deactivte package");
						exit(1);
					}

					ret = ail_desktop_appinfo_modify_str(item->pkgid,
								AIL_PROP_NAME_STR,
								label, FALSE);
					if (ret != AIL_ERROR_OK) {
						perror("fail to activate/deactivte package");
						exit(1);
					}
					free(label);
				}

				ret = ail_desktop_appinfo_modify_bool(item->pkgid,
							AIL_PROP_X_SLP_ENABLED_BOOL,
							val, TRUE);
				if (ret != AIL_ERROR_OK) {
					perror("fail to activate/deactivte package");
					exit(1);
				}
			} else { /* in case of package */
				DBGE("(De)activate PKG[pkgid=%s, val=%d]", item->pkgid, val);
				char *manifest = NULL;
				manifest = pkgmgr_parser_get_manifest_file(item->pkgid);
				if (manifest == NULL) {
					DBGE("Failed to fetch package manifest file\n");
					exit(1);
				}
				DBGE("manifest : %s\n", manifest);

				if (val) {
					pkgmgrinfo_pkginfo_h handle;
					ret = pkgmgrinfo_pkginfo_get_pkginfo(item->pkgid, &handle);
					if (ret < 0) {
						ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
						if (ret < 0) {
							DBGE("insert in db failed\n");
						}

						ret = ail_desktop_add(item->pkgid);
						if (ret != AIL_ERROR_OK) {
							DBGE("fail to ail_desktop_add");
						}
					} else {
						pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
					}

					ret = pkgmgrinfo_appinfo_set_state_enabled(item->pkgid, val);
					if (ret != PMINFO_R_OK) {
						perror("fail to activate/deactivte package");
						exit(1);
					}

					ret = ail_desktop_appinfo_modify_bool(item->pkgid,
								AIL_PROP_X_SLP_ENABLED_BOOL,
								val, TRUE);
					if (ret != AIL_ERROR_OK) {
						perror("fail to ail_desktop_appinfo");
						exit(1);
					}
				}
				else
					ret = pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);

				if (ret < 0) {
					DBGE("insert in db failed\n");
					exit(1);
				}
			}

			_save_queue_status(item, "done");
			exit(0);
			break;

		case -1:	/* error */
			fprintf(stderr, "Fail to execute fork()\n");
			exit(1);
			break;

		default:	/* parent */
			DBG("parent exit\n");
			_save_queue_status(item, "done");
			break;
		}
		break;
	case COMM_REQ_TO_MOVER:
	case COMM_REQ_TO_CLEARER:
		DBG("cleaner start");
		_save_queue_status(item, "processing");
		DBG("saved queue status. Now try fork()");
		/*save pkg type and pkg name for future*/
		x = (pos + num_of_backends - 1) % num_of_backends;
		strncpy((ptr + x)->pkgtype, item->pkg_type, MAX_PKG_TYPE_LEN-1);
		strncpy((ptr + x)->pkgid, item->pkgid, MAX_PKG_NAME_LEN-1);
		strncpy((ptr + x)->args, item->args, MAX_PKG_ARGS_LEN-1);
		(ptr + x)->pid = fork();
		DBG("child forked [%d]\n", (ptr + x)->pid);

		switch ((ptr + x)->pid) {
		case 0:	/* child */
			DBG("before run _get_backend_cmd()");
			backend_cmd = _get_backend_cmd(item->pkg_type);
			if (NULL == backend_cmd)
				break;

			DBG("Try to exec [%s][%s]", item->pkg_type,
			    backend_cmd);
			fprintf(stdout, "Try to exec [%s][%s]\n",
				item->pkg_type, backend_cmd);

			/* Create args vector
			 * req_id + pkgid + args
			 *
			 * vector size = # of args +
			 *(req_id + pkgid + NULL termination = 3)
			 * Last value must be NULL for execv.
			 */
			gboolean ret_parse;
			gint argcp;
			gchar **argvp;
			GError *gerr = NULL;
			ret_parse = g_shell_parse_argv(item->args,
						       &argcp, &argvp, &gerr);
			if (FALSE == ret_parse) {
				DBG("Failed to split args: %s", item->args);
				DBG("messsage: %s", gerr->message);
				exit(1);
			}

			/* Setup argument !!! */
			/*char **args_vector =
			   calloc(argcp + 4, sizeof(char *)); */
			char **args_vector = calloc(argcp + 1, sizeof(char *));
			/*args_vector[0] = strdup(backend_cmd);
			   args_vector[1] = strdup(item->req_id);
			   args_vector[2] = strdup(item->pkgid); */
			int arg_idx;
			for (arg_idx = 0; arg_idx < argcp; arg_idx++) {
				/* args_vector[arg_idx+3] = argvp[arg_idx]; */
				args_vector[arg_idx] = argvp[arg_idx];
			}

			/* dbg */
			/*for(arg_idx = 0; arg_idx < argcp+3; arg_idx++) { */
			for (arg_idx = 0; arg_idx < argcp + 1; arg_idx++) {
				DBG(">>>>>> args_vector[%d]=%s",
				    arg_idx, args_vector[arg_idx]);
			}

			/* Execute backend !!! */
			ret = execv(backend_cmd, args_vector);

			/* Code below: exec failure. Should not be happened! */
			DBG(">>>>>> OOPS 2!!!");

			/* g_strfreev(args_vector); *//* FIXME: causes error */

			if (ret == -1) {
				perror("fail to exec");
				exit(1);
			}
			_save_queue_status(item, "done");
			if (NULL != backend_cmd)
				free(backend_cmd);
			exit(0);
			break;

		case -1:	/* error */
			fprintf(stderr, "Fail to execute fork()\n");
			exit(1);
			break;

		default:	/* parent */
			DBG("parent \n");
			_save_queue_status(item, "done");
			break;
		}
		break;

	case COMM_REQ_GET_SIZE:
		DBG("COMM_REQ_GET_SIZE pkgid = %s\n", item->pkgid);
		_save_queue_status(item, "processing");
		DBG("saved queue status. Now try fork()");
		/*save pkg type and pkg name for future*/
		x = (pos + num_of_backends - 1) % num_of_backends;
		strncpy((ptr + x)->pkgtype, item->pkg_type, MAX_PKG_TYPE_LEN-1);
		strncpy((ptr + x)->pkgid, item->pkgid, MAX_PKG_NAME_LEN-1);
		strncpy((ptr + x)->args, item->args, MAX_PKG_ARGS_LEN-1);
		(ptr + x)->pid = fork();
		DBG("child forked [%d]\n", (ptr + x)->pid);

		switch ((ptr + x)->pid) {
		case 0:	/* child */
			DBG("before run _get_backend_cmd()");
			backend_cmd = strdup("/usr/bin/pkg_getsize");
			if (NULL == backend_cmd)
				break;

			DBG("Try to exec [%s][%s]", item->pkg_type,
			    backend_cmd);
			fprintf(stdout, "Try to exec [%s][%s]\n",
				item->pkg_type, backend_cmd);

			/* Create args vector
			 * req_id + pkgid + args
			 *
			 * vector size = # of args +
			 *(req_id + pkgid + NULL termination = 3)
			 * Last value must be NULL for execv.
			 */
			gboolean ret_parse;
			gint argcp;
			gchar **argvp;
			GError *gerr = NULL;
			ret_parse = g_shell_parse_argv(item->args,
						       &argcp, &argvp, &gerr);
			if (FALSE == ret_parse) {
				DBG("Failed to split args: %s", item->args);
				DBG("messsage: %s", gerr->message);
				exit(1);
			}

			/* Setup argument !!! */
			/*char **args_vector =
			   calloc(argcp + 4, sizeof(char *)); */
			char **args_vector = calloc(argcp + 1, sizeof(char *));
			/*args_vector[0] = strdup(backend_cmd);
			   args_vector[1] = strdup(item->req_id);
			   args_vector[2] = strdup(item->pkgid); */
			int arg_idx;
			for (arg_idx = 0; arg_idx < argcp; arg_idx++) {
				/* args_vector[arg_idx+3] = argvp[arg_idx]; */
				args_vector[arg_idx] = argvp[arg_idx];
			}

			/* dbg */
			/*for(arg_idx = 0; arg_idx < argcp+3; arg_idx++) { */
			for (arg_idx = 0; arg_idx < argcp + 1; arg_idx++) {
				DBG(">>>>>> args_vector[%d]=%s",
				    arg_idx, args_vector[arg_idx]);
			}

			/* Execute backend !!! */
			ret = execv(backend_cmd, args_vector);

			/* Code below: exec failure. Should not be happened! */
			DBG(">>>>>> OOPS 2!!!");

			/* g_strfreev(args_vector); *//* FIXME: causes error */

			if (ret == -1) {
				perror("fail to exec");
				exit(1);
			}
			_save_queue_status(item, "done");
			if (NULL != backend_cmd)
				free(backend_cmd);
			exit(0);
			break;

		case -1:	/* error */
			fprintf(stderr, "Fail to execute fork()\n");
			exit(1);
			break;

		default:	/* parent */
			DBG("parent \n");
			_save_queue_status(item, "done");
			break;
		}
		break;

	case COMM_REQ_KILL_APP:
	case COMM_REQ_CHECK_APP:
		DBG("COMM_REQ_CHECK_APP start");
		_save_queue_status(item, "processing");
		DBG("saved queue status. Now try fork()");
		/*save pkg type and pkg name for future*/
		x = (pos + num_of_backends - 1) % num_of_backends;
		strncpy((ptr + x)->pkgtype, item->pkg_type, MAX_PKG_TYPE_LEN-1);
		strncpy((ptr + x)->pkgid, item->pkgid, MAX_PKG_NAME_LEN-1);
		strncpy((ptr + x)->args, item->args, MAX_PKG_ARGS_LEN-1);
		(ptr + x)->pid = fork();
		DBG("child forked [%d]\n", (ptr + x)->pid);

		switch ((ptr + x)->pid) {
		case 0:	/* child */
			DBG("child run parse argv()");

			pkgmgrinfo_pkginfo_h handle;
			ret = pkgmgrinfo_pkginfo_get_pkginfo(item->pkgid, &handle);
			if (ret < 0) {
				DBG("Failed to get handle\n");
				exit(1);
			}

			if (item->req_type == COMM_REQ_KILL_APP) {
				ret = pkgmgrinfo_appinfo_get_list(handle, PMSVC_UI_APP, __pkgcmd_app_cb, "kill");
				if (ret < 0) {
					DBG("pkgmgrinfo_appinfo_get_list() failed\n");
					pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
					exit(1);
				}
			} else if (item->req_type == COMM_REQ_CHECK_APP) {
				ret = pkgmgrinfo_appinfo_get_list(handle, PMSVC_UI_APP, __pkgcmd_app_cb, "check");
				if (ret < 0) {
					DBG("pkgmgrinfo_appinfo_get_list() failed\n");
					pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
					exit(1);
				}
			}

			pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

			_save_queue_status(item, "done");
			exit(0);
			break;

		case -1:	/* error */
			fprintf(stderr, "Fail to execute fork()\n");
			exit(1);
			break;

		default:	/* parent */
			DBG("parent exit\n");
			_save_queue_status(item, "done");
			break;
		}
		break;

	default:
		break;
	}

	free(item);

	return FALSE;
}

#define IS_WHITESPACE(CHAR) \
((CHAR == ' ' || CHAR == '\t' || CHAR == '\r' || CHAR == '\n') ? TRUE : FALSE)

void _app_str_trim(char *input)
{
	char *trim_str = input;

	if (input == NULL)
		return;

	while (*input != 0) {
		if (!IS_WHITESPACE(*input)) {
			*trim_str = *input;
			trim_str++;
		}
		input++;
	}

	*trim_str = 0;
	return;
}

char *_get_backend_cmd(char *type)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	char *command = NULL;
	int size = 0;
	fp = fopen(PKG_CONF_PATH, "r");
	if (fp == NULL) {
		return NULL;
	}

	char *path = NULL;
	while (fgets(buffer, 1024, fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		_app_str_trim(buffer);

		if ((path = strstr(buffer, PKG_BACKEND)) != NULL) {
			DBG("buffer [%s]", buffer);
			path = path + strlen(PKG_BACKEND);
			DBG("path [%s]", path);

			command =
			    (char *)malloc(sizeof(char) * strlen(path) +
					   strlen(type) + 1);
			if (command == NULL) {
				fclose(fp);
				return NULL;
			}

			size = strlen(path) + strlen(type) + 1;
			snprintf(command, size, "%s%s", path, type);
			command[strlen(path) + strlen(type)] = '\0';
			DBG("command [%s]", command);

			if (fp != NULL)
				fclose(fp);

			return command;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	return NULL;		/* cannot find proper command */
}

void _pm_desktop_file_monitor_init()
{
	int wd = 0;
	int i = 0;
	int ret = 0;

	desktop_notifier.ifd = inotify_init();
	if (desktop_notifier.ifd == -1) {
		DBG("inotify_init error: %s\n", strerror(errno));
		return;
	}

	ret = _pm_desktop_file_dir_search(paths, DESKTOP_FILE_DIRS_NUM);
	if (ret) {
		DBG("desktop file dir search failed\n");
		return;
	}

	for (i = 0; i < DESKTOP_FILE_DIRS_NUM && paths[i].path; i++) {
		DBG("Configuration file for desktop file monitoring [%s] is added\n", paths[i].path);
		if (access(paths[i].path, R_OK) != 0) {
			ecore_file_mkpath(paths[i].path);
			if (chmod(paths[i].path, 0777) == -1) {
				DBG("cannot chmod %s\n", paths[i].path);
			}
		}

		wd = inotify_add_watch(desktop_notifier.ifd, paths[i].path,
				       IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE);
		if (wd == -1) {
			DBG("inotify_add_watch error: %s\n", strerror(errno));
			close(desktop_notifier.ifd);
			return;
		}

		paths[i].wd = wd;
	}

	desktop_notifier.handler =
	    ecore_main_fd_handler_add(desktop_notifier.ifd, ECORE_FD_READ,
				      __directory_notify, NULL, NULL, NULL);
	if (!desktop_notifier.handler) {
		/* TODO: Handle me.. EXCEPTION!! */
		DBG("cannot add handler for inotify\n");
	}
}

void _pm_desktop_file_monitor_fini()
{
	register int i;

	if (desktop_notifier.handler) {
		ecore_main_fd_handler_del(desktop_notifier.handler);
		desktop_notifier.handler = NULL;
	}

	for (i = 0; i < DESKTOP_FILE_DIRS_NUM; i++) {
		if (paths[i].wd) {
			if (inotify_rm_watch(desktop_notifier.ifd, paths[i].wd)
			    < 0) {
				DBG("inotify remove watch failed\n");
			}
			paths[i].wd = 0;
		}
	}

	if (desktop_notifier.ifd) {
		close(desktop_notifier.ifd);
		desktop_notifier.ifd = -1;
	}
}


int _pm_desktop_file_dir_search(pm_inotify_paths *paths, int number)
{
	char *buf = NULL;
	char *noti_dir = NULL;
	char *saveptr = NULL;
	int len = 0;
	int i = 0;
	int fd = -1;
	int read_size = 0;

	fd = open(DESKTOP_FILE_DIRS, O_RDONLY);
	if (fd < 0) {
		DBG("Failed to open %s\n", DESKTOP_FILE_DIRS);
		return -EFAULT;
	}

	if (ioctl(fd, FIONREAD, &read_size) < 0) {
		DBG("Failed to get a size of %s file.\n", DESKTOP_FILE_DIRS);
		close(fd);
		return -EFAULT;
	}

	if (read_size <= 0) {
		DBG("Buffer is not ready.\n");
		close(fd);
		return -EFAULT;
	}

	buf = calloc(1, read_size+1);
	if (!buf) {
		DBG("Failed to allocate heap.\n");
		close(fd);
		return -EFAULT;
	}

	len = read(fd, buf, read_size);
	if (len < 0) {
		DBG("Failed to read.\n");
		close(fd);
		free(buf);
		return -EFAULT;
	}

	buf[len] = 0;

	noti_dir = strtok_r(buf, "\n", &saveptr);
	if (!noti_dir) {
		DBG("Failed to strtok for %s.\n", buf);
		close(fd);
		free(buf);
		return -EFAULT;
	}

	do {
		char *begin;

		begin = noti_dir;
		while (*begin != 0) {
			if (isspace(*begin))
				begin++;
			else
				break;
		}
		if (*begin == '#' || *begin == 0) {
			noti_dir = strtok_r(NULL, "\n", &saveptr);
			continue;
		}

		paths[i].path = strdup(begin);
		noti_dir = strtok_r(NULL, "\n", &saveptr);
		i++;
	} while (number > i && noti_dir);

	paths[i].path = NULL;
	close(fd);
	free(buf);

	return EXIT_SUCCESS;
}

/**< Called before main loop */
int app_create(void *user_data)
{
	/* printf("called app_create\n"); */
	return 0;
}

/**< Called after main loop */
int app_terminate(void *user_data)
{
	/* printf("called app_terminate\n"); */
	return 0;
}

/**< Called when every window goes back */
int app_pause(void *user_data)
{
	/* printf("called app_pause\n"); */
	return 0;
}

/**< Called when any window comes on top */
int app_resume(void *user_data)
{
	/* printf("called app_resume\n"); */
	return 0;
}

/**< Called at the first idler*/
int app_reset(bundle *b, void *user_data)
{
	/* printf("called app_reset\n"); */
	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fp_status = NULL;
	char buf[32] = { 0, };
	pid_t pid;
	char *backend_cmd = NULL;
	char *backend_name = NULL;
	backend_info *ptr = NULL;
	int r;

#ifdef HAVE_X11
    // If DISPLAY is not set then let it default to :0
    // so we can remove hacks in the service file
    // to set the env variable (which will blow up wayland)
    //
    // Passing overwrite as zero so it will not clobber an
    // existing value
    setenv("DISPLAY", ":0", 0);
#endif

	ecore_init();

	DBG("server start");

	if (argv[1]) {
		if (strcmp(argv[1], "init") == 0) {
			/* if current status is "processing", 
			   execute related backend with '-r' option */
			if (!(fp_status = fopen(STATUS_FILE, "r")))
				return 0;	/*if file is not exist, terminated. */

			fgets(buf, 32, fp_status);
			/* if processing <-- unintended termination */
			if (strcmp(buf, "processing") == 0) {
				pid = fork();

				if (pid == 0) {	/* child */
					fgets(buf, 32, fp_status);
					backend_cmd = _get_backend_cmd(buf);
					if (!backend_cmd) {	/* if NULL, */
						DBG("fail to get"
						    " backend command");
						goto err;
					}
					backend_name =
					    strrchr(backend_cmd, '/');

					execl(backend_cmd, backend_name, "-r",
					      NULL);
					if (backend_cmd)
						free(backend_cmd);
					fprintf(fp_status, " ");
 err:
					fclose(fp_status);
					exit(13);
				} else if (pid < 0) {	/* error */
					DBG("fork fail");
					fclose(fp_status);
					return 0;
				} else {	/* parent */

					DBG("parent end\n");
					fprintf(fp_status, " ");
					fclose(fp_status);
					return 0;
				}
			}
		}
	}

	r = _pm_queue_init();
	if (r) {
		DBG("Queue Initialization Failed\n");
		return -1;
	}

	/*Initialize inotify to monitor desktop file updates */
/*	_pm_desktop_file_monitor_init(); */

	/*Allocate memory for holding pid, pkgtype and pkgid*/
	ptr = (backend_info*)calloc(num_of_backends, sizeof(backend_info));
	if (ptr == NULL) {
		DBG("Malloc Failed\n");
		return -1;
	}
	memset(ptr, '\0', num_of_backends * sizeof(backend_info));
	begin = ptr;

	/* init internationalization */
	r = appcore_set_i18n(PACKAGE, LOCALEDIR);
	if (r)
		return -1;

	g_type_init();
	mainloop = g_main_loop_new(NULL, FALSE);
	ecore_main_loop_glib_integrate();

	struct appdata ad;
	struct appcore_ops ops;
	ops.create = app_create;
	ops.terminate = app_terminate;
	ops.pause = app_pause;
	ops.resume = app_resume;
	ops.reset = app_reset;
	ops.data = &ad;

	DBG("Main loop is created.");

	PkgMgrObject *pkg_mgr;
	pkg_mgr = g_object_new(PKG_MGR_TYPE_OBJECT, NULL);
	pkg_mgr_set_request_callback(pkg_mgr, req_cb, &ad);
	DBG("pkg_mgr object is created, and request callback is registered.");

/*      g_main_loop_run(mainloop); */
	appcore_efl_main(PACKAGE, &argc, &argv, &ops);

	DBG("Quit main loop.");
/*	_pm_desktop_file_monitor_fini(); */
	_pm_queue_final();
	/*Free backend info */
	if (begin) {
		free(begin);
		begin = NULL;
	}

	DBG("package manager server terminated.");

	return 0;
}
