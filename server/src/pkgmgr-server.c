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
#include <Ecore_X.h>
#include <Ecore_File.h>
#include <ail.h>

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

#define DBGE(fmt, arg...) LOGE("[%s,%d] "fmt, __FUNCTION__, __LINE__, ##arg)
#define DBG(fmt, arg...) LOGD("[%s,%d] "fmt, __FUNCTION__, __LINE__, ##arg)
#endif

#if !defined(PACKAGE)
#define PACKAGE "package-manager"
#endif

#if !defined(LOCALEDIR)
#define LOCALEDIR "/usr/share/locale"
#endif

#define DESKTOP_W   720.0

static int backend_flag = 0;	/* 0 means that backend process is not running */
static int drawing_popup = 0;	/* 0 means that pkgmgr-server has no popup now */

/* For pkgs with no desktop file, inotify callback wont be called.
*  To handle that case ail_db_update is initialized as 1
*  This flag will be used to ensure that pkgmgr server does not exit
*  before the db is updated. */
int ail_db_update = 1;

GMainLoop *mainloop = NULL;

static const char *activate_cmd = "/usr/bin/activator";

/* operation_type */
typedef enum {
	OPERATION_INSTALL = 0,
	OPERATION_UNINSTALL,
	OPERATION_ACTIVATE,
	OPERATION_MAX
} OPERATION_TYPE;

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

static
void response_cb(void *data, Evas_Object *notify, void *event_info);
static
int create_popup(struct appdata *ad);
static void sighandler(int signo);
gboolean queue_job(void *data);
static Eina_Bool __directory_notify(void *data, Ecore_Fd_Handler *fd_handler);

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

	buf = malloc(read_size);
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
		*cut = '\0';
		DBG("Package : %s\n", package);

		/* add & update */
		if (event->mask & IN_CREATE || event->mask & IN_CLOSE_WRITE ||
		    event->mask & IN_MOVED_TO) {
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
void response_cb(void *data, Evas_Object *notify, void *event_info)
{
	struct appdata *ad = (struct appdata *)data;

	DBG("start of response_cb()\n");

	if ((int)event_info == ELM_POPUP_RESPONSE_OK) {	/* YES  */
		DBG("Uninstalling... [%s]\n", ad->item->pkg_name);

		if (strlen(ad->item->pkg_name) == 0) {
			DBG("package_name is empty\n");
		}

		if (strlen(ad->item->pkg_type) == 0) {
			DBG("Fail :  Uninstalling... [%s]\n",
			    ad->item->pkg_name);
			free(ad->item);
			evas_object_del(ad->notify);
			evas_object_del(ad->win);
			drawing_popup = 0;

			return;
		}

		DBG("pkg_type = [%s]\n", ad->item->pkg_type);

		_pm_queue_push(*(ad->item));

	} else {		/* NO  */
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
					     ad->item->pkg_name, "end",
					     "cancel");

		pkgmgr_installer_free(pi);
	}

	/* Free resource */
	free(ad->item);
	evas_object_del(ad->notify);
	evas_object_del(ad->win);
	/***************/

	g_idle_add(queue_job, NULL);

	DBG("end of response_cb()\n");

	drawing_popup = 0;

	return;
}

static char *__get_exe_path(const char *pkg_name)
{
	ail_appinfo_h handle;
	ail_error_e ret;
	char *str;
	char *exe_path;

	ret = ail_package_get_appinfo(pkg_name, &handle);
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
		return NULL;
	}

	return exe_path;
}

static
int create_popup(struct appdata *ad)
{
	DBG("start of create_popup()\n");

	drawing_popup = 1;

	char sentence[MAX_PKG_ARGS_LEN] = { '\0' };
	char *pkg_name = NULL;
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
	ecore_x_window_geometry_get(ecore_x_window_root_get(
					    ecore_x_window_focus_get()),
				    &x, &y, &w, &h);
	int ret =
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

	double s;
	s = w / DESKTOP_W;
	elm_scale_set(s);

	evas_object_show(ad->win);

	ad->notify = elm_popup_add(ad->win);
	if (!ad->notify) {
		DBG("failed to create notify object\n");
		evas_object_del(ad->win);
		drawing_popup = 0;
		return -1;
	}

	/* Sentence of popup */
	pkg_name = strrchr(ad->item->pkg_name, '/') == NULL ?
	    ad->item->pkg_name : strrchr(ad->item->pkg_name, '/') + 1;

	if (ad->op_type == OPERATION_INSTALL) {
		snprintf(sentence, sizeof(sentence) - 1, _("Install?"));
	} else if (ad->op_type == OPERATION_UNINSTALL) {

		ail_appinfo_h handle;
		ail_error_e ret;
		char *str;
		ret = ail_package_get_appinfo(pkg_name, &handle);
		if (ret != AIL_ERROR_OK) {
			drawing_popup = 0;
			evas_object_del(ad->notify);
			evas_object_del(ad->win);
			return -1;
		}

		ret = ail_appinfo_get_str(handle, AIL_PROP_NAME_STR, &str);
		if (ret != AIL_ERROR_OK) {
			ail_package_destroy_appinfo(handle);
			drawing_popup = 0;
			evas_object_del(ad->notify);
			evas_object_del(ad->win);
			return -1;
		}

		snprintf(app_name, sizeof(app_name) - 1, str);

		ret = ail_package_destroy_appinfo(handle);
		if (ret != AIL_ERROR_OK) {
			drawing_popup = 0;
			evas_object_del(ad->notify);
			evas_object_del(ad->win);
			return -1;
		}

		pkg_name = app_name;

		snprintf(sentence, sizeof(sentence) - 1, _("Uninstall?"));
	} else
		snprintf(sentence, sizeof(sentence) - 1, _("Invalid request"));

	elm_popup_title_label_set(ad->notify, pkg_name);
	evas_object_size_hint_weight_set(ad->notify, EVAS_HINT_EXPAND,
					 EVAS_HINT_EXPAND);
/*      elm_popup_mode_set(ad->notify, ELM_POPUP_TYPE_ALERT); */

	evas_object_show(ad->notify);
	/***********************************/

	elm_popup_desc_set(ad->notify, sentence);

	elm_popup_buttons_add(ad->notify, 2,
			      dgettext("sys_string", "IDS_COM_SK_YES"),
			      ELM_POPUP_RESPONSE_OK, dgettext("sys_string",
							      "IDS_COM_SK_NO"),
			      ELM_POPUP_RESPONSE_CANCEL, NULL);
	evas_object_smart_callback_add(ad->notify,
				       "response", response_cb, ad);

	evas_object_show(ad->notify);

	DBG("end of create_popup()\n");
	return 0;
}

static void sighandler(int signo)
{
	int status;
	pid_t pid;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		DBG("child exit [%d]\n", pid);
	}

	g_idle_add(queue_job, NULL);

	backend_flag = 0;
}

void req_cb(void *cb_data, const char *req_id, const int req_type,
	    const char *pkg_type, const char *pkg_name, const char *args,
	    const char *cookie, int *ret)
{
	static int sig_reg = 0;
	int err = -1;

	DBG(">> in callback >> Got request: [%s] [%d] [%s] [%s] [%s] [%s]",
	    req_id, req_type, pkg_type, pkg_name, args, cookie);

	struct appdata *ad = (struct appdata *)cb_data;

	pm_dbus_msg *item = calloc(1, sizeof(pm_dbus_msg));
	memset(item, 0x00, sizeof(pm_dbus_msg));

	strncpy(item->req_id, req_id, sizeof(item->req_id) - 1);
	item->req_type = req_type;
	strncpy(item->pkg_type, pkg_type, sizeof(item->pkg_type) - 1);
	strncpy(item->pkg_name, pkg_name, sizeof(item->pkg_name) - 1);
	strncpy(item->args, args, sizeof(item->args) - 1);
	strncpy(item->cookie, cookie, sizeof(item->cookie) - 1);

	if (sig_reg == 0) {
		struct sigaction act;

		act.sa_handler = sighandler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = SA_NOCLDSTOP;

		if (sigaction(SIGCHLD, &act, NULL) < 0) {
			DBG("signal: SIGCHLD failed\n");
		} else
			DBG("signal: SIGCHLD succeed\n");

		sig_reg = 1;
	}

	DBG("req_type=(%d) drawing_popup=(%d) backend_flag=(%d)\n", req_type,
	    drawing_popup, backend_flag);

	char *quiet = NULL;

	switch (item->req_type) {
	case COMM_REQ_TO_INSTALLER:
		/* -q option should be located at the end of command !! */
		if (((quiet = strstr(args, " -q")) &&
		     (quiet[strlen(quiet)] == '\0')) ||
		    ((quiet = strstr(args, " '-q'")) &&
		     (quiet[strlen(quiet)] == '\0'))) {
			/* quiet mode */
			_pm_queue_push(*item);
			/* Free resource */
			free(item);

			g_idle_add(queue_job, NULL);
			*ret = COMM_RET_OK;
		} else {
			/* non quiet mode */
			if (drawing_popup == 0 && backend_flag == 0) {
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
				} else
					ad->op_type = OPERATION_MAX;

				err = create_popup(ad);
				if (err != 0) {
					*ret = COMM_RET_ERROR;
					DBG("create popup failed\n");
					queue_job(NULL);
					return;
				} else {
					*ret = COMM_RET_OK;
				}
			} else {
				/* if popup is already being drawn */
				free(item);
				*ret = COMM_RET_ERROR;
			}
		}
		break;
	case COMM_REQ_TO_ACTIVATOR:
		/* In case of activate, there is no popup */
		_pm_queue_push(*item);
		/* Free resource */
		free(item);

/*		g_idle_add(queue_job, NULL); */
		queue_job(NULL);
		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_TO_CLEARER:
		/* In case of activate, there is no popup */
		_pm_queue_push(*item);
		/* Free resource */
		free(item);

/*		g_idle_add(queue_job, NULL); */
		queue_job(NULL);
		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_CANCEL:
		ad->item = item;
		_pm_queue_delete(*(ad->item));
		free(item);
		*ret = COMM_RET_OK;
		break;
	default:
		DBG("Check your request..\n");
		free(item);
		*ret = COMM_RET_ERROR;
		break;
	}
}

gboolean queue_job(void *data)
{
	/* DBG("queue_job start"); */

	/* Pop a job from queue */
	pm_dbus_msg item = _pm_queue_get_head();
	pid_t pid;
	int ret = 0;
	char *backend_cmd = NULL;
	char *exe_path = NULL;

	DBG("item.req_type=(%d) backend_flag=(%d)\n", item.req_type,
	    backend_flag);

	/* queue is empty and backend process is not running, quit */
	if ((item.req_type == -1) && (backend_flag == 0) &&
	    drawing_popup == 0 && ail_db_update == 1) {
		if (!getenv("PMS_STANDALONE"))
			ecore_main_loop_quit();	/* Quit main loop:
						   go to cleanup */
		return FALSE;	/* Anyway, run queue_job() again. */
	} else if (backend_flag == 1)	/* backend process is running */
		return FALSE;

	_pm_queue_pop();

	switch (item.req_type) {
	case COMM_REQ_TO_INSTALLER:
		DBG("installer start");
		_save_queue_status(item, "processing");
		DBG("saved queue status. Now try fork()");
		pid = fork();

		switch (pid) {
		case 0:	/* child */
			DBG("before run _get_backend_cmd()");
			backend_cmd = _get_backend_cmd(item.pkg_type);
			if (NULL == backend_cmd)
				break;

			DBG("Try to exec [%s][%s]", item.pkg_type,
			    backend_cmd);
			fprintf(stdout, "Try to exec [%s][%s]\n",
				item.pkg_type, backend_cmd);

			/* Create args vector
			 * req_id + pkg_name + args
			 *
			 * vector size = # of args +
			 *(req_id + pkg_name + NULL termination = 3)
			 * Last value must be NULL for execv.
			 */
			gboolean ret_parse;
			gint argcp;
			gchar **argvp;
			GError *gerr = NULL;
			ret_parse = g_shell_parse_argv(item.args,
						       &argcp, &argvp, &gerr);
			if (FALSE == ret_parse) {
				DBG("Failed to split args: %s", item.args);
				DBG("messsage: %s", gerr->message);
				exit(1);
			}

			/* Setup argument !!! */
			/*char **args_vector =
			   calloc(argcp + 4, sizeof(char *)); */
			char **args_vector = calloc(argcp + 1, sizeof(char *));
			/*args_vector[0] = strdup(backend_cmd);
			   args_vector[1] = strdup(item.req_id);
			   args_vector[2] = strdup(item.pkg_name); */
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
				exit(SIGCHLD);
			}
			_save_queue_status(item, "done");
			if (NULL != backend_cmd)
				free(backend_cmd);
			exit(SIGCHLD);	/* exit with SIGCHLD */
			break;

		case -1:	/* error */
			fprintf(stderr, "Fail to execute fork()\n");
			exit(1);
			break;

		default:	/* parent */
			backend_flag = 1;
			DBG("parent \n");
			_save_queue_status(item, "done");
			break;
		}
		break;
	case COMM_REQ_TO_ACTIVATOR:
		DBG("activator start");
		_save_queue_status(item, "processing");
		DBG("saved queue status. Now try fork()");
		pid = fork();

		switch (pid) {
		case 0:	/* child */
			/* Execute Activator !!! */
			exe_path = __get_exe_path(item.pkg_name);
			if (exe_path == NULL)
				break;

			if (item.args[0] == '1')	/* activate */
				ret = chmod(exe_path, 0755);
			else if (item.args[0] == '0')	/* deactivate */
				ret = chmod(exe_path, 0000);
			else {
				DBG("error in args parameter:[%c]\n",
				    item.args[0]);
				exit(SIGCHLD);
			}

			free(exe_path);

			if (ret == -1) {
				perror("fail to exec");
				exit(SIGCHLD);
			}
			_save_queue_status(item, "done");
			exit(SIGCHLD);	/* exit with SIGCHLD */
			break;

		case -1:	/* error */
			fprintf(stderr, "Fail to execute fork()\n");
			exit(1);
			break;

		default:	/* parent */
			backend_flag = 1;
			DBG("parent exit\n");
			_save_queue_status(item, "done");
			break;
		}
		break;
	case COMM_REQ_TO_CLEARER:
		DBG("cleaner start");
		_save_queue_status(item, "processing");
		DBG("saved queue status. Now try fork()");
		pid = fork();

		switch (pid) {
		case 0:	/* child */
			DBG("before run _get_backend_cmd()");
			backend_cmd = _get_backend_cmd(item.pkg_type);
			if (NULL == backend_cmd)
				break;

			DBG("Try to exec [%s][%s]", item.pkg_type,
			    backend_cmd);
			fprintf(stdout, "Try to exec [%s][%s]\n",
				item.pkg_type, backend_cmd);

			/* Create args vector
			 * req_id + pkg_name + args
			 *
			 * vector size = # of args +
			 *(req_id + pkg_name + NULL termination = 3)
			 * Last value must be NULL for execv.
			 */
			gboolean ret_parse;
			gint argcp;
			gchar **argvp;
			GError *gerr = NULL;
			ret_parse = g_shell_parse_argv(item.args,
						       &argcp, &argvp, &gerr);
			if (FALSE == ret_parse) {
				DBG("Failed to split args: %s", item.args);
				DBG("messsage: %s", gerr->message);
				exit(1);
			}

			/* Setup argument !!! */
			/*char **args_vector =
			   calloc(argcp + 4, sizeof(char *)); */
			char **args_vector = calloc(argcp + 1, sizeof(char *));
			/*args_vector[0] = strdup(backend_cmd);
			   args_vector[1] = strdup(item.req_id);
			   args_vector[2] = strdup(item.pkg_name); */
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
				exit(SIGCHLD);
			}
			_save_queue_status(item, "done");
			if (NULL != backend_cmd)
				free(backend_cmd);
			exit(SIGCHLD);	/* exit with SIGCHLD */
			break;

		case -1:	/* error */
			fprintf(stderr, "Fail to execute fork()\n");
			exit(1);
			break;

		default:	/* parent */
			backend_flag = 1;
			DBG("parent \n");
			_save_queue_status(item, "done");
			break;
		}
		break;
	default:
		break;
	}

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
				       IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO
				       | IN_DELETE);
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
		return -EFAULT;
	}

	if (read_size <= 0) {
		DBG("Buffer is not ready.\n");
		return -EFAULT;
	}

	buf = malloc(read_size);
	if (!buf) {
		DBG("Failed to allocate heap.\n");
		return -EFAULT;
	}

	len = read(fd, buf, read_size);
	if (len < 0) {
		DBG("Failed to read.\n");
		free(buf);
		return -EFAULT;
	}

	noti_dir = strtok_r(buf, "\n", &saveptr);
	if (!noti_dir) {
		DBG("Failed to strtok for %s.\n", buf);
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
	int r;

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

	_pm_queue_init();
	/*Initialize inotify to monitor desktop file updates */
	_pm_desktop_file_monitor_init();

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

/*      g_timeout_add_seconds(1, queue_job, NULL); */
	DBG("queue function is added to idler. Now run main loop.");

/*      g_main_loop_run(mainloop); */
	appcore_efl_main(PACKAGE, &argc, &argv, &ops);

	DBG("Quit main loop.");
	_pm_desktop_file_monitor_fini();
	_pm_queue_final();

	DBG("package manager server terminated.");

	return 0;
}
