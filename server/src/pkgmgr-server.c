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
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>

#include <glib.h>

#include <pkgmgr-info.h>
#include <pkgmgr/pkgmgr_parser.h>
#include <cynara-client.h>
#include <tzplatform_config.h>

#include "pkgmgr_installer.h"
#include "comm_pkg_mgr_server.h"
#include "pkgmgr-server.h"
#include "pm-queue.h"
#include "comm_config.h"
#include "package-manager.h"

#define BUFMAX 128
#define NO_MATCHING_FILE 11

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

static int backend_flag = 0;	/* 0 means that backend process is not running */

typedef struct  {
	char **env;
	uid_t uid;
	gid_t gid;
} user_ctx;


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

struct signal_info_t {
	pid_t pid;
	int status;
};

static int pipe_sig[2];
static GIOChannel *pipe_io;
static guint pipe_wid;

backend_info *begin;
extern queue_info_map *start;
extern int entries;
static cynara *p_cynara;

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

static int __check_backend_status_for_exit(void);
static int __check_queue_status_for_exit(void);
static int __is_backend_busy(int position);
static void __set_backend_busy(int position);
static void __set_backend_free(int position);
static void __set_backend_mode(int position);
static void __unset_backend_mode(int position);
static void sighandler(int signo);
static int __get_position_from_pkg_type(char *pkgtype);
static int __is_efl_tpk_app(char *pkgpath);
static int __xsystem(const char *argv[]);

gboolean queue_job(void *data);
gboolean exit_server(void *data);

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

static int __is_global(uid_t uid)
{
	return (uid == OWNER_ROOT || uid == GLOBAL_USER) ? 1 : 0;
}

static const char *__get_recovery_file_path(uid_t uid)
{
	const char *path;

	if (!__is_global(uid))
		tzplatform_set_user(uid);

	path = tzplatform_getenv(__is_global(uid)
			? TZ_SYS_RW_PACKAGES : TZ_USER_PACKAGES);

	tzplatform_reset_user();

	return path;
}

static void __set_recovery_mode(uid_t uid, char *pkgid, char *pkg_type)
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
		snprintf(recovery_file, sizeof(recovery_file), "%s/%s", __get_recovery_file_path(uid), pkgid_tmp);
	} else {
		snprintf(recovery_file, sizeof(recovery_file), "%s/%s", __get_recovery_file_path(uid), pkgid);
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

static void __unset_recovery_mode(uid_t uid, char *pkgid, char *pkg_type)
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
		snprintf(recovery_file, sizeof(recovery_file), "%s/%s", __get_recovery_file_path(uid), pkgid_tmp);
	} else {
		snprintf(recovery_file, sizeof(recovery_file), "%s/%s", __get_recovery_file_path(uid), pkgid);
	}

	ret = remove(recovery_file);
	if (ret < 0)
		DBG("remove recovery_file[%s] fail\n", recovery_file);
}

#define PRIVILEGE_PACKAGEMANAGER_ADMIN "http://tizen.org/privilege/packagemanager.admin"
#define PRIVILEGE_PACKAGEMANAGER_INFO  "http://tizen.org/privilege/packagemanager.info"
#define PRIVILEGE_PACKAGEMANAGER_NONE  "NONE"

static const char *__convert_req_type_to_privilege(int req_type)
{
	switch (req_type) {
	case COMM_REQ_TO_INSTALLER:
	case COMM_REQ_TO_ACTIVATOR:
	case COMM_REQ_TO_CLEARER:
	case COMM_REQ_TO_MOVER:
	case COMM_REQ_KILL_APP:
	case COMM_REQ_CLEAR_CACHE_DIR:
		return PRIVILEGE_PACKAGEMANAGER_ADMIN;
	case COMM_REQ_GET_SIZE:
	case COMM_REQ_CHECK_APP:
		return PRIVILEGE_PACKAGEMANAGER_INFO;
	case COMM_REQ_CANCEL:
	default:
		return PRIVILEGE_PACKAGEMANAGER_NONE;
	}
}

static int __check_privilege_by_cynara(const char *client, const char *session, const char *user, int req_type)
{
	int ret;
	const char *privilege;
	char buf[BUFMAX] = {0, };

	privilege = __convert_req_type_to_privilege(req_type);
	if (!strcmp(privilege, PRIVILEGE_PACKAGEMANAGER_NONE))
		return 0;

	ret = cynara_check(p_cynara, client, session, user, privilege);
	switch (ret) {
	case CYNARA_API_ACCESS_ALLOWED:
		DBG("%s(%s) from user %s privilege %s allowed", client, session, user, privilege);
		return 0;
	case CYNARA_API_ACCESS_DENIED:
		ERR("%s(%s) from user %s privilege %s denied", client, session, user, privilege);
		return -1;
	default:
		cynara_strerror(ret, buf, BUFMAX);
		ERR("cynara_check failed: %s", buf);
		return -1;
	}
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

static void send_fail_signal(char *pname, char *ptype, char *args)
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
		return;
	}
	ret_parse = g_shell_parse_argv(args,
				       &argcp, &argvp, &gerr);
	if (FALSE == ret_parse) {
		DBG("Failed to split args: %s", args);
		DBG("messsage: %s", gerr->message);
		pkgmgr_installer_free(pi);
		return;
	}

	pkgmgr_installer_receive_request(pi, argcp, argvp);
	pkgmgr_installer_send_signal(pi, ptype, pname, "end", "fail");
	pkgmgr_installer_free(pi);
	return;
}

static gboolean pipe_io_handler(GIOChannel *io, GIOCondition cond, gpointer data)
{
	int x;
	GError *err = NULL;
	GIOStatus s;
	gsize len;
	struct signal_info_t info;
	backend_info *ptr = begin;

	s = g_io_channel_read_chars(io, (gchar *)&info, sizeof(struct signal_info_t), &len, &err);
	if (s != G_IO_STATUS_NORMAL) {
		ERR("Signal pipe read failed: %s", err->message);
		g_error_free(err);
		return TRUE;
	}

	for (x = 0; x < num_of_backends; x++, ptr++) {
		if (ptr && ptr->pid == info.pid)
			break;
	}

	if (x == num_of_backends) {
		ERR("Unknown child exit");
		return -1;
	}

	__set_backend_free(x);
	__set_backend_mode(x);
	__unset_recovery_mode(ptr->uid, ptr->pkgid, ptr->pkgtype);
	if (WIFSIGNALED(info.status) || WEXITSTATUS(info.status)) {
		send_fail_signal(ptr->pkgid, ptr->pkgtype, ptr->args);
		DBG("backend[%s] exit with error", ptr->pkgtype);
	} else {
		DBG("backend[%s] exit", ptr->pkgtype);
	}

	g_idle_add(queue_job, NULL);

	return TRUE;
}

static int __init_backend_info(void)
{
	backend_info *ptr;

	/*Allocate memory for holding pid, pkgtype and pkgid*/
	ptr = (backend_info*)calloc(num_of_backends, sizeof(backend_info));
	if (ptr == NULL) {
		DBG("Malloc Failed\n");
		return -1;
	}
	begin = ptr;

	if (pipe(pipe_sig)) {
		ERR("create pipe failed");
		return -1;
	}

	pipe_io = g_io_channel_unix_new(pipe_sig[0]);
	g_io_channel_set_encoding(pipe_io, NULL, NULL);
	g_io_channel_set_buffered(pipe_io, FALSE);
	pipe_wid = g_io_add_watch(pipe_io, G_IO_IN, pipe_io_handler, NULL);

	return 0;
}

static void __fini_backend_info(void)
{
	g_source_remove(pipe_wid);
	g_io_channel_unref(pipe_io);
	close(pipe_sig[0]);
	close(pipe_sig[1]);

	/*Free backend info */
	free(begin);
}

static void sighandler(int signo)
{
	struct signal_info_t info;

	info.pid = waitpid(-1, &info.status, WNOHANG);
	if (write(pipe_sig[1], &info, sizeof(struct signal_info_t)) < 0)
		ERR("failed to write result: %s", strerror(errno));
}

static int __register_signal_handler(void)
{
	static int sig_reg = 0;
	struct sigaction act;

	if (sig_reg)
		return 0;

	act.sa_handler = sighandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &act, NULL) < 0) {
		ERR("signal: SIGCHLD failed\n");
		return -1;
	}

	g_timeout_add_seconds(2, exit_server, NULL);

	sig_reg = 1;
	return 0;
}

void req_cb(void *cb_data, uid_t uid, const char *req_id, const int req_type,
	    const char *pkg_type, const char *pkgid, const char *args,
	    const char *client, const char *session, const char *user, int *ret)
{
	int p;

	DBG(">> in callback >> Got request: [%s] [%d] [%s] [%s] [%s] [%s] [%s] [%s]",
	    req_id, req_type, pkg_type, pkgid, args, client, session, user);

	pm_dbus_msg *item = calloc(1, sizeof(pm_dbus_msg));
	memset(item, 0x00, sizeof(pm_dbus_msg));

	strncpy(item->req_id, req_id, sizeof(item->req_id) - 1);
	item->req_type = req_type;
	strncpy(item->pkg_type, pkg_type, sizeof(item->pkg_type) - 1);
	strncpy(item->pkgid, pkgid, sizeof(item->pkgid) - 1);
	strncpy(item->args, args, sizeof(item->args) - 1);
	item->uid = uid;
	/* uid equals to GLOBALUSER means that the installation or action is made at Global level.
	 * At this time, we are not able to check the credentials of this dbus message (due to gdbus API to implement the pkgmgr-server)
	 * So we cannot check if the user that makes request has permisssion to do it.
	 * Note theses CAPI could be used by deamon (user is root or system user) or web/native API framework (user id is one of regular users)
	 * In consequence a bug is filed :
	 *
	 * Logic has to be implmemented:
	 * RUID means the id of the user that make the request (retreived from credential of the message)
	 * UID is the uid in argument of the request
	 *
	 * if RUID == UID & UID is regular user == TRUE ==> Granted
	 * if UID == GLOBAL_USER & RUID is ADMIN == TRUE ==> Granted
	 * if RUID == (ROOT or System USER) & UID is Regular USER ==> Granted
	 * if UID != Regular USER & UID != GLOBAL USER  == TRUE ==> NOT GRANTED
	 * if RUID == Regular USER & UID != RUID == True ==> NOT GRANTED
	 *  */

	if (__register_signal_handler()) {
		ERR("failed to register signal handler");
		*ret = COMM_RET_ERROR;
		goto err;
	}
	g_idle_add(queue_job, NULL);

	DBG("req_type=(%d) backend_flag=(%d)\n", req_type, backend_flag);

	if (__check_privilege_by_cynara(client, session, user, item->req_type)) {
		*ret = PKGMGR_R_EPRIV;
		goto err;
	}

	switch (item->req_type) {
	case COMM_REQ_TO_INSTALLER:
		/* quiet mode */
		if (_pm_queue_push(item)) {
			ERR("failed to push queue item");
			*ret = COMM_RET_ERROR;
			goto err;
		}
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		/* Free resource */
		free(item);
		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_TO_ACTIVATOR:
		/* In case of activate, there is no popup */
		if (_pm_queue_push(item)) {
			ERR("failed to push queue item");
			*ret = COMM_RET_ERROR;
			goto err;
		}
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		/* Free resource */
		free(item);

		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_TO_CLEARER:
		/* In case of clearer, there is no popup */
		if (_pm_queue_push(item)) {
			ERR("failed to push queue item");
			*ret = COMM_RET_ERROR;
			goto err;
		}
		p = __get_position_from_pkg_type(item->pkg_type);
		/*the backend shows the success/failure popup
		so this request is non quiet*/
		__unset_backend_mode(p);
		/* Free resource */
		free(item);

		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_TO_MOVER:
		/* In case of mover, there is no popup */
		if (_pm_queue_push(item)) {
			ERR("failed to push queue item");
			*ret = COMM_RET_ERROR;
			goto err;
		}
		p = __get_position_from_pkg_type(item->pkg_type);
		/*the backend shows the success/failure popup
		so this request is non quiet*/
		__unset_backend_mode(p);
		/* Free resource */
		free(item);
		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_CANCEL:
		_pm_queue_delete(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__unset_backend_mode(p);
		free(item);
		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_GET_SIZE:
		if (_pm_queue_push(item)) {
			ERR("failed to push queue item");
			*ret = COMM_RET_ERROR;
			goto err;
		}
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		/* Free resource */
		free(item);
		*ret = COMM_RET_OK;
		break;

	case COMM_REQ_CHECK_APP:
	case COMM_REQ_KILL_APP:
		/* In case of activate, there is no popup */
		if (_pm_queue_push(item)) {
			ERR("failed to push queue item");
			*ret = COMM_RET_ERROR;
			goto err;
		}
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		/* Free resource */
		free(item);

		*ret = COMM_RET_OK;
		break;
	case COMM_REQ_CLEAR_CACHE_DIR:
		if (_pm_queue_push(item)) {
			ERR("failed to push queue item");
			*ret = COMM_RET_ERROR;
			goto err;
		}
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);

		*ret = PKGMGR_R_OK;
		break;

	default:
		DBG("Check your request..\n");
		*ret = COMM_RET_ERROR;
		break;
	}
err:
	if (*ret != COMM_RET_OK) {
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
static int __check_backend_status_for_exit(void)
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

static int __check_queue_status_for_exit(void)
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
			__check_queue_status_for_exit()) {
		if (!getenv("PMS_STANDALONE")) {
			g_main_loop_quit(mainloop);
			return FALSE;
		}
	}
	return TRUE;
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

static void __make_pid_info_file(char *req_key, int pid)
{
	FILE* file;
	int fd;
	char buf[MAX_PKG_TYPE_LEN] = {0};
	char info_file[PATH_MAX] = {'\0'};

	if(req_key == NULL)
		return;

	snprintf(info_file, PATH_MAX, "/tmp/%s", req_key);

	DBG("info_path(%s)", info_file);
	file = fopen(info_file, "w");
	if (file == NULL) {
		ERR("Couldn't open the file(%s)", info_file);
		return;
	}

	snprintf(buf, MAX_PKG_TYPE_LEN, "%d\n", pid);
	fwrite(buf, 1, strlen(buf), file);

	fflush(file);
	fd = fileno(file);
	fsync(fd);
	fclose(file);
}

static int __pkgcmd_app_cb(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *pkgid;
	char *exec;
	int ret;
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
	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	if (ret) {
		perror("Failed to get pkgid\n");
		exit(1);
	}

	if (strcmp(user_data, "kill") == 0)
		pid = __pkgcmd_proc_iter_kill_cmdline(exec, 1);
	else if(strcmp(user_data, "check") == 0)
		pid = __pkgcmd_proc_iter_kill_cmdline(exec, 0);

	__make_pid_info_file(pkgid, pid);

	return 0;
}

void free_user_context(user_ctx* ctx)
{
	char **env = NULL;
	int i = 0;
	if (!ctx)
		return;
	env = ctx->env;
	//env variable ends by NULL element
	while (env[i]) {
		free(env[i]);
		i++;
	}
	free(env);
	env = NULL;
	free(ctx);
}

int set_environement(user_ctx *ctx)
{
	int i = 0;
	int res = 0;
	char **env = NULL;
	if (!ctx)
		return -1;;
	if (setgid(ctx->gid)) {
		ERR("setgid failed: %d", errno);
		return -1;
	}
	if (setuid(ctx->uid)) {
		ERR("setuid failed: %d", errno);
		return -1;
	}
	env = ctx->env;
	//env variable ends by NULL element
	while (env[i]) {
		if (putenv(env[i]) != 0)
			res = -1;
		i++;
	}
	return res;
}

user_ctx* get_user_context(uid_t uid)
{
	/* we can use getpwnam because this is used only after a
	 * fork and just before an execv
	 * No concurrencial call can corrupt the data
	 * returned by getpwuid
	 */
	user_ctx *context_res;
	char **env = NULL;
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
		env[0] = (char*)malloc((len + 1)* sizeof(char));
		if(env[0] == NULL) {
			ret = -1;
			break;
		}
		sprintf(env[0], "HOME=%s", pwd->pw_dir);
		len = snprintf(NULL,0, "USER=%s", pwd->pw_name);
		env[1] = (char*)malloc((len + 1)* sizeof(char));
		if(env[1] == NULL) {
			ret = -1;
			break;
		}

		sprintf(env[1], "USER=%s", pwd->pw_name);
		env[2] = NULL;
	} while (0);

	if (ret == -1) {
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

static char **__generate_argv(const char *args)
{
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
	ret_parse = g_shell_parse_argv(args,
			&argcp, &argvp, &gerr);
	if (FALSE == ret_parse) {
		DBG("Failed to split args: %s", args);
		DBG("messsage: %s", gerr->message);
		exit(1);
	}

	/* Setup argument !!! */
	/*char **args_vector =
	  calloc(argcp + 4, sizeof(char *)); */
	char **args_vector = calloc(argcp + 1, sizeof(char *));
	if (args_vector == NULL) {
		ERR("Out of memory");
		exit(1);
	}
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

	return args_vector;
}

static void __exec_with_arg_vector(const char *cmd, char **argv, uid_t uid)
{
	user_ctx* user_context = get_user_context(uid);
	if(!user_context) {
		DBG("Failed to getenv for the user : %d", uid);
		exit(1);
	}
	if(set_environement(user_context)){
		DBG("Failed to set env for the user : %d", uid);
		exit(1);
	}
	free_user_context(user_context);

	/* Execute backend !!! */
	int ret = execv(cmd, argv);

	/* Code below: exec failure. Should not be happened! */
	DBG(">>>>>> OOPS 2!!!");

	/* g_strfreev(args_vector); *//* FIXME: causes error */

	if (ret == -1) {
		perror("fail to exec");
		exit(1);
	}
}

gboolean queue_job(void *data)
{
	pm_dbus_msg *item = NULL;
	backend_info *ptr;
	int x;
	int ret;
	char *backend_cmd = NULL;

	/* Pop a job from queue */
	for (x = 0, ptr = begin; x < num_of_backends; x++, ptr++) {
		if (__is_backend_busy(x))
			continue;

		item = _pm_queue_pop(x);
		if (item && item->req_type != -1)
			break;
		free(item);
	}

	/* all backend messages queue are empty or busy */
	if (x == num_of_backends)
		return FALSE;

	__set_backend_busy(x);
	__set_recovery_mode(item->uid, item->pkgid, item->pkg_type);

	/* fork */
	_save_queue_status(item, "processing");
	DBG("saved queue status. Now try fork()");
	/*save pkg type and pkg name for future*/
	strncpy(ptr->pkgtype, item->pkg_type, MAX_PKG_TYPE_LEN-1);
	strncpy(ptr->pkgid, item->pkgid, MAX_PKG_NAME_LEN-1);
	strncpy(ptr->args, item->args, MAX_PKG_ARGS_LEN-1);
	ptr->uid = item->uid;
	ptr->pid = fork();
	DBG("child forked [%d] for request type [%d]", ptr->pid, item->req_type);

	switch (ptr->pid) {
	case 0:	/* child */
		switch (item->req_type) {
		case COMM_REQ_TO_INSTALLER:
			DBG("before run _get_backend_cmd()");
			/*Check for efl-tpk app*/
			backend_cmd = _get_backend_cmd(item->pkg_type);
			if (backend_cmd == NULL)
				break;

			if (strcmp(item->pkg_type, "tpk") == 0) {
				ret = __is_efl_tpk_app(item->pkgid);
				if (ret == 1) {
					if (backend_cmd)
						free(backend_cmd);
					backend_cmd = _get_backend_cmd("efltpk");
				}
			}

			DBG("Try to exec [%s][%s]", item->pkg_type, backend_cmd);
			fprintf(stdout, "Try to exec [%s][%s]\n", item->pkg_type, backend_cmd);

			char **args_vector = __generate_argv(item->args);
			args_vector[0] = backend_cmd;

			/* Execute backend !!! */
			__exec_with_arg_vector(backend_cmd, args_vector, item->uid);
			free(backend_cmd);
			break;
		case COMM_REQ_TO_ACTIVATOR:
			DBG("activator start");
			int val = 0;
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
			user_ctx* user_context = get_user_context(item->uid);
			if(!user_context) {
				DBG("Failed to getenv for the user : %d", item->uid);
				exit(1);
			}
			if(set_environement(user_context)){
				DBG("Failed to set env for the user : %d", item->uid);
				exit(1);
			}
			free_user_context(user_context);

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
						ERR("Incorrect argument %s\n", item->args);
						exit(1);
					}
				}

				ret = pkgmgrinfo_appinfo_set_usr_state_enabled(item->pkgid, val, item->uid);
				if (ret != PMINFO_R_OK) {
					perror("fail to activate/deactivte package");
					exit(1);
				}

				if (label) {
					ret = pkgmgrinfo_appinfo_set_usr_default_label(item->pkgid, label, item->uid);
					if (ret != PMINFO_R_OK) {
						perror("fail to activate/deactivte package");
						exit(1);
					}
					free(label);
				}
			} else { /* in case of package */
				ERR("(De)activate PKG[pkgid=%s, val=%d]", item->pkgid, val);
				char *manifest = NULL;
				manifest = pkgmgr_parser_get_manifest_file(item->pkgid);
				if (manifest == NULL) {
					ERR("Failed to fetch package manifest file\n");
					exit(1);
				}
				ERR("manifest : %s\n", manifest);

				if (val) {
					pkgmgrinfo_pkginfo_h handle;
					ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(item->pkgid, item->uid, &handle);
					if (ret < 0) {
						ret = pkgmgr_parser_parse_usr_manifest_for_installation(manifest,item->uid, NULL);
						if (ret < 0) {
							ERR("insert in db failed\n");
						}
					} else {
						pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
					}

					ret = pkgmgrinfo_appinfo_set_usr_state_enabled(item->pkgid, val, item->uid);
					if (ret != PMINFO_R_OK) {
						perror("fail to activate/deactivte package");
						exit(1);
					}
				}
				else
					ret = pkgmgr_parser_parse_usr_manifest_for_uninstallation(manifest, item->uid, NULL);

				if (ret < 0) {
					ERR("insert in db failed\n");
					exit(1);
				}
			}
			break;
		case COMM_REQ_TO_MOVER:
		case COMM_REQ_TO_CLEARER:
			DBG("cleaner start");
			DBG("before run _get_backend_cmd()");
			backend_cmd = _get_backend_cmd(item->pkg_type);
			if (NULL == backend_cmd)
				break;

			DBG("Try to exec [%s][%s]", item->pkg_type, backend_cmd);
			fprintf(stdout, "Try to exec [%s][%s]\n", item->pkg_type, backend_cmd);

			char **args_vectors = __generate_argv(item->args);
			args_vectors[0] = backend_cmd;

			/* Execute backend !!! */
			__exec_with_arg_vector(backend_cmd, args_vectors, item->uid);
			free(backend_cmd);
			break;
		case COMM_REQ_GET_SIZE:
			DBG("before run _get_backend_cmd()");
			__exec_with_arg_vector("usr/bin/pkg_getsize", __generate_argv(item->args), item->uid);
			break;
		case COMM_REQ_KILL_APP:
		case COMM_REQ_CHECK_APP:
			DBG("COMM_REQ_CHECK_APP start");
			pkgmgrinfo_pkginfo_h handle;
			ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(item->pkgid, item->uid, &handle);
			if (ret < 0) {
				DBG("Failed to get handle\n");
				exit(1);
			}

			if (item->req_type == COMM_REQ_KILL_APP) {
				ret = pkgmgrinfo_appinfo_get_usr_list(handle, PMSVC_ALL_APP, __pkgcmd_app_cb, "kill", item->uid);
				if (ret < 0) {
					DBG("pkgmgrinfo_appinfo_get_list() failed\n");
					pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
					exit(1);
				}
			} else if (item->req_type == COMM_REQ_CHECK_APP) {
				ret = pkgmgrinfo_appinfo_get_usr_list(handle, PMSVC_ALL_APP, __pkgcmd_app_cb, "check", item->uid);
				if (ret < 0) {
					DBG("pkgmgrinfo_appinfo_get_list() failed\n");
					pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
					exit(1);
				}
			}
			pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
			break;
		}
		/* exit child */
		_save_queue_status(item, "done");
		exit(0);
		break;

	case -1:
		fprintf(stderr, "Fail to execute_fork()\n");
		exit(1);

	default:	/* parent */
		DBG("parent exit\n");
		_save_queue_status(item, "done");
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

int main(int argc, char *argv[])
{
	FILE *fp_status = NULL;
	char buf[32] = { 0, };
	pid_t pid;
	char *backend_cmd = NULL;
	char *backend_name = NULL;
	int r;

	DBG("server start");

	if (argv[1] && (strcmp(argv[1], "init") == 0)) {
		/* if current status is "processing",
		   execute related backend with '-r' option */
		if (!(fp_status = fopen(STATUS_FILE, "r")))
			return 0;	/*if file is not exist, terminated. */
		/* if processing <-- unintended termination */
		if (fgets(buf, 32, fp_status) &&
				strcmp(buf, "processing") == 0) {
			pid = fork();
			if (pid == 0) {	/* child */
				if (fgets(buf, 32, fp_status))
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

	r = _pm_queue_init();
	if (r) {
		DBG("Queue Initialization Failed\n");
		return -1;
	}

	r = __init_backend_info();
	if (r) {
		DBG("backend info init failed");
		return -1;
	}

	r = cynara_initialize(&p_cynara, NULL);
	if (r != CYNARA_API_SUCCESS) {
		ERR("cynara initialize failed with code=%d", r);
		return -1;
	}

#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init();
#endif
	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		ERR("g_main_loop_new failed");
		return -1;
	}

	DBG("Main loop is created.");

	PkgMgrObject *pkg_mgr;
	pkg_mgr = g_object_new(PKG_MGR_TYPE_OBJECT, NULL);
	pkg_mgr_set_request_callback(pkg_mgr, req_cb, NULL);
	DBG("pkg_mgr object is created, and request callback is registered.");

	g_main_loop_run(mainloop);

	DBG("Quit main loop.");
	_pm_queue_final();
	__fini_backend_info();
	cynara_finish(p_cynara);

	DBG("package manager server terminated.");

	return 0;
}
