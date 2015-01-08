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
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <ail.h>
#include <vconf.h>
#include <db-util.h>
#include <pkgmgr-info.h>
#include <iniparser.h>
#include <security-server.h>

/* For multi-user support */
#include <tzplatform_config.h>

#include "package-manager.h"
#include "pkgmgr-internal.h"
#include "pkgmgr-debug.h"
#include "pkgmgr-api.h"
#include "comm_client.h"
#include "comm_status_broadcast_server.h"

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR"
#endif				/* LOG_TAG */

#define PKG_TMP_PATH tzplatform_mkpath(TZ_USER_APP, "tmp")

#define BINSH_NAME	"/bin/sh"
#define BINSH_SIZE	7

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

static int _get_request_id()
{
	static int internal_req_id = 1;

	return internal_req_id++;
}

typedef struct _req_cb_info {
	int request_id;
	char *req_key;
	pkgmgr_handler event_cb;
	void *data;
	struct _req_cb_info *next;
} req_cb_info;

typedef struct _listen_cb_info {
	int request_id;
	pkgmgr_handler event_cb;
	void *data;
	struct _listen_cb_info *next;
} listen_cb_info;

typedef struct _pkgmgr_client_t {
	client_type ctype;
	int status_type;
	union {
		struct _request {
			comm_client *cc;
			req_cb_info *rhead;
		} request;
		struct _listening {
			comm_client *cc;
			listen_cb_info *lhead;
		} listening;
		struct _broadcast {
			DBusConnection *bc;
		} broadcast;
	} info;
	void *new_event_cb;
} pkgmgr_client_t;

typedef struct _iter_data {
	pkgmgr_iter_fn iter_fn;
	void *data;
} iter_data;

static char *__get_cookie_from_security_server(void)
{
	int ret = 0;
	size_t cookie_size = 0;
	char *e_cookie = NULL;

	//calculage cookie size
	cookie_size = security_server_get_cookie_size();
	retvm_if(cookie_size <= 0, NULL, "security_server_get_cookie_size : cookie_size is %d", cookie_size);

	//get cookie from security server
	char cookie[cookie_size];
	cookie[0] = '\0';
	ret = security_server_request_cookie(cookie, cookie_size);
	retvm_if(ret < 0, NULL, "security_server_request_cookie fail (%d)", ret);

	//encode cookie
	e_cookie = g_base64_encode((const guchar *)cookie, cookie_size);
	retvm_if(e_cookie == NULL, NULL, "g_base64_encode e_cookie is NULL");

	return e_cookie;
}

static int __xsystem(const char *argv[])
{
	int status = 0;
	pid_t pid;
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:
		/* child */
		execvp(argv[0], (char *const *)argv);
		_exit(-1);
	default:
		/* parent */
		break;
	}
	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid failed");
		return -1;
	}
	if (WIFSIGNALED(status)) {
		perror("signal");
		return -1;
	}
	if (!WIFEXITED(status)) {
		/* shouldn't happen */
		perror("should not happen");
		return -1;
	}
	return WEXITSTATUS(status);
}

static void __error_to_string(int errnumber, char **errstr)
{
	if (errstr == NULL)
		return;
	switch (errnumber) {
	case PKGCMD_ERR_PACKAGE_NOT_FOUND:
		*errstr = PKGCMD_ERR_PACKAGE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_PACKAGE_INVALID:
		*errstr = PKGCMD_ERR_PACKAGE_INVALID_STR;
		break;
	case PKGCMD_ERR_PACKAGE_LOWER_VERSION:
		*errstr = PKGCMD_ERR_PACKAGE_LOWER_VERSION_STR;
		break;
	case PKGCMD_ERR_PACKAGE_EXECUTABLE_NOT_FOUND:
		*errstr = PKGCMD_ERR_PACKAGE_EXECUTABLE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_MANIFEST_INVALID:
		*errstr = PKGCMD_ERR_MANIFEST_INVALID_STR;
		break;
	case PKGCMD_ERR_CONFIG_NOT_FOUND:
		*errstr = PKGCMD_ERR_CONFIG_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_CONFIG_INVALID:
		*errstr = PKGCMD_ERR_CONFIG_INVALID_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_NOT_FOUND:
		*errstr = PKGCMD_ERR_SIGNATURE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_INVALID:
		*errstr = PKGCMD_ERR_SIGNATURE_INVALID_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_VERIFICATION_FAILED:
		*errstr = PKGCMD_ERR_SIGNATURE_VERIFICATION_FAILED_STR;
		break;
	case PKGCMD_ERR_ROOT_CERTIFICATE_NOT_FOUND:
		*errstr = PKGCMD_ERR_ROOT_CERTIFICATE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_INVALID:
		*errstr = PKGCMD_ERR_CERTIFICATE_INVALID_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED:
		*errstr = PKGCMD_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_EXPIRED:
		*errstr = PKGCMD_ERR_CERTIFICATE_EXPIRED_STR;
		break;
	case PKGCMD_ERR_INVALID_PRIVILEGE:
		*errstr = PKGCMD_ERR_INVALID_PRIVILEGE_STR;
		break;
	case PKGCMD_ERR_MENU_ICON_NOT_FOUND:
		*errstr = PKGCMD_ERR_MENU_ICON_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_FATAL_ERROR:
		*errstr = PKGCMD_ERR_FATAL_ERROR_STR;
		break;
	case PKGCMD_ERR_OUT_OF_STORAGE:
		*errstr = PKGCMD_ERR_OUT_OF_STORAGE_STR;
		break;
	case PKGCMD_ERR_OUT_OF_MEMORY:
		*errstr = PKGCMD_ERR_OUT_OF_MEMORY_STR;
		break;
	case PKGCMD_ERR_ARGUMENT_INVALID:
		*errstr = PKGCMD_ERR_ARGUMENT_INVALID_STR;
		break;
	default:
		*errstr = PKGCMD_ERR_UNKNOWN_STR;
		break;
	}
}

static void __add_op_cbinfo(pkgmgr_client_t * pc, int request_id,
			    const char *req_key, pkgmgr_handler event_cb, void *new_event_cb,
			    void *data)
{
	req_cb_info *cb_info;
	req_cb_info *current;
	req_cb_info *prev;

	cb_info = (req_cb_info *) calloc(1, sizeof(req_cb_info));
	if (cb_info == NULL) {
		_LOGD("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->req_key = strdup(req_key);
	cb_info->event_cb = event_cb;
	cb_info->data = data;
	cb_info->next = NULL;
	pc->new_event_cb = new_event_cb;

	if (pc->info.request.rhead == NULL)
		pc->info.request.rhead = cb_info;
	else {
		current = prev = pc->info.request.rhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static req_cb_info *__find_op_cbinfo(pkgmgr_client_t *pc, const char *req_key)
{
	req_cb_info *tmp;

	tmp = pc->info.request.rhead;

	if (tmp == NULL) {
		_LOGE("tmp is NULL");
		return NULL;
	}

	_LOGD("tmp->req_key %s, req_key %s", tmp->req_key, req_key);

	while (tmp) {
		if (strncmp(tmp->req_key, req_key, strlen(tmp->req_key)) == 0)
			return tmp;
		tmp = tmp->next;
	}
	return NULL;
}

static void __remove_op_cbinfo(pkgmgr_client_t *pc, req_cb_info *info)
{
	req_cb_info *tmp;

	if (pc == NULL || pc->info.request.rhead == NULL || info == NULL)
		return;

	tmp = pc->info.request.rhead;
	while (tmp) {
		if (tmp->next == info) {
			tmp->next = info->next;
			free(info);
			return;
		}
		tmp = tmp->next;
	}
}


static void __add_stat_cbinfo(pkgmgr_client_t *pc, int request_id,
			      pkgmgr_handler event_cb, void *data)
{
	listen_cb_info *cb_info;
	listen_cb_info *current;
	listen_cb_info *prev;

	cb_info = (listen_cb_info *) calloc(1, sizeof(listen_cb_info));
	if (cb_info == NULL) {
		_LOGD("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->event_cb = event_cb;
	cb_info->data = data;
	cb_info->next = NULL;

	/* TODO - check the order of callback - FIFO or LIFO => Should be changed to LIFO */
	if (pc->info.listening.lhead == NULL)
		pc->info.listening.lhead = cb_info;
	else {
		current = prev = pc->info.listening.lhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static void __operation_callback(void *cb_data, const char *req_id,
				 const char *pkg_type, const char *pkgid,
				 const char *key, const char *val)
{
	pkgmgr_client_t *pc;
	req_cb_info *cb_info;

	_LOGD("__operation_callback() req_id[%s] pkg_type[%s] pkgid[%s]"
	      "key[%s] val[%s]\n", req_id, pkg_type, pkgid, key, val);

	pc = (pkgmgr_client_t *) cb_data;

	/* find callback info */
	cb_info = __find_op_cbinfo(pc, req_id);
	if (cb_info == NULL)
		return;

	_LOGD("__find_op_cbinfo");

	/* call callback */
	if (cb_info->event_cb) {
		cb_info->event_cb(cb_info->request_id, pkg_type, pkgid, key,
				  val, NULL, cb_info->data);
		_LOGD("event_cb is called");
	}

	/*remove callback for last call 
	   if (strcmp(key, "end") == 0) {
	   __remove_op_cbinfo(pc, cb_info);
	   _LOGD("__remove_op_cbinfo");
	   }
	 */

	return;
}

static void __status_callback(void *cb_data, const char *req_id,
			      const char *pkg_type, const char *pkgid,
			      const char *key, const char *val)
{
	pkgmgr_client_t *pc;
	listen_cb_info *tmp;

	_LOGD("__status_callback() req_id[%s] pkg_type[%s] pkgid[%s]"
	      "key[%s] val[%s]\n", req_id, pkg_type, pkgid, key, val);

	pc = (pkgmgr_client_t *) cb_data;

	tmp = pc->info.listening.lhead;
	while (tmp) {
		if (tmp->event_cb(tmp->request_id, pkg_type, pkgid, key, val,
				  NULL, tmp->data) != 0)
			break;
		tmp = tmp->next;
	}

	return;
}

static char *__get_req_key(const char *pkg_path)
{
	struct timeval tv;
	long curtime;
	char timestr[PKG_STRING_LEN_MAX];
	char *str_req_key;
	int size;

	gettimeofday(&tv, NULL);
	curtime = tv.tv_sec * 1000000 + tv.tv_usec;
	snprintf(timestr, sizeof(timestr), "%ld", curtime);

	size = strlen(pkg_path) + strlen(timestr) + 2;
	str_req_key = (char *)calloc(size, sizeof(char));
	if (str_req_key == NULL) {
		_LOGD("calloc failed");
		return NULL;
	}
	snprintf(str_req_key, size, "%s_%s", pkg_path, timestr);

	return str_req_key;
}

static char *__get_type_from_path(const char *pkg_path)
{
	int ret;
	char mimetype[255] = { '\0', };
	char extlist[256] = { '\0', };
	char *pkg_type;

	ret = _get_mime_from_file(pkg_path, mimetype, sizeof(mimetype));
	if (ret) {
		_LOGE("_get_mime_from_file() failed - error code[%d]\n",
		      ret);
		return NULL;
	}

	ret = _get_mime_extension(mimetype, extlist, sizeof(extlist));
	if (ret) {
		_LOGE("_get_mime_extension() failed - error code[%d]\n",
		      ret);
		return NULL;
	}

	if (strlen(extlist) == 0)
		return NULL;

	if (strchr(extlist, ',')) {
		extlist[strlen(extlist) - strlen(strchr(extlist, ','))] = '\0';
	}
	pkg_type = strchr(extlist, '.') + 1;
	return strdup(pkg_type);
}

static int __get_pkgid_by_appid(const char *appid, char **pkgid)
{
	pkgmgrinfo_appinfo_h pkgmgrinfo_appinfo = NULL;
	int ret = -1;
	char *pkg_id = NULL;
	char *pkg_id_dup = NULL;

	if (pkgmgrinfo_appinfo_get_appinfo(appid, &pkgmgrinfo_appinfo) != PMINFO_R_OK)
		return -1;

	if (pkgmgrinfo_appinfo_get_pkgname(pkgmgrinfo_appinfo, &pkg_id) != PMINFO_R_OK)
		goto err;

	pkg_id_dup = strdup(pkg_id);
	if (pkg_id_dup == NULL)
		goto err;

	*pkgid = pkg_id_dup;
	ret = PMINFO_R_OK;

err:
	pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo);

	return ret;
}

static inline ail_cb_ret_e __appinfo_cb(const ail_appinfo_h appinfo, void *user_data)
{
	char *package;
	ail_cb_ret_e ret = AIL_CB_RET_CONTINUE;

	ail_appinfo_get_str(appinfo, AIL_PROP_PACKAGE_STR, &package);

	if (package) {
		(* (char **) user_data) = strdup(package);
		ret = AIL_CB_RET_CANCEL;
	}

	return ret;
}

static char *__get_app_info_from_db_by_apppath(const char *apppath, uid_t uid)
{
	char *caller_appid = NULL;
	ail_filter_h filter;
	ail_error_e ret;
	int count;

	if (apppath == NULL)
		return NULL;

	ret = ail_filter_new(&filter);
	if (ret != AIL_ERROR_OK) {
		return NULL;
	}

	ret = ail_filter_add_str(filter, AIL_PROP_X_SLP_EXE_PATH, apppath);
	if (ret != AIL_ERROR_OK) {
		ail_filter_destroy(filter);
		return NULL;
	}
	
	if(uid != GLOBAL_USER)
		ret = ail_filter_count_usr_appinfo(filter, &count, uid);
	else
		ret = ail_filter_count_appinfo(filter, &count);

	if (ret != AIL_ERROR_OK) {
		ail_filter_destroy(filter);
		return NULL;
	}
	if (count < 1) {
		ail_filter_destroy(filter);
		return NULL;
	}
	if(uid != GLOBAL_USER)
		ail_filter_list_usr_appinfo_foreach(filter, __appinfo_cb, &caller_appid,uid);
	else
		ail_filter_list_appinfo_foreach(filter, __appinfo_cb, &caller_appid);	

	ail_filter_destroy(filter);

	return caller_appid;
}

static inline int __read_proc(const char *path, char *buf, int size)
{
	int fd = 0;
	int ret = 0;

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

char *__proc_get_cmdline_bypid(int pid)
{
	char buf[PKG_STRING_LEN_MAX] = {'\0', };
	int ret = 0;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return NULL;

	/* support app launched by shell script*/
	if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0)
		return strdup(&buf[BINSH_SIZE + 1]);
	else
		return strdup(buf);
}

static int __get_appid_bypid(int pid, char *pkgname, int len, uid_t uid)
{
	char *cmdline = NULL;
	char *caller_appid = NULL;

	cmdline = __proc_get_cmdline_bypid(pid);
	if (cmdline == NULL)
		return -1;

	caller_appid = __get_app_info_from_db_by_apppath(cmdline, uid);
	snprintf(pkgname, len, "%s", caller_appid);

	free(cmdline);
	free(caller_appid);

	return 0;
}

static char *__get_caller_pkgid(uid_t uid)
{
	char *caller_appid[PKG_STRING_LEN_MAX] = {0, };
	char *caller_pkgid = NULL;

	if (__get_appid_bypid(getpid(), caller_appid, sizeof(caller_appid), uid) < 0) {
		_LOGE("get appid fail!!!\n");
		return NULL;
	}
	if (__get_pkgid_by_appid(caller_appid, &caller_pkgid) < 0){
		_LOGE("get pkgid fail!!!\n");
		return NULL;
	}

	return caller_pkgid;
}

static inline int __pkgmgr_read_proc(const char *path, char *buf, int size)
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

static inline int __pkgmgr_find_pid_by_cmdline(const char *dname,
				      const char *cmdline, const char *apppath)
{
	int pid = 0;

	if (strncmp(cmdline, apppath, PKG_STRING_LEN_MAX-1) == 0) {
		pid = atoi(dname);
		if (pid != getpgid(pid))
			pid = 0;
	}

	return pid;
}


static int __pkgmgr_proc_iter_kill_cmdline(const char *apppath)
{
	DIR *dp;
	struct dirent *dentry;
	int pid;
	int ret;
	char buf[PKG_STRING_LEN_MAX];

	dp = opendir("/proc");
	if (dp == NULL) {
		return -1;
	}

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		snprintf(buf, sizeof(buf), "/proc/%s/cmdline", dentry->d_name);
		ret = __pkgmgr_read_proc(buf, buf, sizeof(buf));
		if (ret <= 0)
			continue;

		pid = __pkgmgr_find_pid_by_cmdline(dentry->d_name, buf, apppath);

		if (pid > 0) {
			int pgid;

			pgid = getpgid(pid);
			if (pgid <= 1) {
				closedir(dp);
				return -1;
			}

			if (killpg(pgid, SIGKILL) < 0) {
				closedir(dp);
				return -1;
			}
		}
	}

	closedir(dp);
	return 0;
}


static int __app_list_cb (const pkgmgr_appinfo_h handle,
						void *user_data)
{
	char *exec = NULL;
	pkgmgr_appinfo_get_exec(handle, &exec);

	__pkgmgr_proc_iter_kill_cmdline(exec);

	return 0;
}

static int __sync_process(char *req_key)
{
	char info_file[PKG_STRING_LEN_MAX] = {'\0', };
	int result = 0;
	int check_cnt = 0;

	snprintf(info_file, PKG_STRING_LEN_MAX, "%s/%s", PKG_TMP_PATH, req_key);
	while(1)
	{
		check_cnt ++;

		vconf_get_int(VCONFKEY_PKGMGR_STATUS, &result);
		if (result < 0) {
			_LOGD("file is not generated yet.... wait\n");
			usleep(10 * 1000);	/* 10ms sleep*/
		} else {
			_LOGD("info_file file is generated, result = %d. \n", result);
			break;
		}

		if (check_cnt > 6000) {	/* 60s time over*/
			_LOGD("wait time over!!\n");
			break;
		}
	}

	vconf_set_int(VCONFKEY_PKGMGR_STATUS, -1);

	return result;
}
static int __csc_process(const char *csc_path, char *result_path)
{
	int ret = 0;
	int cnt = 0;
	int count = 0;
	int csc_fail = 0;
	int fd = 0;
	char *pkgtype = NULL;
	char *des = NULL;
	char buf[PKG_STRING_LEN_MAX] = {0,};
	char type_buf[1024] = { 0 };
	char des_buf[1024] = { 0 };
	dictionary *csc = NULL;
	FILE* file = NULL;

	csc = iniparser_load(csc_path);
	retvm_if(csc == NULL, PKGMGR_R_EINVAL, "cannot open parse file [%s]", csc_path);

	file = fopen(result_path, "w");
	tryvm_if(file == NULL, ret = PKGMGR_R_EINVAL, "cannot open result file [%s]", result_path);

	count = iniparser_getint(csc, "csc packages:count", -1);
	tryvm_if(count == 0, ret = PKGMGR_R_ERROR, "csc [%s] dont have packages", csc_path);

	snprintf(buf, PKG_STRING_LEN_MAX, "[result]\n");
	fwrite(buf, 1, strlen(buf), file);
	snprintf(buf, PKG_STRING_LEN_MAX, "count = %d\n", count);
	fwrite(buf, 1, strlen(buf), file);

	for(cnt = 1 ; cnt <= count ; cnt++)
	{
		snprintf(type_buf, PKG_STRING_LEN_MAX - 1, "csc packages:type_%03d", cnt);
		snprintf(des_buf, PKG_STRING_LEN_MAX - 1, "csc packages:description_%03d", cnt);

		pkgtype = iniparser_getstring(csc, type_buf, NULL);
		des = iniparser_getstring(csc, des_buf, NULL);
		ret = 0;

		if (pkgtype == NULL) {
			csc_fail++;
			snprintf(buf, PKG_STRING_LEN_MAX, "%s = Fail to get pkgtype\n", type_buf);
			fwrite(buf, 1, strlen(buf), file);
			continue;
		} else if (des == NULL) {
			csc_fail++;
			snprintf(buf, PKG_STRING_LEN_MAX, "%s = Fail to get description\n", des_buf);
			fwrite(buf, 1, strlen(buf), file);
			continue;
		}

		snprintf(buf, PKG_STRING_LEN_MAX, "type_%03d = %s\n", cnt, pkgtype);
		fwrite(buf, 1, strlen(buf), file);
		snprintf(buf, PKG_STRING_LEN_MAX, "description_%03d = %s\n", cnt, des);
		fwrite(buf, 1, strlen(buf), file);

		if (strcmp(pkgtype, "tpk") == 0) {
			const char *ospinstaller_argv[] = { "/usr/bin/osp-installer", "-c", des, NULL };
			ret = __xsystem(ospinstaller_argv);
		} else if (strcmp(pkgtype, "wgt")== 0) {
			const char *wrtinstaller_argv[] = { "/usr/bin/wrt-installer", "-c", des, NULL };
			ret = __xsystem(wrtinstaller_argv);
		} else {
			csc_fail++;
			ret = -1;
		}

		if (ret != 0) {
			char *errstr = NULL;
			__error_to_string(ret, &errstr);
			snprintf(buf, PKG_STRING_LEN_MAX, "result_%03d = fail[%s]\n", cnt, errstr);
		}
		else
			snprintf(buf, PKG_STRING_LEN_MAX, "result_%03d = success\n", cnt);

		fwrite(buf, 1, strlen(buf), file);
	}

catch:
	iniparser_freedict(csc);
	if (file != NULL) {
		fflush(file);
		fd = fileno(file);
		fsync(fd);
		fclose(file);
	}
	return ret;
}

static int __get_size_process(pkgmgr_client * pc, const char *pkgid, uid_t uid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data)
{
	char *req_key = NULL;
	int ret =0;
	char *pkgtype = "rpm";
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int i = 0;
	char buf[128] = {'\0'};
	char *cookie = NULL;

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	req_key = __get_req_key(pkgid);

	snprintf(buf, 128, "%d", get_type);
	argv[argcnt++] = strdup(pkgid);
	argv[argcnt++] = strdup(buf);

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* request */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_GET_SIZE, pkgtype, pkgid, args, cookie, uid, 1);
	if (ret < 0)
		_LOGE("comm_client_request failed, ret=%d\n", ret);

	ret = __sync_process(req_key);
	if (ret < 0)
		_LOGE("get size failed, ret=%d\n", ret);

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	return ret;
}

static int __move_pkg_process(pkgmgr_client * pc, const char *pkgid, uid_t uid, pkgmgr_move_type move_type, pkgmgr_handler event_cb, void *data)
{
	char *req_key = NULL;
	int req_id = 0;
	int ret =0;
	pkgmgrinfo_pkginfo_h handle;
	char *pkgtype = NULL;
	char *installer_path = NULL;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int i = 0;
	char buf[128] = {'\0'};
	char info_file[PKG_STRING_LEN_MAX] = {'\0', };
	char *cookie = NULL;

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	if(uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	else
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_pkginfo failed");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_type failed");

	installer_path = _get_backend_path_with_type(pkgtype);
	req_key = __get_req_key(pkgid);
	req_id = _get_request_id();

	/* generate argv */
	snprintf(buf, 128, "%d", move_type);
	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-m");
	/* argv[4] */
	argv[argcnt++] = strdup(pkgid);
	/* argv[5] */
	argv[argcnt++] = strdup("-t");
	/* argv[6] */
	argv[argcnt++] = strdup(buf);
	/* argv[7] */
	argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* 6. request */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_MOVER, pkgtype, pkgid, args, cookie,uid, 1);
	if (ret < 0)
		_LOGE("comm_client_request failed, ret=%d\n", ret);

	snprintf(info_file, PKG_STRING_LEN_MAX, "app2sd_%s", pkgid);
	ret = __sync_process(info_file);
	if (ret != 0)
		_LOGE("move pkg failed, ret=%d\n", ret);

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	return ret;
}

static int __check_app_process(pkgmgr_request_service_type service_type, pkgmgr_client * pc, const char *pkgid, uid_t uid, void *data)
{
	const char *pkgtype;
	char *req_key;
	int ret;
	pkgmgrinfo_pkginfo_h handle;
	int pid = -1;

	/* Check for NULL value of pc */
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	else
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_pkginfo failed");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_type failed");

	/* 2. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 3. request activate */
	if (service_type == PM_REQUEST_KILL_APP)
		ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_KILL_APP, pkgtype, pkgid, NULL, NULL, uid, 1);
	else if (service_type == PM_REQUEST_CHECK_APP)
		ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_CHECK_APP, pkgtype, pkgid, NULL, NULL, uid, 1);

	if (ret < 0)
		_LOGE("request failed, ret=%d\n", ret);

	pid  = __sync_process(req_key);
	* (int *) data = pid;

catch:
	free(req_key);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return ret;

}

static int __request_size_info(pkgmgr_client *pc, uid_t uid)
{
	char *req_key = NULL;
	int ret =0;
	char *pkgtype = "getsize";
	char *pkgid = "size_info";
	pkgmgr_getsize_type get_type = PM_GET_SIZE_INFO;

	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int i = 0;
	char buf[128] = {'\0'};
	char *cookie = NULL;

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	req_key = __get_req_key(pkgid);

	snprintf(buf, 128, "%d", get_type);
	argv[argcnt++] = strdup(pkgid);
	argv[argcnt++] = strdup(buf);
	argv[argcnt++] = strdup(buf);

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* request */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_GET_SIZE, pkgtype, pkgid, args, cookie, uid, 1);
	if (ret < 0) {
		_LOGE("COMM_REQ_GET_SIZE failed, ret=%d\n", ret);
	}

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	return ret;
}

static int __change_op_cb_for_getsize(pkgmgr_client *pc)
{
	int ret = -1;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/*  free listening head */
	req_cb_info *tmp = NULL;
	req_cb_info *prev = NULL;
	for (tmp = mpc->info.request.rhead; tmp;) {
		prev = tmp;
		tmp = tmp->next;
		free(prev);
	}

	/* free dbus connection */
	ret = comm_client_free(mpc->info.request.cc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "comm_client_free() failed - %d", ret);

	/* Manage pc for seperated event */
	mpc->ctype = PC_REQUEST;
	mpc->status_type = PKGMGR_CLIENT_STATUS_GET_SIZE;


	mpc->info.request.cc = comm_client_new();
	retvm_if(mpc->info.request.cc == NULL, PKGMGR_R_ERROR, "client creation failed");

	ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_GET_SIZE, mpc->info.request.cc, __operation_callback, pc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "set_status_callback() failed - %d", ret);

	return PKGMGR_R_OK;
}

static int __get_package_size_info(pkgmgr_client_t *mpc, char *req_key, const char *pkgid, pkgmgr_getsize_type get_type, uid_t uid)
{
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	char *pkgtype = "getsize"; //unused
	char buf[128] = { 0, };
	int len = 0;
	char *cookie = NULL;
	char *temp = NULL;
	int i = 0;
	int ret = 0;

	snprintf(buf, 128, "%d", get_type);
	argv[argcnt++] = strdup(pkgid);
	argv[argcnt++] = strdup(buf);
	argv[argcnt++] = strdup("-k");
	argv[argcnt++] = req_key;

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* request */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_GET_SIZE, pkgtype, pkgid, args, cookie, uid, 1);
	if (ret < 0)
		_LOGE("COMM_REQ_GET_SIZE failed, ret=%d\n", ret);

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	return ret;
}

static int __get_pkg_size_info_cb(int req_id, const char *req_type,
		const char *pkgid, const char *key,
		const char *value, const void *pc, void *user_data)
{
	int ret = 0;
	_LOGD("reqid: %d, req type: %s, pkgid: %s, unused key: %s, size info: %s",
			req_id, req_type, pkgid, key, value);

	pkg_size_info_t *size_info = (pkg_size_info_t *)malloc(sizeof(pkg_size_info_t));
	retvm_if(size_info == NULL, -1, "The memory is insufficient.");

	char *save_ptr = NULL;
	char *token = strtok_r((char*)value, ":", &save_ptr);
	size_info->data_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	size_info->cache_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	size_info->app_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	size_info->ext_data_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	size_info->ext_cache_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	size_info->ext_app_size = atoll(token);

	_LOGD("data: %lld, cache: %lld, app: %lld, ext_data: %lld, ext_cache: %lld, ext_app: %lld",
			size_info->data_size, size_info->cache_size, size_info->app_size,
			size_info->ext_data_size, size_info->ext_cache_size, size_info->ext_app_size);

	pkgmgr_client_t *pmc = (pkgmgr_client_t *)pc;
	tryvm_if(pmc == NULL, ret = -1, "pkgmgr_client instance is null.");

	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0)
	{	// total package size info
		pkgmgr_total_pkg_size_info_receive_cb callback = (pkgmgr_total_pkg_size_info_receive_cb)(pmc->new_event_cb);
		callback((pkgmgr_client *)pc, size_info, user_data);
	}
	else
	{
		pkgmgr_pkg_size_info_receive_cb callback = (pkgmgr_pkg_size_info_receive_cb)(pmc->new_event_cb);
		callback((pkgmgr_client *)pc, pkgid, size_info, user_data);
	}

catch:

	if(size_info){
		free(size_info);
		size_info = NULL;
	}
	return ret;
}

API pkgmgr_client *pkgmgr_client_new(client_type ctype)
{
	pkgmgr_client_t *pc = NULL;
	int ret = -1;

	retvm_if(ctype != PC_REQUEST && ctype != PC_LISTENING && ctype != PC_BROADCAST, NULL, "ctype is not client_type");

	/* Allocate memory for ADT:pkgmgr_client */
	pc = calloc(1, sizeof(pkgmgr_client_t));
	retvm_if(pc == NULL, NULL, "No memory");

	/* Manage pc */
	pc->ctype = ctype;
	pc->status_type = PKGMGR_CLIENT_STATUS_ALL;

	if (pc->ctype == PC_REQUEST) {
		pc->info.request.cc = comm_client_new();
		trym_if(pc->info.request.cc == NULL, "client creation failed");

		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_ALL, pc->info.request.cc, __operation_callback, pc);
		trym_if(ret < 0L, "comm_client_set_status_callback() failed - %d", ret);
	} else if (pc->ctype == PC_LISTENING) {
		pc->info.listening.cc = comm_client_new();
		trym_if(pc->info.listening.cc == NULL, "client creation failed");

		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_ALL, pc->info.listening.cc, __status_callback, pc);
		trym_if(ret < 0L, "comm_client_set_status_callback() failed - %d", ret);
	} else if (pc->ctype == PC_BROADCAST) {
		pc->info.broadcast.bc = comm_status_broadcast_server_connect(COMM_STATUS_BROADCAST_ALL);
		trym_if(pc->info.broadcast.bc == NULL, "client creation failed");
	}

	return (pkgmgr_client *) pc;

 catch:
	if (pc)
		free(pc);
	return NULL;
}

API int pkgmgr_client_free(pkgmgr_client *pc)
{
	int ret = -1;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc == NULL, PKGMGR_R_EINVAL, "Invalid argument");

	if (mpc->ctype == PC_REQUEST) {
		req_cb_info *tmp;
		req_cb_info *prev;
		for (tmp = mpc->info.request.rhead; tmp;) {
			prev = tmp;
			tmp = tmp->next;
			free(prev);
		}

		ret = comm_client_free(mpc->info.request.cc);
		tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "comm_client_free() failed");
	} else if (mpc->ctype == PC_LISTENING) {
			listen_cb_info *tmp;
			listen_cb_info *prev;
			for (tmp = mpc->info.listening.lhead; tmp;) {
				prev = tmp;
				tmp = tmp->next;
				free(prev);
			}

			ret = comm_client_free(mpc->info.listening.cc);
			tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "comm_client_free() failed");
	} else if (mpc->ctype == PC_BROADCAST) {
		comm_status_broadcast_server_disconnect(mpc->info.broadcast.bc);
		ret = 0;
	} else {
		_LOGE("Invalid client type\n");
		return PKGMGR_R_EINVAL;
	}

	free(mpc);
	mpc = NULL;
	return PKGMGR_R_OK;

 catch:
	if (mpc) {
		free(mpc);
		mpc = NULL;
	}
	return PKGMGR_R_ERROR;
}


API int pkgmgr_client_usr_install(pkgmgr_client * pc, const char *pkg_type,
			      const char *descriptor_path, const char *pkg_path,
			      const char *optional_file, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data, uid_t uid)
{
	char *pkgtype = NULL;
	char *installer_path = NULL;
	char *req_key = NULL;
	int req_id = 0;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = 0;
	char *cookie = NULL;
	char *caller_pkgid = NULL;

	caller_pkgid = __get_caller_pkgid(uid);
	if (caller_pkgid == NULL)
		_LOGE("caller dont have pkgid..\n");

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL");

	/* 0. check the pc type */
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	if (descriptor_path) {
		retvm_if(strlen(descriptor_path) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "descriptor_path over PKG_STRING_LEN_MAX");
		retvm_if(access(descriptor_path, F_OK) != 0, PKGMGR_R_EINVAL, "descriptor_path access fail");
	}

	retvm_if(pkg_path == NULL, PKGMGR_R_EINVAL, "pkg_path is NULL");
	retvm_if(strlen(pkg_path) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkg_path over PKG_STRING_LEN_MAX");
	retvm_if(access(pkg_path, F_OK) != 0, PKGMGR_R_EINVAL, "pkg_path access fail");

	if (optional_file)
		retvm_if(strlen(optional_file) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "optional_file over PKG_STRING_LEN_MAX");

	/* 2. get installer path using pkg_path */
	if (pkg_type) {
		installer_path = _get_backend_path_with_type(pkg_type);
		pkgtype = strdup(pkg_type);
	} else {
		installer_path = _get_backend_path(pkg_path);
		pkgtype = __get_type_from_path(pkg_path);
	}
	if (installer_path == NULL) {
		free(pkgtype);
		_LOGE("installer_path is NULL\n");
		return PKGMGR_R_EINVAL;
	}

	/* 3. generate req_key */
	req_key = __get_req_key(pkg_path);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	/* 5. generate argv */

	/*  argv[0] installer path */
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-i");
	/* argv[(4)] if exists */
	if (descriptor_path)
		argv[argcnt++] = strdup(descriptor_path);
	/* argv[4] */
	argv[argcnt++] = strdup(pkg_path);
	/* argv[(5)] if exists */
	if (optional_file){
		argv[argcnt++] = strdup("-o");
		argv[argcnt++] = strdup(optional_file);
	}
	if (caller_pkgid) {
		argv[argcnt++] = strdup("-p");
		argv[argcnt++] = strdup(caller_pkgid);
	}


/* argv[6] -q option should be located at the end of command !! */
	if (mode == PM_QUIET)
		argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALLER, pkgtype, pkg_path, args, cookie, uid, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "request failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (pkgtype)
		free(pkgtype);
	if (cookie)
		free(cookie);

	return ret;
}



API int pkgmgr_client_install(pkgmgr_client * pc, const char *pkg_type,
			      const char *descriptor_path, const char *pkg_path,
			      const char *optional_file, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data)
{
	

	return pkgmgr_client_usr_install(pc, pkg_type,
			      descriptor_path, pkg_path, optional_file, mode, event_cb,data,  GLOBAL_USER);
}

API int pkgmgr_client_reinstall(pkgmgr_client * pc, const char *pkg_type, const char *pkgid,
				  const char *optional_file, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_usr_reinstall(pc, pkg_type, pkgid, optional_file, mode, event_cb, data,GLOBAL_USER);
}

API int pkgmgr_client_usr_reinstall(pkgmgr_client * pc, const char *pkg_type, const char *pkgid,
				  const char *optional_file, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data, uid_t uid)
{
	char *pkgtype = NULL;
	char *installer_path = NULL;
	char *req_key = NULL;
	int req_id = 0;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = 0;
	char *cookie = NULL;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retv_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL);


	/* 1. check argument */
	retv_if(pkgid == NULL, PKGMGR_R_EINVAL);
	retv_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL);
	if (optional_file) {
		if (strlen(optional_file) >= PKG_STRING_LEN_MAX)
			return PKGMGR_R_EINVAL;
	}

	/* 2. get installer path using pkg_path */
	installer_path = _get_backend_path_with_type(pkg_type);
	pkgtype = strdup(pkg_type);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_EINVAL, "installer_path is null");

	/* 3. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	/* 5. generate argv */

	/*  argv[0] installer path */
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-r");
	/* argv[4] */
	argv[argcnt++] = strdup(pkgid);
	/* argv[(5)] if exists */
	if (optional_file){
		argv[argcnt++] = strdup("-o");
		argv[argcnt++] = strdup(optional_file);
	}

	/* argv[5] -q option should be located at the end of command !! */
	if (mode == PM_QUIET)
		argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALLER, pkgtype, pkgid, args, cookie, uid, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "request failed");

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (pkgtype)
		free(pkgtype);
	if (cookie)
		free(cookie);

	return ret;
}

API int pkgmgr_client_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_usr_uninstall(pc, pkg_type,pkgid, mode, event_cb,  data, GLOBAL_USER);
}
API int pkgmgr_client_usr_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data, uid_t uid)
{
	char *pkgtype;
	char *installer_path;
	char *req_key;
	int req_id;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = -1;
	char *cookie = NULL;
	bool removable = false;
	char *caller_pkgid = NULL;

	caller_pkgid = __get_caller_pkgid(uid);
	if (caller_pkgid == NULL)
		_LOGD("caller dont have pkgid..\n");

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retv_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL);

	/* 1. check argument */
	retv_if(pkgid == NULL, PKGMGR_R_EINVAL);

	pkgmgr_pkginfo_h handle;
	ret = pkgmgr_pkginfo_get_usr_pkginfo(pkgid, uid, &handle); 

	/*check package id	*/
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_pkginfo_get_pkginfo fail");
	tryvm_if(handle == NULL, ret = PKGMGR_R_EINVAL, "Pkgid(%s) can not find in installed pkg DB! \n", pkgid);

  if (uid != GLOBAL_USER) {
	  /*check running app , terminate app if it is running*/
	  ret = pkgmgr_appinfo_get_usr_list(handle, PM_UI_APP, __app_list_cb, NULL, uid);
	  tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_appinfo_get_list : PM_UI_APP fail");

	  /*check running app , terminate app if it is running*/
	  ret = pkgmgr_appinfo_get_usr_list(handle, PM_SVC_APP, __app_list_cb, NULL, uid);
	  tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_appinfo_get_list : PM_SVC_APP fail");
  } else {
 	  /*check running app , terminate app if it is running*/
	  ret = pkgmgr_appinfo_get_list(handle, PM_UI_APP, __app_list_cb, NULL);
	  tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_appinfo_get_list : PM_UI_APP fail");

	  /*check running app , terminate app if it is running*/
	  ret = pkgmgr_appinfo_get_list(handle, PM_SVC_APP, __app_list_cb, NULL);
	  tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_appinfo_get_list : PM_SVC_APP fail"); 
	}
  /*check type	*/
	ret = pkgmgr_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_pkginfo_get_type fail");
	tryvm_if(pkgtype == NULL, ret = PKGMGR_R_ERROR, "pkgtype is NULL");

	/*check removable, execpt "rpm" type	*/
	if (strcmp(pkgtype, "rpm")) {
		pkgmgr_pkginfo_is_removable(handle, &removable);
		tryvm_if(removable == false, ret = PKGMGR_R_ERROR, "Pkgid(%s) can not be removed, This is non-removalbe package...\n", pkgid);
	}

	/*check pkgid length	*/
	tryvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, ret = PKGMGR_R_EINVAL, "pkgid is too long");

	/* 2. get installer path using pkgtype */
	installer_path = _get_backend_path_with_type(pkgtype);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	/* 3. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	/* 5. generate argv */

	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-d");
	/* argv[4] */
	argv[argcnt++] = strdup(pkgid);
	if (caller_pkgid) {
		argv[argcnt++] = strdup("-p");
		argv[argcnt++] = caller_pkgid;
	}
	/* argv[5] -q option should be located at the end of command !! */
	if (mode == PM_QUIET)
		argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALLER, pkgtype, pkgid, args, cookie, uid, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "calloc failed");

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	pkgmgr_pkginfo_destroy_pkginfo(handle);
	PKGMGR_END();\
	return ret;
}

API int pkgmgr_client_move(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_move_type move_type, pkgmgr_mode mode)
{
	return pkgmgr_client_usr_move( pc,pkg_type, pkgid, move_type, mode, GLOBAL_USER);
}
API int pkgmgr_client_usr_move(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_move_type move_type, pkgmgr_mode mode, uid_t uid)
{
	const char *pkgtype = NULL;
	char *installer_path = NULL;
	char *req_key = NULL;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = 0;
	int req_id = 0;
	char *cookie = NULL;
	char buf[128] = {'\0'};

	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	/*check the pc type */
	if (mpc->ctype != PC_REQUEST)
		return PKGMGR_R_EINVAL;

	/*check argument */
	if (pkgid == NULL)
		return PKGMGR_R_EINVAL;

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkgid, uid);
		if (pkgtype == NULL)
			return PKGMGR_R_EINVAL;
	} else
		pkgtype = pkg_type;

	if (strlen(pkgid) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	if ((move_type < PM_MOVE_TO_INTERNAL) || (move_type > PM_MOVE_TO_SDCARD))
		return PKGMGR_R_EINVAL;

	/* get installer path using pkg_path */
	installer_path = _get_backend_path_with_type(pkgtype);
	if (installer_path == NULL)
		return PKGMGR_R_EINVAL;

	/* generate req_key */
	req_key = __get_req_key(pkgid);
	req_id = _get_request_id();

	/* generate argv */
	snprintf(buf, 128, "%d", move_type);
	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-m");
	/* argv[4] */
	argv[argcnt++] = strdup(pkgid);
	/* argv[5] */
	argv[argcnt++] = strdup("-t");
	/* argv[6] */
	argv[argcnt++] = strdup(buf);
	/* argv[7] -q option should be located at the end of command !! */
	if (mode == PM_QUIET)
		argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	if (args == NULL) {
		_LOGD("calloc failed");

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		return PKGMGR_R_ERROR;
	}
	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_MOVER, pkgtype, pkgid,
				  args, cookie, uid, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		free(args);
		return PKGMGR_R_ECOMM;
	}

	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);

	return req_id;
}

API int pkgmgr_client_move_pkg(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_move_type move_type, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_move_usr_pkg(pc, pkg_type, pkgid, GLOBAL_USER, move_type, mode, event_cb, data);
}

API int pkgmgr_client_move_usr_pkg(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, uid_t uid, pkgmgr_move_type move_type, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data)
{
	char *pkgtype;
	char *installer_path;
	char *req_key;
	int req_id;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = -1;
	char *cookie = NULL;
	char buf[128] = {'\0'};

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retv_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL);

	/* 1. check argument */
	retv_if(pkgid == NULL, PKGMGR_R_EINVAL);

	pkgmgr_pkginfo_h handle;
  if (uid != GLOBAL_USER)
	  ret = pkgmgr_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
  else
	  ret = pkgmgr_pkginfo_get_pkginfo(pkgid, &handle);

	/*check package id	*/
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_pkginfo_get_pkginfo fail");
	tryvm_if(handle == NULL, ret = PKGMGR_R_EINVAL, "Pkgid(%s) can not find in installed pkg DB! \n", pkgid);

  if (uid != GLOBAL_USER) {
	  /*check running app , terminate app if it is running*/
	  ret = pkgmgr_appinfo_get_usr_list(handle, PM_UI_APP, __app_list_cb, NULL, uid);
	  tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_appinfo_get_list : PM_UI_APP fail");

    /*check running app , terminate app if it is running*/
	  ret = pkgmgr_appinfo_get_usr_list(handle, PM_SVC_APP, __app_list_cb, NULL, uid);
	  tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_appinfo_get_list : PM_SVC_APP fail");

  } else {
    /*check running app , terminate app if it is running*/
	  ret = pkgmgr_appinfo_get_list(handle, PM_UI_APP, __app_list_cb, NULL);
	  tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_appinfo_get_list : PM_UI_APP fail");
    /*check running app , terminate app if it is running*/
	  ret = pkgmgr_appinfo_get_list(handle, PM_SVC_APP, __app_list_cb, NULL);
	  tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_appinfo_get_list : PM_SVC_APP fail");
  }
	/*check type	*/
	ret = pkgmgr_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_pkginfo_get_type fail");
	tryvm_if(pkgtype == NULL, ret = PKGMGR_R_ERROR, "pkgtype is NULL");

	/*check pkgid length	*/
	tryvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, ret = PKGMGR_R_EINVAL, "pkgid is too long");

	/*check move_type	*/
	tryvm_if((move_type < PM_MOVE_TO_INTERNAL) || (move_type > PM_MOVE_TO_SDCARD), ret = PKGMGR_R_EINVAL, "move_type is not supported");

	/* 2. get installer path using pkgtype */
	installer_path = _get_backend_path_with_type(pkgtype);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	/* 3. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	/* 5. generate argv */
	snprintf(buf, 128, "%d", move_type);
	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-m");
	/* argv[4] */
	argv[argcnt++] = strdup(pkgid);
	/* argv[5] */
	argv[argcnt++] = strdup("-t");
	/* argv[6] */
	argv[argcnt++] = strdup(buf);
	/* argv[5] -q option should be located at the end of command !! */
	if (mode == PM_QUIET)
		argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_MOVER, pkgtype, pkgid, args, cookie, uid, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "calloc failed");

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	pkgmgr_pkginfo_destroy_pkginfo(handle);
	PKGMGR_END();\
	return ret;
}

API int pkgmgr_client_activate(pkgmgr_client * pc, const char *pkg_type,
			       const char *pkgid)
{
	return pkgmgr_client_usr_activate(pc, pkg_type, pkgid, GLOBAL_USER);
}

API int pkgmgr_client_usr_activate(pkgmgr_client * pc, const char *pkg_type,
			       const char *pkgid, uid_t uid)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");
	retvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkgid length over PKG_STRING_LEN_MAX ");

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkgid, uid);
		retvm_if(pkgtype == NULL, PKGMGR_R_EINVAL, "pkgtype is NULL");
	} else
		pkgtype = pkg_type;

	/* 2. generate req_key */
	req_key = __get_req_key(pkgid);
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_ACTIVATOR, pkgtype, pkgid, "1 PKG", cookie, uid, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "request failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	free(req_key);
	return ret;
}

API int pkgmgr_client_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkgid)
{
	return pkgmgr_client_usr_deactivate(pc, pkg_type, pkgid, GLOBAL_USER);
}

API int pkgmgr_client_usr_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkgid, uid_t uid)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");
	retvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkgid length over PKG_STRING_LEN_MAX ");

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkgid, uid);
		if (pkgtype == NULL)
			return PKGMGR_R_EINVAL;
	} else
		pkgtype = pkg_type;

	/* 2. generate req_key */
	req_key = __get_req_key(pkgid);
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_ACTIVATOR, pkgtype, pkgid, "0 PKG", cookie, uid, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "request failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	free(req_key);
	return ret;
}

API int pkgmgr_client_activate_app(pkgmgr_client * pc, const char *appid)
{
	return pkgmgr_client_usr_activate_app(pc,appid, GLOBAL_USER);
}

API int pkgmgr_client_usr_activate_app(pkgmgr_client * pc, const char *appid, uid_t uid)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(appid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");
	retvm_if(strlen(appid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkgid length over PKG_STRING_LEN_MAX ");

	pkgtype = _get_pkg_type_from_desktop_file(appid, uid);
	retvm_if(pkgtype == NULL, PKGMGR_R_EINVAL, "pkgtype is NULL");

	/* 2. generate req_key */
	req_key = __get_req_key(appid);
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_ACTIVATOR, pkgtype, appid, "1 APP", cookie, uid, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "request failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	free(req_key);
	return ret;
}

API int pkgmgr_client_activate_appv(pkgmgr_client * pc, const char *appid, char *const argv[])
{
	return pkgmgr_client_usr_activate_appv(pc, appid,  argv, GLOBAL_USER);
}

API int pkgmgr_client_usr_activate_appv(pkgmgr_client * pc, const char *appid, char *const argv[], uid_t uid)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
	int i = 0;
	char *temp = NULL;
	int len = 0;
	int argcnt = 0;
	char *args = NULL;
	char *argsr = NULL;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(appid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");
	retvm_if(strlen(appid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkgid length over PKG_STRING_LEN_MAX ");

	pkgtype = _get_pkg_type_from_desktop_file(appid, uid);
	retvm_if(pkgtype == NULL, PKGMGR_R_EINVAL, "pkgtype is NULL");

	/* 2. generate req_key */
	req_key = __get_req_key(appid);
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	if (argv) {
		for (i = 0; argv[i]; i++) {
			temp = g_shell_quote(argv[i]);
			len += (strlen(temp) + 1);
			g_free(temp);
			argcnt++;
		}

		if (argcnt) {
			args = (char *)calloc(len, sizeof(char));
			tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");
			strncpy(args, argv[0], len - 1);

			for (i = 1; i < argcnt; i++) {
				strncat(args, " ", strlen(" "));
				temp = g_shell_quote(argv[i]);
				strncat(args, temp, strlen(temp));
				g_free(temp);
			}
		}
	}

	argsr = (char *)calloc(strlen("1 APP")+2+len, sizeof(char));
	tryvm_if(argsr == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(argsr, "1 APP", strlen("1 APP"));
	if (argcnt) {
		strncat(argsr, " ", strlen(" "));
		strncat(argsr, args, strlen(args));
	}

	_LOGD("argsr [%s]\n", argsr);
	/******************* end of quote ************************/

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_ACTIVATOR, pkgtype, appid, argsr, cookie, uid, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "request failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:

	free(req_key);
	free(args);
	free(argsr);

	return ret;
}


API int pkgmgr_client_deactivate_app(pkgmgr_client *pc, const char *appid)
{
	return pkgmgr_client_usr_deactivate_app(pc, appid, GLOBAL_USER);
}

API int pkgmgr_client_usr_deactivate_app(pkgmgr_client *pc, const char *appid, uid_t uid)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(appid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");
	retvm_if(strlen(appid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkgid length over PKG_STRING_LEN_MAX ");

	pkgtype = _get_pkg_type_from_desktop_file(appid, uid);
	retvm_if(pkgtype == NULL, PKGMGR_R_EINVAL, "pkgtype is NULL");

	/* 2. generate req_key */
	req_key = __get_req_key(appid);
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_ACTIVATOR, pkgtype, appid, "0 APP", cookie, uid, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "request failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	free(req_key);
	return ret;
}

API int pkgmgr_client_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				      const char *appid, pkgmgr_mode mode)
{
	return pkgmgr_client_usr_clear_user_data(pc, pkg_type, appid,mode, GLOBAL_USER);
}
API int pkgmgr_client_usr_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				      const char *appid, pkgmgr_mode mode, uid_t uid)
{
	const char *pkgtype;
	char *installer_path;
	char *req_key;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret;
	char *cookie = NULL;

	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_REQUEST)
		return PKGMGR_R_EINVAL;

	/* 1. check argument */
	if (appid == NULL)
		return PKGMGR_R_EINVAL;


	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(appid, uid);
		if (pkgtype == NULL)
			return PKGMGR_R_EINVAL;
	} else
		pkgtype = pkg_type;

	if (strlen(appid) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	/* 2. get installer path using pkg_path */
	installer_path = _get_backend_path_with_type(pkgtype);
	if (installer_path == NULL)
		return PKGMGR_R_EINVAL;

	/* 3. generate req_key */
	req_key = __get_req_key(appid);

	/* 4. generate argv */

	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-c");
	/* argv[4] */
	argv[argcnt++] = strdup(appid);
	/* argv[5] -q option should be located at the end of command !! */
	if (mode == PM_QUIET)
		argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	if (args == NULL) {
		_LOGD("calloc failed");

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		return PKGMGR_R_ERROR;
	}
	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);
	/******************* end of quote ************************/

	/* 6. request clear */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_CLEARER, pkgtype, appid,
				  args, cookie, uid, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		free(args);
		return PKGMGR_R_ECOMM;
	}

	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	free(args);

	return PKGMGR_R_OK;
}


API int pkgmgr_client_set_status_type(pkgmgr_client *pc, int status_type)
{
	int ret = -1;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	retvm_if(status_type == PKGMGR_CLIENT_STATUS_ALL, PKGMGR_R_OK, "status_type is PKGMGR_CLIENT_STATUS_ALL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/*  free listening head */
	listen_cb_info *tmp = NULL;
	listen_cb_info *prev = NULL;
	for (tmp = mpc->info.listening.lhead; tmp;) {
		prev = tmp;
		tmp = tmp->next;
		free(prev);
	}

	/* free dbus connection */
	ret = comm_client_free(mpc->info.listening.cc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "comm_client_free() failed - %d", ret);

	/* Manage pc for seperated event */
	mpc->ctype = PC_LISTENING;
	mpc->status_type = status_type;

	mpc->info.listening.cc = comm_client_new();
	retvm_if(mpc->info.listening.cc == NULL, PKGMGR_R_EINVAL, "client creation failed");

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_INSTALL) == PKGMGR_CLIENT_STATUS_INSTALL) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_INSTALL, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "PKGMGR_CLIENT_STATUS_INSTALL failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_UNINSTALL) == PKGMGR_CLIENT_STATUS_UNINSTALL) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_UNINSTALL, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_UNINSTALL failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_MOVE) == PKGMGR_CLIENT_STATUS_MOVE) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_MOVE, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_MOVE failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_INSTALL_PROGRESS) == PKGMGR_CLIENT_STATUS_INSTALL_PROGRESS) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_INSTALL_PROGRESS, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_INSTALL_PROGRESS failed - %d", ret);
	}

   if ((mpc->status_type & PKGMGR_CLIENT_STATUS_UPGRADE) == PKGMGR_CLIENT_STATUS_UPGRADE) {
	   ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_UPGRADE, mpc->info.listening.cc, __status_callback, pc);
	   retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_UPGRADE failed - %d", ret);
   }

   return PKGMGR_R_OK;
}

API int pkgmgr_client_listen_status(pkgmgr_client *pc, pkgmgr_handler event_cb,
				    void *data)
{
	int req_id;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check input */
	retvm_if(mpc->ctype != PC_LISTENING, PKGMGR_R_EINVAL, "ctype is not PC_LISTENING");
	retvm_if(event_cb == NULL, PKGMGR_R_EINVAL, "event_cb is NULL");

	/* 1. get id */
	req_id = _get_request_id();

	/* 2. add callback info to pkgmgr_client */
	__add_stat_cbinfo(mpc, req_id, event_cb, data);
	return req_id;
}

API int pkgmgr_client_broadcast_status(pkgmgr_client *pc, const char *pkg_type,
				       const char *pkgid, const char *key,
				       const char *val)
{
	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	/* Check for valid arguments. NULL parameter causes DBUS to abort */
	if (pkgid == NULL || pkg_type == NULL || key == NULL || val == NULL) {
		_LOGD("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_BROADCAST)
		return PKGMGR_R_EINVAL;

	comm_status_broadcast_server_send_signal(COMM_STATUS_BROADCAST_ALL, mpc->info.broadcast.bc,
						 PKG_STATUS, pkg_type,
						 pkgid, key, val);

	return PKGMGR_R_OK;
}

API pkgmgr_info *pkgmgr_client_check_pkginfo_from_file(const char *pkg_path)
{
	return pkgmgr_info_new_from_file(NULL, pkg_path);
}

API int pkgmgr_client_free_pkginfo(pkgmgr_info * pkg_info)
{
	if (pkg_info == NULL)
		return PKGMGR_R_EINVAL;

	package_manager_pkg_detail_info_t *info = (package_manager_pkg_detail_info_t *)pkg_info;

	if (info->icon_buf)
		free(info->icon_buf);

	free(info);
	info = NULL;

	return PKGMGR_R_OK;
}

API int pkgmgr_client_request_service(pkgmgr_request_service_type service_type, int service_mode,
				  pkgmgr_client * pc, const char *pkg_type, const char *pkgid,
			      const char *custom_info, pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_usr_request_service(service_type, service_mode, pc, pkg_type, pkgid, GLOBAL_USER, custom_info, event_cb, data);
}

API int pkgmgr_client_usr_request_service(pkgmgr_request_service_type service_type, int service_mode,
				  pkgmgr_client * pc, const char *pkg_type, const char *pkgid, uid_t uid,
			      const char *custom_info, pkgmgr_handler event_cb, void *data)
{
	int ret =0;

	/* Check for NULL value of service type */
	retvm_if(service_type > PM_REQUEST_MAX, PKGMGR_R_EINVAL, "service type is not defined\n");
	retvm_if(service_type < 0, PKGMGR_R_EINVAL, "service type is error\n");
	vconf_set_int(VCONFKEY_PKGMGR_STATUS, -1);

	switch (service_type) {
	case PM_REQUEST_CSC:
		tryvm_if(custom_info == NULL, ret = PKGMGR_R_EINVAL, "custom_info is NULL\n");
		tryvm_if(strlen(custom_info) >= PKG_STRING_LEN_MAX, ret = PKGMGR_R_EINVAL, "optional_file over PKG_STRING_LEN_MAX");
		tryvm_if(data == NULL, ret = PKGMGR_R_EINVAL, "data is NULL\n");

		ret = __csc_process(custom_info, (char *)data);
		if (ret < 0)
			_LOGE("__csc_process fail \n");
		else
			ret = PKGMGR_R_OK;

		break;

	case PM_REQUEST_MOVE:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");
		tryvm_if((service_mode < PM_MOVE_TO_INTERNAL) || (service_mode > PM_MOVE_TO_SDCARD), ret = PKGMGR_R_EINVAL, "service_mode is wrong\n");

		ret = __move_pkg_process(pc, pkgid, uid, (pkgmgr_move_type)service_mode, event_cb, data);
		break;

	case PM_REQUEST_GET_SIZE:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");
		tryvm_if((service_mode < PM_GET_TOTAL_SIZE) || (service_mode >= PM_GET_MAX), ret = PKGMGR_R_EINVAL, "service_mode is wrong\n");

		ret = __get_size_process(pc, pkgid, uid, (pkgmgr_getsize_type)service_mode, event_cb, data);
		break;

	case PM_REQUEST_KILL_APP:
	case PM_REQUEST_CHECK_APP:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");

		ret = __check_app_process(service_type, pc, pkgid, uid, data);
		if (ret < 0)
			_LOGE("__check_app_process fail \n");
		else
			ret = PKGMGR_R_OK;

		break;

	default:
		_LOGE("Wrong Request\n");
		ret = -1;
		break;
	}

catch:

	return ret;
}


API int pkgmgr_client_usr_request_size_info(uid_t uid)
{
	int ret = 0;
	pkgmgr_client *pc = NULL;

	pc = pkgmgr_client_new(PC_REQUEST);
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "request pc is null\n");

	ret = __request_size_info(pc, uid);
	if (ret < 0) {
		_LOGE("__request_size_info fail \n");
	}

	pkgmgr_client_free(pc);
	return ret;
}

API int pkgmgr_client_request_size_info(void) // get all package size (data, total)
{
	return pkgmgr_client_usr_request_size_info(GLOBAL_USER);
}

API int pkgmgr_client_usr_clear_cache_dir(const char *pkgid, uid_t uid)
{
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "package id is null\n");

	int ret = 0;
	pkgmgr_client_t *pc = NULL;
	char *pkg_type = NULL;
	char *cookie = NULL;
	int is_type_malloced = 0;

	pkgmgrinfo_pkginfo_h handle = NULL;

	pc = pkgmgr_client_new(PC_REQUEST);
	retvm_if(pc == NULL, PKGMGR_R_ESYSTEM, "request pc is null\n");

	if (strcmp(pkgid, PKG_CLEAR_ALL_CACHE) != 0)
	{
		ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
		tryvm_if(ret < 0, ret = PKGMGR_R_ENOPKG, "pkgmgr_pkginfo_get_pkginfo failed");

		ret = pkgmgrinfo_pkginfo_get_type(handle, &pkg_type);
		tryvm_if(ret < 0, ret = PKGMGR_R_ESYSTEM, "pkgmgr_pkginfo_get_type failed");
	}
	else
	{
		pkg_type = (char *)malloc(strlen("rpm") + 1);
		strcpy(pkg_type, "rpm");
		is_type_malloced = 1;
	}

	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ESYSTEM, "__get_cookie_from_security_server is NULL");

	ret = comm_client_request(pc->info.request.cc, NULL, COMM_REQ_CLEAR_CACHE_DIR, pkg_type, pkgid, NULL, cookie, uid, 0);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "COMM_REQ_CLEAR_CACHE_DIR failed, ret=%d\n", ret);

	ret = PKGMGR_R_OK;
catch:
	if (cookie)
		free(cookie);

	if (pc)
		pkgmgr_client_free(pc);

	if(is_type_malloced)
		free(pkg_type);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return ret;
}

API int pkgmgr_client_clear_cache_dir(const char *pkgid)
{
	return pkgmgr_client_usr_clear_cache_dir(pkgid, GLOBAL_USER);
}

API int pkgmgr_client_clear_usr_all_cache_dir(uid_t uid)
{
	return pkgmgr_client_usr_clear_cache_dir(PKG_CLEAR_ALL_CACHE, uid);
}

API int pkgmgr_client_clear_all_cache_dir(void)
{
	int ret = 0;
	ret = pkgmgr_client_usr_clear_cache_dir(PKG_CLEAR_ALL_CACHE, GLOBAL_USER);
	return ret;
}

API int pkgmgr_client_get_size(pkgmgr_client * pc, const char *pkgid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_usr_get_size(pc, pkgid, get_type, event_cb, data, GLOBAL_USER);
}

API int pkgmgr_client_usr_get_size(pkgmgr_client * pc, const char *pkgid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data, uid_t uid)
{
	char *req_key = NULL;
	int ret =0;
	char *pkgtype = "rpm";
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int i = 0;
	char buf[128] = {'\0'};
	char *cookie = NULL;
	int req_id = 0;

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");
	retvm_if(event_cb == NULL, PKGMGR_R_EINVAL, "event_cb is NULL\n");
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL\n");

	req_key = __get_req_key(pkgid);
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	snprintf(buf, 128, "%d", get_type);
	argv[argcnt++] = strdup(pkgid);
	argv[argcnt++] = strdup(buf);
	argv[argcnt++] = strdup("-k");
	argv[argcnt++] = req_key;

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* request */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_GET_SIZE, pkgtype, pkgid, args, cookie, uid, 1);
	if (ret < 0)
		_LOGE("comm_client_request failed, ret=%d\n", ret);

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	return ret;
}

API int pkgmgr_client_usr_get_package_size_info(pkgmgr_client *pc, const char *pkgid, pkgmgr_pkg_size_info_receive_cb event_cb, void *user_data, uid_t uid)
{
	pkgmgrinfo_pkginfo_h pkginfo = NULL;
	char *req_key = NULL;
	int req_id = 0;
	int res = 0;
	int type = PM_GET_PKG_SIZE_INFO;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "The specified pc is NULL.");
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "The package id is NULL.");

	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0)
	{	// total package size info
		type = PM_GET_TOTAL_PKG_SIZE_INFO;
	}
	else
	{
		res = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &pkginfo);
		retvm_if(res != 0, PKGMGR_R_ENOPKG, "The package id is not installed.");

		if (pkginfo) {
			pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
		}
	}

	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	res = __change_op_cb_for_getsize(mpc);
	retvm_if(res < 0 , PKGMGR_R_ESYSTEM, "__change_op_cb_for_getsize is fail");

	req_key = __get_req_key(pkgid);
	retvm_if(req_key == NULL, PKGMGR_R_ESYSTEM, "req_key is NULL");

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, __get_pkg_size_info_cb, event_cb, user_data);

	res = __get_package_size_info(mpc, req_key, pkgid, type, uid);

	return res;
}

API int pkgmgr_client_get_package_size_info(pkgmgr_client *pc, const char *pkgid, pkgmgr_pkg_size_info_receive_cb event_cb, void *user_data)
{
	return pkgmgr_client_usr_get_package_size_info(pc, pkgid, event_cb, user_data, GLOBAL_USER);
}

API int pkgmgr_client_usr_get_total_package_size_info(pkgmgr_client *pc, pkgmgr_total_pkg_size_info_receive_cb event_cb, void *user_data, uid_t uid)
{	// total package size info
	return pkgmgr_client_usr_get_package_size_info(pc, PKG_SIZE_INFO_TOTAL, (pkgmgr_pkg_size_info_receive_cb)event_cb, user_data, uid);
}

API int pkgmgr_client_get_total_package_size_info(pkgmgr_client *pc, pkgmgr_total_pkg_size_info_receive_cb event_cb, void *user_data)
{
	return pkgmgr_client_usr_get_package_size_info(pc, PKG_SIZE_INFO_TOTAL, event_cb, user_data, GLOBAL_USER);
}

#define __START_OF_OLD_API
ail_cb_ret_e __appinfo_func(const ail_appinfo_h appinfo, void *user_data)
{
	char *type;
	char *package;
	char *version;

	iter_data *udata = (iter_data *) user_data;

	ail_appinfo_get_str(appinfo, AIL_PROP_X_SLP_PACKAGETYPE_STR, &type);
	if (type == NULL)
		type = "";
	ail_appinfo_get_str(appinfo, AIL_PROP_PACKAGE_STR, &package);
	if (package == NULL)
		package = "";
	ail_appinfo_get_str(appinfo, AIL_PROP_VERSION_STR, &version);
	if (version == NULL)
		version = "";

	if (udata->iter_fn(type, package, version, udata->data) != 0)
		return AIL_CB_RET_CANCEL;

	return AIL_CB_RET_CONTINUE;
}

API int pkgmgr_get_pkg_list(pkgmgr_iter_fn iter_fn, void *data, uid_t uid)
{
	int cnt = -1;
	ail_filter_h filter;
	ail_error_e ret;

	if (iter_fn == NULL)
		return PKGMGR_R_EINVAL;

	ret = ail_filter_new(&filter);
	if (ret != AIL_ERROR_OK) {
		return PKGMGR_R_ERROR;
	}

	ret = ail_filter_add_str(filter, AIL_PROP_TYPE_STR, "Application");
	if (ret != AIL_ERROR_OK) {
		ail_filter_destroy(filter);
		return PKGMGR_R_ERROR;
	}

	ret = ail_filter_add_bool(filter, AIL_PROP_X_SLP_REMOVABLE_BOOL, true);
	if (ret != AIL_ERROR_OK) {
		ail_filter_destroy(filter);
		return PKGMGR_R_ERROR;
	}
	
	if(uid != GLOBAL_USER)
		ret = ail_filter_count_usr_appinfo(filter, &cnt, uid);
	else
		ret = ail_filter_count_appinfo(filter, &cnt);
	if (ret != AIL_ERROR_OK) {
		ail_filter_destroy(filter);
		return PKGMGR_R_ERROR;
	}

	iter_data *udata = calloc(1, sizeof(iter_data));
	if (udata == NULL) {
		_LOGE("calloc failed");
		ail_filter_destroy(filter);

		return PKGMGR_R_ERROR;
	}
	udata->iter_fn = iter_fn;
	udata->data = data;
	
	if(uid != GLOBAL_USER)
		ail_filter_list_usr_appinfo_foreach(filter, __appinfo_func, udata, uid);
	else
		ail_filter_list_appinfo_foreach(filter, __appinfo_func, udata);
	free(udata);

	ret = ail_filter_destroy(filter);
	if (ret != AIL_ERROR_OK) {
		return PKGMGR_R_ERROR;
	}

	return PKGMGR_R_OK;
}

API pkgmgr_info *pkgmgr_info_new(const char *pkg_type, const char *pkgid)
{
	return pkgmgr_info_usr_new(pkg_type, pkgid, GLOBAL_USER);
}
API pkgmgr_info *pkgmgr_info_usr_new(const char *pkg_type, const char *pkgid, uid_t uid)
{
	const char *pkgtype;
	pkg_plugin_set *plugin_set = NULL;
	package_manager_pkg_detail_info_t *pkg_detail_info = NULL;

	/* 1. check argument */
	if (pkgid == NULL)
		return NULL;

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkgid, uid);
		if (pkgtype == NULL)
			return NULL;
	} else
		pkgtype = pkg_type;

	if (strlen(pkgid) >= PKG_STRING_LEN_MAX)
		return NULL;

	pkg_detail_info = calloc(1, sizeof(package_manager_pkg_detail_info_t));
	if (pkg_detail_info == NULL) {
		_LOGE("*** Failed to alloc package_handler_info.\n");
		return NULL;
	}

	plugin_set = _package_manager_load_library(pkgtype);
	if (plugin_set == NULL) {
		_LOGE("*** Failed to load library");
		free(pkg_detail_info);
		return NULL;
	}

	if (plugin_set->pkg_is_installed) {
		if (plugin_set->pkg_is_installed(pkgid) != 0) {
			_LOGE("*** Failed to call pkg_is_installed()");
			free(pkg_detail_info);
			return NULL;
		}

		if (plugin_set->get_pkg_detail_info) {
			if (plugin_set->get_pkg_detail_info(pkgid,
							    pkg_detail_info) != 0) {
				_LOGE("*** Failed to call get_pkg_detail_info()");
				free(pkg_detail_info);
				return NULL;
			}
		}
	}

	return (pkgmgr_info *) pkg_detail_info;
}

API char * pkgmgr_info_get_string(pkgmgr_info * pkg_info, const char *key)
{
	package_manager_pkg_detail_info_t *pkg_detail_info;

	if (pkg_info == NULL)
		return NULL;
	if (key == NULL)
		return NULL;

	pkg_detail_info = (package_manager_pkg_detail_info_t *) pkg_info;

	return _get_info_string(key, pkg_detail_info);
}

API pkgmgr_info *pkgmgr_info_new_from_file(const char *pkg_type,
					   const char *pkg_path)
{
	pkg_plugin_set *plugin_set = NULL;
	package_manager_pkg_detail_info_t *pkg_detail_info = NULL;
	char *pkgtype;
	if (pkg_path == NULL) {
		_LOGE("pkg_path is NULL\n");
		return NULL;
	}

	if (strlen(pkg_path) > PKG_URL_STRING_LEN_MAX) {
		_LOGE("length of pkg_path is too long - %d.\n",
		      strlen(pkg_path));
		return NULL;
	}

	pkg_detail_info = calloc(1, sizeof(package_manager_pkg_detail_info_t));
	if (pkg_detail_info == NULL) {
		_LOGE("*** Failed to alloc package_handler_info.\n");
		return NULL;
	}

	if (pkg_type == NULL)
		pkgtype = __get_type_from_path(pkg_path);
	else
		pkgtype = strdup(pkg_type);

	plugin_set = _package_manager_load_library(pkgtype);
	if (plugin_set == NULL) {
		free(pkg_detail_info);
		free(pkgtype);
		return NULL;
	}

	if (plugin_set->get_pkg_detail_info_from_package) {
		if (plugin_set->get_pkg_detail_info_from_package(pkg_path,
								 pkg_detail_info) != 0) {
			free(pkg_detail_info);
			free(pkgtype);
			return NULL;
		}
	}

	free(pkgtype);
	return (pkgmgr_info *) pkg_detail_info;
}

API int pkgmgr_info_free(pkgmgr_info * pkg_info)
{
	if (pkg_info == NULL)
		return PKGMGR_R_EINVAL;

	free(pkg_info);
	pkg_info = NULL;

	return 0;
}

#define __END_OF_OLD_API

API int pkgmgr_pkginfo_get_list(pkgmgr_info_pkg_list_cb pkg_list_cb, void *user_data)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_list(pkg_list_cb, user_data);
	return ret;
}

API int pkgmgr_pkginfo_get_usr_list(pkgmgr_info_pkg_list_cb pkg_list_cb, void *user_data, uid_t uid)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_usr_list(pkg_list_cb, user_data, uid);
	return ret;
}


API int pkgmgr_pkginfo_get_usr_pkginfo(const char *pkgid, uid_t uid, pkgmgr_pkginfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, handle);
	return ret;
}


API int pkgmgr_pkginfo_get_pkginfo(const char *pkgid, pkgmgr_pkginfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, handle);
	return ret;
}



API int pkgmgr_pkginfo_get_pkgname(pkgmgr_pkginfo_h handle, char **pkg_name)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_pkgname(handle, pkg_name);
	return ret;
}


API int pkgmgr_pkginfo_get_pkgid(pkgmgr_pkginfo_h handle, char **pkgid)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, pkgid);
	return ret;
}

API int pkgmgr_pkginfo_get_type(pkgmgr_pkginfo_h handle, char **type)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_type(handle, type);
	return ret;
}

API int pkgmgr_pkginfo_get_version(pkgmgr_pkginfo_h handle, char **version)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_version(handle, version);
	return ret;
}

API int pkgmgr_pkginfo_get_install_location(pkgmgr_pkginfo_h handle, pkgmgr_install_location *location)
{
	int ret = 0;
	pkgmgrinfo_install_location loc;
	ret = pkgmgrinfo_pkginfo_get_install_location(handle, &loc);
	*location = loc;
	return ret;
}

API int pkgmgr_pkginfo_get_package_size(pkgmgr_pkginfo_h handle, int *size)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_package_size(handle, size);
	return ret;
}

API int pkgmgr_pkginfo_get_icon(pkgmgr_pkginfo_h handle, char **icon)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_icon(handle, icon);
	return ret;
}

API int pkgmgr_pkginfo_get_label(pkgmgr_pkginfo_h handle, char **label)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_label(handle, label);
	return ret;
}

API int pkgmgr_pkginfo_get_description(pkgmgr_pkginfo_h handle, char **description)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_description(handle, description);
	return ret;
}

API int pkgmgr_pkginfo_get_author_name(pkgmgr_pkginfo_h handle, char **author_name)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_author_name(handle, author_name);
	return ret;
}

API int pkgmgr_pkginfo_get_author_email(pkgmgr_pkginfo_h handle, char **author_email)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_author_email(handle, author_email);
	return ret;
}

API int pkgmgr_pkginfo_get_author_href(pkgmgr_pkginfo_h handle, char **author_href)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_author_href(handle, author_href);
	return ret;
}

API int pkgmgr_pkginfo_is_removable(pkgmgr_pkginfo_h handle, bool *removable)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_is_removable(handle, removable);
	return ret;
}

API int pkgmgr_pkginfo_is_preload(pkgmgr_pkginfo_h handle, bool *preload)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_is_preload(handle, preload);
	return ret;
}

API int pkgmgr_pkginfo_is_readonly(pkgmgr_pkginfo_h handle, bool *readonly)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_is_readonly(handle, readonly);
	return ret;
}

API int pkgmgr_pkginfo_is_for_all_users(pkgmgr_pkginfo_h handle, bool *for_all_users)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_is_for_all_users(handle, for_all_users);
	return ret;
}

API int pkgmgr_pkginfo_is_accessible(pkgmgr_pkginfo_h handle, bool *accessible)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_is_accessible(handle, accessible);
	return ret;
}

API int pkgmgr_pkginfo_destroy_pkginfo(pkgmgr_pkginfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	return ret;
}

API int pkgmgr_pkginfo_get_installed_storage(pkgmgr_pkginfo_h handle, pkgmgr_installed_storage *storage)
{
	int ret = 0;
	pkgmgrinfo_installed_storage sto;
	ret = pkgmgrinfo_pkginfo_get_installed_storage(handle, &sto);
	*storage = sto;
	return ret;
}

API int pkgmgr_pkginfo_get_installed_time(pkgmgr_pkginfo_h handle, int *installed_time)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_installed_time(handle, installed_time);
	return ret;
}

API int pkgmgr_appinfo_get_list(pkgmgr_pkginfo_h handle, pkgmgr_app_component component,
							pkgmgr_info_app_list_cb app_func, void *user_data)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_list(handle, component, app_func, user_data);
	return ret;
}

API int pkgmgr_appinfo_get_usr_list(pkgmgr_pkginfo_h handle, pkgmgr_app_component component,
							pkgmgr_info_app_list_cb app_func, void *user_data, uid_t uid)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_usr_list(handle, component, app_func, user_data, uid);
	return ret;
}

API int pkgmgr_appinfo_foreach_category(pkgmgr_appinfo_h handle, pkgmgr_info_app_category_list_cb category_func,
							void *user_data)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_foreach_category(handle, category_func, user_data);
	return ret;
}

API int pkgmgr_appinfo_get_appinfo(const char *appid, pkgmgr_appinfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_appinfo(appid, handle);
	return ret;
}

API int pkgmgr_appinfo_get_appid(pkgmgr_appinfo_h  handle, char **appid)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_appid(handle, appid);
	return ret;
}

API int pkgmgr_appinfo_get_pkgname(pkgmgr_appinfo_h  handle, char **pkg_name)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_pkgname(handle, pkg_name);
	return ret;
}

API int pkgmgr_appinfo_get_pkgid(pkgmgr_appinfo_h  handle, char **pkgid)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_pkgid(handle, pkgid);
	return ret;
}

API int pkgmgr_appinfo_get_icon(pkgmgr_appinfo_h handle, char **icon)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_icon(handle, icon);
	return ret;
}

API int pkgmgr_appinfo_get_label(pkgmgr_appinfo_h handle, char **label)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_label(handle, label);
	return ret;
}

API int pkgmgr_appinfo_get_exec(pkgmgr_appinfo_h  handle, char **exec)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_exec(handle, exec);
	return ret;
}

API int pkgmgr_appinfo_get_component(pkgmgr_appinfo_h  handle, pkgmgr_app_component *component)
{
	int ret = 0;
	pkgmgrinfo_app_component comp;
	ret = pkgmgrinfo_appinfo_get_component(handle, &comp);
	*component = comp;
	return ret;
}

API int pkgmgr_appinfo_get_apptype(pkgmgr_appinfo_h  handle, char **app_type)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_apptype(handle, app_type);
	return ret;
}

API int pkgmgr_appinfo_is_nodisplay(pkgmgr_appinfo_h  handle, bool *nodisplay)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_is_nodisplay(handle, nodisplay);
	return ret;
}

API int pkgmgr_appinfo_is_multiple(pkgmgr_appinfo_h  handle, bool *multiple)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_is_multiple(handle, multiple);
	return ret;
}

API int pkgmgr_appinfo_is_taskmanage(pkgmgr_appinfo_h  handle, bool *taskmanage)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_is_taskmanage(handle, taskmanage);
	return ret;
}

API int pkgmgr_appinfo_get_hwacceleration(pkgmgr_appinfo_h  handle, pkgmgr_hwacceleration_type *hwacceleration)
{
	int ret = 0;
	pkgmgrinfo_app_hwacceleration hwacc;
	ret = pkgmgrinfo_appinfo_get_hwacceleration(handle, &hwacc);
	*hwacceleration = hwacc;
	return ret;
}

API int pkgmgr_appinfo_is_onboot(pkgmgr_appinfo_h  handle, bool *onboot)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_is_onboot(handle, onboot);
	return ret;
}

API int pkgmgr_appinfo_is_autorestart(pkgmgr_appinfo_h  handle, bool *autorestart)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_is_autorestart(handle, autorestart);
	return ret;
}

API int pkgmgr_appinfo_destroy_appinfo(pkgmgr_appinfo_h  handle)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_destroy_appinfo(handle);
	return ret;
}

API int pkgmgr_pkginfo_create_certinfo(pkgmgr_certinfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_create_certinfo(handle);
	return ret;
}

API int pkgmgr_pkginfo_load_certinfo(const char *pkgid, pkgmgr_certinfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, handle);
	return ret;
}

API int pkgmgr_pkginfo_get_cert_value(pkgmgr_certinfo_h handle, pkgmgr_cert_type cert_type, const char **cert_value)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_cert_value(handle, cert_type, cert_value);
	return ret;
}

API int pkgmgr_pkginfo_destroy_certinfo(pkgmgr_certinfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_destroy_certinfo(handle);
	return ret;
}

API int pkgmgr_datacontrol_get_info(const char *providerid, const char * type, char **appid, char **access)
{
	int ret = 0;
	ret = pkgmgrinfo_datacontrol_get_info(providerid, type, appid, access);
	return ret;
}
