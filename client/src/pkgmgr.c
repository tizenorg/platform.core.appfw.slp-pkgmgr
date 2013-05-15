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
#include <aul.h>
#include <vconf.h>
#include <db-util.h>
#include <pkgmgr-info.h>
#include <iniparser.h>

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

#define PKG_TMP_PATH "/opt/usr/apps/tmp"

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
} pkgmgr_client_t;

typedef struct _iter_data {
	pkgmgr_iter_fn iter_fn;
	void *data;
} iter_data;

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
			    const char *req_key, pkgmgr_handler event_cb,
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

		pkgtype = iniparser_getstr(csc, type_buf);
		des = iniparser_getstr(csc, des_buf);
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

static int __get_size_process(pkgmgr_client * pc, const char *pkgid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data)
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
	char size_info_file[PKG_STRING_LEN_MAX] = {'\0', };
	int pkg_size = 0;
	int check_cnt = 0;
	FILE *fp;
	char buffer[PKG_ARGC_MAX] = {'\0', };

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_pkginfo failed");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_type failed");

	installer_path = _get_backend_path_with_type(pkgtype);
	req_key = __get_req_key(pkgid);
	req_id = _get_request_id();

	snprintf(buf, 128, "%d", get_type);
	argv[argcnt++] = installer_path;
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-d");
	/* argv[4] */
	argv[argcnt++] = strdup(pkgid);
	/* argv[5] */
	argv[argcnt++] = strdup("-t");
	/* argv[6] */
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

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_GET_SIZE, pkgtype, pkgid, args, NULL, 1);

	snprintf(size_info_file, PKG_STRING_LEN_MAX, "%s/%s", PKG_TMP_PATH, req_key);
	while(1)
	{
		check_cnt ++;
		if (access(size_info_file, F_OK) != 0) {
			_LOGD("file is not generated yet.... wait\n", size_info_file);
			usleep(10 * 1000);	/* 10ms sleep*/
		} else {
			_LOGD("size_info_file file is generated!!\n");

			fp = fopen(size_info_file, "r");
			if (fp == NULL) {
				_LOGE("fopen failed\n");
				break;
			}
			fread(&buffer, sizeof(buffer), 1, fp);
			fclose(fp);

			pkg_size = atoi(buffer);
			_LOGD("pkg_sizepkg_size  == > %d!!\n", pkg_size);

			break;
		}

		if (check_cnt > 500) {	/* 5s time over*/
			_LOGD("wait time over!!\n");
			break;
		}
	}

	const char *rm_argv[] = { "/bin/rm", "-rf", size_info_file, NULL };
	ret = __xsystem(rm_argv);
	if (ret < 0)
		_LOGE("__xsystem failed, ret=%d\n", ret);

	ret = pkg_size;
	if (ret < 0)
		_LOGE("request failed, ret=%d\n", ret);

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	return ret;
}

static int __move_pkg_process(pkgmgr_client * pc, const char *pkgid, pkgmgr_move_type move_type, pkgmgr_handler event_cb, void *data)
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

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_pkginfo failed");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_type failed");

	installer_path = _get_backend_path_with_type(pkgtype);
	req_key = __get_req_key(pkgid);
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, data);

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

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_MOVER, pkgtype, pkgid, args, NULL, 1);
	if (ret < 0)
		_LOGE("request failed, ret=%d\n", ret);

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	return ret;
}

static int __kill_app_process(pkgmgr_client * pc, const char *pkgid)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
	pkgmgrinfo_pkginfo_h handle;

	/* Check for NULL value of pc */
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_pkginfo failed");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_type failed");

	/* 2. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_KILL_APP, pkgtype, pkgid, NULL, NULL, 1);
	if (ret < 0)
		_LOGE("request failed, ret=%d\n", ret);

catch:
	free(req_key);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return ret;

}

API pkgmgr_client *pkgmgr_client_new(client_type ctype)
{
	pkgmgr_client_t *pc = NULL;
	int ret = -1;

	if (ctype != PC_REQUEST && ctype != PC_LISTENING
	    && ctype != PC_BROADCAST)
		return NULL;

	/* Allocate memory for ADT:pkgmgr_client */
	pc = calloc(1, sizeof(pkgmgr_client_t));
	if (pc == NULL) {
		_LOGE("No memory");
		return NULL;
	}

	/* Manage pc */
	pc->ctype = ctype;

	if (pc->ctype == PC_REQUEST) {
		pc->info.request.cc = comm_client_new();
		if (pc->info.request.cc == NULL) {
			_LOGE("client creation failed");
			goto err;
		}
		ret = comm_client_set_status_callback(pc->info.request.cc,
						      __operation_callback, pc);
		if (ret < 0) {
			_LOGE("comm_client_set_status_callback() failed - %d",
			      ret);
			goto err;
		}
	} else if (pc->ctype == PC_LISTENING) {
		pc->info.listening.cc = comm_client_new();
		if (pc->info.listening.cc == NULL) {
			_LOGE("client creation failed");
			goto err;
		}
		ret = comm_client_set_status_callback(pc->info.listening.cc,
						      __status_callback, pc);
		if (ret < 0) {
			_LOGE("comm_client_set_status_callback() failed - %d",
			      ret);
			goto err;
		}
	} else if (pc->ctype == PC_BROADCAST) {
		pc->info.broadcast.bc = comm_status_broadcast_server_connect();
		if (pc->info.broadcast.bc == NULL) {
			_LOGE("client creation failed");
			goto err;
		}
		ret = 0;
	}

	return (pkgmgr_client *) pc;

 err:
	if (pc)
		free(pc);
	return NULL;
}

API int pkgmgr_client_free(pkgmgr_client *pc)
{
	int ret = -1;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	if (mpc == NULL) {
		_LOGE("Invalid argument");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype == PC_REQUEST) {
		req_cb_info *tmp;
		req_cb_info *prev;
		for (tmp = mpc->info.request.rhead; tmp;) {
			prev = tmp;
			tmp = tmp->next;
			free(prev);
		}

		ret = comm_client_free(mpc->info.request.cc);
		if (ret < 0) {
			_LOGE("comm_client_free() failed - %d", ret);
			goto err;
		}
	} else if (mpc->ctype == PC_LISTENING) {
		listen_cb_info *tmp;
		listen_cb_info *prev;
		for (tmp = mpc->info.listening.lhead; tmp;) {
			prev = tmp;
			tmp = tmp->next;
			free(prev);
		}

		ret = comm_client_free(mpc->info.listening.cc);
		if (ret < 0) {
			_LOGE("comm_client_free() failed - %d", ret);
			goto err;
		}
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

 err:
	if (mpc) {
		free(mpc);
		mpc = NULL;
	}
	return PKGMGR_R_ERROR;
}

API int pkgmgr_client_install(pkgmgr_client * pc, const char *pkg_type,
			      const char *descriptor_path, const char *pkg_path,
			      const char *optional_file, pkgmgr_mode mode,
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
	if (descriptor_path) {
		if (strlen(descriptor_path) >= PKG_STRING_LEN_MAX)
			return PKGMGR_R_EINVAL;

		if (access(descriptor_path, F_OK) != 0)
			return PKGMGR_R_EINVAL;
	}

	if (pkg_path == NULL)
		return PKGMGR_R_EINVAL;
	else {
		if (strlen(pkg_path) >= PKG_STRING_LEN_MAX)
			return PKGMGR_R_EINVAL;

		if (access(pkg_path, F_OK) != 0)
			return PKGMGR_R_EINVAL;
	}

	if (optional_file) {
		if (strlen(optional_file) >= PKG_STRING_LEN_MAX)
			return PKGMGR_R_EINVAL;
	}

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
		return PKGMGR_R_EINVAL;
	}

	/* 3. generate req_key */
	req_key = __get_req_key(pkg_path);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, data);

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
	if (args == NULL) {
		_LOGD("calloc failed");

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		free(pkgtype);
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
				  COMM_REQ_TO_INSTALLER, pkgtype, pkg_path,
				  args, cookie, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);

		for (i = 0; i < argcnt; i++)
			free(argv[i]);
		free(args);
		free(pkgtype);
		return PKGMGR_R_ECOMM;
	}

	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	free(args);
	free(pkgtype);

	return req_id;
}

API int pkgmgr_client_reinstall(pkgmgr_client * pc, const char *pkg_type, const char *pkgid,
				  const char *optional_file, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data)
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
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, data);

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
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALLER, pkgtype, pkgid, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "request failed");

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	free(args);
	free(pkgtype);

	return ret;
}

API int pkgmgr_client_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_mode mode,
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

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retv_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL);

	/* 1. check argument */
	retv_if(pkgid == NULL, PKGMGR_R_EINVAL);

	pkgmgr_pkginfo_h handle;
	ret = pkgmgr_pkginfo_get_pkginfo(pkgid, &handle);

	/*check package id	*/
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_pkginfo_get_pkginfo fail");
	tryvm_if(handle == NULL, ret = PKGMGR_R_EINVAL, "Pkgid(%s) can not find in installed pkg DB! \n", pkgid);

	/*check running app , terminate app if it is running*/
	ret = pkgmgr_appinfo_get_list(handle, PM_UI_APP, __app_list_cb, NULL);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_appinfo_get_list : PM_UI_APP fail");

	/*check running app , terminate app if it is running*/
	ret = pkgmgr_appinfo_get_list(handle, PM_SVC_APP, __app_list_cb, NULL);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_appinfo_get_list : PM_SVC_APP fail");

	/*check type	*/
	ret = pkgmgr_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_pkginfo_get_type fail");
	tryvm_if(pkgtype == NULL, ret = PKGMGR_R_ERROR, "pkgtype is NULL");

	/*check pkgid length	*/
	tryvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, ret = PKGMGR_R_EINVAL, "pkgid is too long");

	/* 2. get installer path using pkgtype */
	installer_path = _get_backend_path_with_type(pkgtype);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	/* 3. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, data);

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
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALLER, pkgtype, pkgid, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "calloc failed");

	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	free(args);

	pkgmgr_pkginfo_destroy_pkginfo(handle);
	return req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);

	pkgmgr_pkginfo_destroy_pkginfo(handle);
	PKGMGR_END();\
	return ret;
}

API int pkgmgr_client_move(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_move_type move_type, pkgmgr_mode mode)
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
		pkgtype = _get_pkg_type_from_desktop_file(pkgid);
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
				  args, cookie, 1);
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

	return req_id;
}

API int pkgmgr_client_activate(pkgmgr_client * pc, const char *pkg_type,
			       const char *pkgid)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
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
	if (pkgid == NULL)
		return PKGMGR_R_EINVAL;

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkgid);
		if (pkgtype == NULL)
			return PKGMGR_R_EINVAL;
	} else
		pkgtype = pkg_type;

	if (strlen(pkgid) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	/* 2. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_ACTIVATOR, pkgtype,
				  pkgid, "1 PKG", cookie, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);
		free(req_key);
		return PKGMGR_R_ECOMM;
	}

	free(req_key);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkgid)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
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
	if (pkgid == NULL)
		return PKGMGR_R_EINVAL;

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkgid);
		if (pkgtype == NULL)
			return PKGMGR_R_EINVAL;
	} else
		pkgtype = pkg_type;

	if (strlen(pkgid) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	/* 2. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_ACTIVATOR, pkgtype,
				  pkgid, "0 PKG", cookie, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);
		free(req_key);
		return PKGMGR_R_ECOMM;
	}

	free(req_key);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_activate_app(pkgmgr_client * pc, const char *appid)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
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

	if (strlen(appid) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	pkgtype = _get_pkg_type_from_desktop_file(appid);

	/* 2. generate req_key */
	req_key = __get_req_key(appid);

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_ACTIVATOR, pkgtype,
				  appid, "1 APP", cookie, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);
		free(req_key);
		return PKGMGR_R_ECOMM;
	}

	free(req_key);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_activate_appv(pkgmgr_client * pc, const char *appid, char *const argv[])
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

	if (strlen(appid) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	pkgtype = _get_pkg_type_from_desktop_file(appid);

	/* 2. generate req_key */
	req_key = __get_req_key(appid);

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
			if (args == NULL) {
				_LOGE("calloc failed");
				free(req_key);
				return PKGMGR_R_ERROR;
			}
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
	if (argsr == NULL) {
		_LOGE("calloc failed");
		free(req_key);
		free(args);
		return PKGMGR_R_ERROR;
	}
	strncpy(argsr, "1 APP", strlen("1 APP"));
	if (argcnt) {
		strncat(argsr, " ", strlen(" "));
		strncat(argsr, args, strlen(args));
	}

	_LOGD("argsr [%s]\n", argsr);
	/******************* end of quote ************************/

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_ACTIVATOR, pkgtype,
				  appid, argsr, cookie, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);
		free(req_key);
		free(args);
		free(argsr);
		return PKGMGR_R_ECOMM;
	}

	free(req_key);
	free(args);
	free(argsr);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_deactivate_app(pkgmgr_client *pc, const char *appid)
{
	const char *pkgtype;
	char *req_key;
	char *cookie = NULL;
	int ret;
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

	if (strlen(appid) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	pkgtype = _get_pkg_type_from_desktop_file(appid);

	/* 2. generate req_key */
	req_key = __get_req_key(appid);

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key,
				  COMM_REQ_TO_ACTIVATOR, pkgtype,
				  appid, "0 APP", cookie, 1);
	if (ret < 0) {
		_LOGE("request failed, ret=%d\n", ret);
		free(req_key);
		return PKGMGR_R_ECOMM;
	}

	free(req_key);

	return PKGMGR_R_OK;
}


API int pkgmgr_client_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				      const char *appid, pkgmgr_mode mode)
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
		pkgtype = _get_pkg_type_from_desktop_file(appid);
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
				  args, cookie, 1);
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

API int pkgmgr_client_listen_status(pkgmgr_client *pc, pkgmgr_handler event_cb,
				    void *data)
{
	int req_id;
	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_LISTENING)
		return PKGMGR_R_EINVAL;

	/* 1. check argument */
	if (event_cb == NULL)
		return PKGMGR_R_EINVAL;

	/* 2. add callback info to pkgmgr_client */
	req_id = _get_request_id();
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

	comm_status_broadcast_server_send_signal(mpc->info.broadcast.bc,
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
	int ret =0;

	/* Check for NULL value of service type */
	retvm_if(service_type > PM_REQUEST_MAX, PKGMGR_R_EINVAL, "service type is not defined\n");
	retvm_if(service_type < 0, PKGMGR_R_EINVAL, "service type is error\n");

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

		ret = __move_pkg_process(pc, pkgid, (pkgmgr_move_type)service_mode, event_cb, data);
		if (ret < 0)
			_LOGE("__move_pkg_process fail \n");
		else
			ret = PKGMGR_R_OK;

		break;

	case PM_REQUEST_GET_SIZE:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");
		tryvm_if((service_mode < PM_GET_TOTAL_SIZE) || (service_mode > PM_GET_DATA_SIZE), ret = PKGMGR_R_EINVAL, "service_mode is wrong\n");

		ret = __get_size_process(pc, pkgid, (pkgmgr_getsize_type)service_mode, event_cb, data);
		if (ret < 0)
			_LOGE("__get_size_process fail \n");

		break;

	case PM_REQUEST_KILL_APP:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");

		ret = __kill_app_process(pc, pkgid);
		if (ret < 0)
			_LOGE("__kill_app_process fail \n");
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

API int pkgmgr_get_pkg_list(pkgmgr_iter_fn iter_fn, void *data)
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
	const char *pkgtype;
	pkg_plugin_set *plugin_set = NULL;
	package_manager_pkg_detail_info_t *pkg_detail_info = NULL;

	/* 1. check argument */
	if (pkgid == NULL)
		return NULL;

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkgid);
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
