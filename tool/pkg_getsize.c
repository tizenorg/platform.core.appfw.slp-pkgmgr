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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkgmgr-info.h>
#include <vconf.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "pkgmgr-debug.h"
#include "package-manager.h"
#include "pkgmgr_installer.h"

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR"
#endif				/* LOG_TAG */

#define MAX_PKG_BUF_LEN	1024
#define BLOCK_SIZE      4096 /*in bytes*/

#define PKG_TMP_PATH "/opt/usr/apps/tmp"
#define PKG_RW_PATH "/opt/usr/apps/"
#define PKG_RO_PATH "/usr/apps/"

long long __get_dir_size(int dfd)
{
    long long size = 0;
    struct stat f_stat;
    DIR *dir;
    struct dirent *de;
    long long tmp_size = 0;

    dir = fdopendir(dfd);
    if (dir == NULL) {
    	_LOGE("Couldn't open the directory\n");
    	close(dfd);
        return 0;
    }

    while ((de = readdir(dir))) {
        const char *name = de->d_name;
        if (name[0] == '.') {
            if (name[1] == 0)
                continue;
            if ((name[1] == '.') && (name[2] == 0))
                continue;
        }

        if (fstatat(dfd, name, &f_stat, AT_SYMLINK_NOFOLLOW) == 0) {
       	 size += f_stat.st_blocks * 512;
        }
        if (de->d_type == DT_DIR) {
            int subfd;

            subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
            if (subfd >= 0) {
            	tmp_size = __get_dir_size(subfd);
            	size += tmp_size;
            }
        }
    }
    closedir(dir);
    return size;
}

long long __get_pkg_size(char *path)
{
	long long size;
	DIR *dir;
	int dfd;
	struct stat f_stat;
	if (path == NULL){
		_LOGE("path is NULL");
		return -1;
	}

	if (lstat(path, &f_stat) == 0) {
		if (!S_ISLNK(f_stat.st_mode)) {
			dir = opendir(path);
			if (dir == NULL) {
				_LOGE("Couldn't open the directory %s \n", path);
				return -1;
			}
			dfd = dirfd(dir);

			size = __get_dir_size(dfd);
			if (size > 0) {
				 size = size + f_stat.st_blocks * 512;
			}
			else {
				_LOGE("Couldn't open the directory\n");
				return -1;
			}
		}
	}
	else {
		_LOGE("Couldn't lstat the directory %s %d \n", path, errno);
		return -1;
	}

	return size;
}

static int __get_total_size(char *pkgid, int *size)

{
	char device_path[MAX_PKG_BUF_LEN] = { '\0', };
	long long rw_size = 0;
	long long ro_size= 0;
	long long tmp_size= 0;
	long long total_size= 0;

	/* RW area */
	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/bin", PKG_RW_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		rw_size += tmp_size;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/info", PKG_RW_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		rw_size += tmp_size;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/res", PKG_RW_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		rw_size += tmp_size;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/data", PKG_RW_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		rw_size += tmp_size;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/shared", PKG_RW_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		rw_size += tmp_size;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/setting", PKG_RW_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		rw_size += tmp_size;
#if 0
	/* RO area */
	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/bin", PKG_RO_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		ro_size += tmp_size;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/info", PKG_RO_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		ro_size += tmp_size;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/res", PKG_RO_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		ro_size += tmp_size;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/data", PKG_RO_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		ro_size += tmp_size;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/shared", PKG_RO_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		ro_size += tmp_size;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/setting", PKG_RO_PATH, pkgid);
	tmp_size = __get_pkg_size(device_path);
	if (tmp_size > 0)
		ro_size += tmp_size;
#endif

	/* Total size */
	total_size = rw_size + ro_size;
	*size = (int)total_size;

	return PMINFO_R_OK;
}

static int __get_data_size(char *pkgid, int *size)
{
	char device_path[MAX_PKG_BUF_LEN] = { '\0', };
	long long total_size= 0;

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/data", PKG_RW_PATH, pkgid);
	if (access(device_path, R_OK) == 0)
		total_size = __get_pkg_size(device_path);
	if (total_size < 0)
		return PMINFO_R_ERROR;

	*size = (int)total_size;

	return PMINFO_R_OK;
}

static int __pkg_list_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid;

	int size = 0;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if(ret < 0) {
		printf("pkgmgr_pkginfo_get_pkgid() failed\n");
	}

	__get_total_size(pkgid, &size);

	* (int *) user_data += size;

	_LOGD("pkg=[%s], size=[%d]\n", pkgid, size);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int size = 0;
	int get_type = 0;
	char *pkgid = NULL;
	pkgmgr_installer *pi;
	char buf[MAX_PKG_BUF_LEN] = {'\0'};

	pkgid = argv[0];
	get_type = atoi(argv[1]);

	if (get_type == PM_GET_TOTAL_SIZE) {
		ret = __get_total_size(pkgid, &size);
	} else if(get_type == PM_GET_DATA_SIZE) {
		ret = __get_data_size(pkgid, &size);
	} else if(get_type == PM_GET_ALL_PKGS) {
		ret = pkgmgrinfo_pkginfo_get_list(__pkg_list_cb, &size);
	}
	if (ret < 0)
		_LOGD("_pkg_getsize fail \n");
	else
		_LOGD("_pkg_getsize success \n");

	pi = pkgmgr_installer_new();
	if (!pi) {
		_LOGD("Failure in creating the pkgmgr_installer object");
	} else {
		pkgmgr_installer_receive_request(pi, argc, argv);
		snprintf(buf, MAX_PKG_BUF_LEN - 1, "%d", size);
		pkgmgr_installer_send_signal(pi, "get-size", pkgid, "get-size", buf);
		pkgmgr_installer_free(pi);
	}

	vconf_set_int(VCONFKEY_PKGMGR_STATUS, size);
	return 0;
}
