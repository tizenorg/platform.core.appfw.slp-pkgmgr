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

#include "pkgmgr-debug.h"
#include "package-manager.h"

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR"
#endif				/* LOG_TAG */

#define MAX_PKG_BUF_LEN	1024
#define BLOCK_SIZE      4096 /*in bytes*/

#define PKG_TMP_PATH "/opt/usr/apps/tmp"
#define PKG_RW_PATH "/opt/usr/apps/"
#define PKG_RO_PATH "/usr/apps/"

long long __calculate_dir_size(char *dirname)
{
	long long total = 0;
	long long ret = 0;
	int q = 0; /*quotient*/
	int r = 0; /*remainder*/
	DIR *dp = NULL;
	struct dirent *ep = NULL;
	struct stat fileinfo;
	char abs_filename[FILENAME_MAX] = { 0, };
	if(dirname == NULL) {
		_LOGE("dirname is NULL");
		return PMINFO_R_ERROR;
	}
	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp)) != NULL) {
			if (!strcmp(ep->d_name, ".") ||
				!strcmp(ep->d_name, "..")) {
				continue;
			}
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 ep->d_name);
			if (lstat(abs_filename, &fileinfo) < 0)
				perror(abs_filename);
			else {
				if (S_ISDIR(fileinfo.st_mode)) {
					total += fileinfo.st_size;
					if (strcmp(ep->d_name, ".")
					    && strcmp(ep->d_name, "..")) {
						ret = __calculate_dir_size
						    (abs_filename);
						total = total + ret;
					}
				} else if (S_ISLNK(fileinfo.st_mode)) {
					continue;
				} else {
					/*It is a file. Calculate the actual
					size occupied (in terms of 4096 blocks)*/
				q = (fileinfo.st_size / BLOCK_SIZE);
				r = (fileinfo.st_size % BLOCK_SIZE);
				if (r) {
					q = q + 1;
				}
				total += q * BLOCK_SIZE;
				}
			}
		}
		(void)closedir(dp);
	} else {
		_LOGE("Couldn't open the directory\n");
		return -1;
	}
	return total;

}

static int __get_total_size(char *pkgid, int *size)

{
	char device_path[MAX_PKG_BUF_LEN] = { '\0', };
	long long rw_size = 0;
	long long ro_size= 0;
	long long tmp_size= 0;
	long long total_size= 0;
	struct stat fileinfo;
	int ret = -1;

	/* RW area */
	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/bin", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
				rw_size += tmp_size;
		}
	}

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/info", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
			rw_size += tmp_size;
		}
	}

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/res", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
			rw_size += tmp_size;
		}
	}

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/data", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
				rw_size += tmp_size;
		}
	}

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/shared", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
				rw_size += tmp_size;
	}
	}

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/setting", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
				rw_size += tmp_size;
		}
	}
#if 1
	/* RO area */
	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/bin", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/info", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/res", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/data", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/shared", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
	}
	}

	snprintf(device_path, MAX_PKG_BUF_LEN, "%s%s/setting", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = __calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}
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
		total_size = __calculate_dir_size(device_path);
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

	_LOGD("pkg=[%s], size=[%d]\n", pkgid, size);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int size = 0;
	int get_type = 0;
	char *pkgid = NULL;

	pkgid = argv[0];
	get_type = atoi(argv[1]);

	if (get_type == PM_GET_TOTAL_SIZE) {
		ret = __get_total_size(pkgid, &size);
	} else if(get_type == PM_GET_DATA_SIZE) {
		ret = __get_data_size(pkgid, &size);
	} else if(get_type == PM_GET_ALL_PKGS) {
		ret = pkgmgrinfo_pkginfo_get_list(__pkg_list_cb, NULL);
	}
	if (ret < 0)
		_LOGD("_pkg_getsize fail \n");
	else
		_LOGD("_pkg_getsize success \n");

	vconf_set_int(VCONFKEY_PKGMGR_STATUS, size);
	return 0;
}
