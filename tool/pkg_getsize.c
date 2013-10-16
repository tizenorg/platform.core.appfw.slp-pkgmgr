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

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR_GETSIZE"
#endif				/* LOG_TAG */

#define MAX_PKG_INFO_LEN	10
#define MAX_PKG_BUF_LEN	1024
#define BLOCK_SIZE      4096 /*in bytes*/

#define PKG_RW_PATH "/opt/usr/apps/"
#define PKG_SIZE_INFO_FILE "/tmp/pkgmgr_size_info.txt"

char* directory_list[4][10] = { {"bin", "info", "res", "info", "data", "shared", "setting", "lib", NULL},
								{"bin", "info", "res", "info", "shared", "setting", "lib", NULL},
								{"data", NULL},
								NULL };

long long __stat_size(struct stat *s)
{
	long long blksize = s->st_blksize;
	long long size = s->st_blocks * 512;

    if (blksize) {
        size = (size + blksize - 1) & (~(blksize - 1));
    }

    return size;
}

long long __calculate_dir_size(int dfd, int depth, int type)
{
    long long size = 0;
    struct stat s;
    DIR *d = NULL;
    struct dirent *de = NULL;
    int i = 0;

    depth++;

    d = fdopendir(dfd);
    if (d == NULL) {
        close(dfd);
        return 0;
    }

    while ((de = readdir(d))) {
		int skip = 0;
		const char *name = de->d_name;
		if (name[0] == '.') {
            if (name[1] == 0)
                continue;
            if ((name[1] == '.') && (name[2] == 0))
                continue;
        }

        if (depth == 1 && de->d_type == DT_DIR) {
			for (i = 0; directory_list[type][i]; i++) {
				if (strcmp(name, directory_list[type][i]) == 0) {
					skip = -1;
					break;
				}
			}

			if (skip == 0)
				continue;
        }

        if (fstatat(dfd, name, &s, AT_SYMLINK_NOFOLLOW) == 0) {
            size += __stat_size(&s);
        }

        if (de->d_type == DT_DIR) {
            int subfd;

            subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
            if (subfd >= 0) {
                size += __calculate_dir_size(subfd, depth, type);
            }
        }
    }

    closedir(d);
    return size;
}

void __make_sizeinfo_file(char *package_size_info)
{
	FILE* file = NULL;
	int fd = 0;

	if(package_size_info == NULL)
		return;

	file = fopen(PKG_SIZE_INFO_FILE, "w");
	if (file == NULL) {
		_LOGE("Couldn't open the file %s \n", PKG_SIZE_INFO_FILE);
		return;
	}

	fwrite(package_size_info, 1, strlen(package_size_info), file);
	fflush(file);
	fd = fileno(file);
	fsync(fd);
	fclose(file);

	const char *chsmack_info[] = { "/usr/bin/chsmack", "-a", "*", PKG_SIZE_INFO_FILE};
	system(chsmack_info);

	chmod(PKG_SIZE_INFO_FILE, 0777);
	chown(PKG_SIZE_INFO_FILE, 5000, 5000);
}

int __get_size_info(char *pkgid, int get_type, int *size)
{
	char *package_size_info = NULL;
	int info_len = MAX_PKG_BUF_LEN * MAX_PKG_INFO_LEN;

	DIR *dir = NULL;
	int dfd = 0;
	struct stat f_stat;
    struct dirent *de = NULL;

	dir = opendir(PKG_RW_PATH);
	if (dir == NULL) {
		_LOGE("Couldn't open the directory %s \n", PKG_RW_PATH);
		return -1;
	}

	package_size_info = (char*)malloc(info_len);
	memset(package_size_info, 0, info_len);

    while ((de = readdir(dir)))
    {
		int total_size = 0;
		int others_size = 0;
		int data_size = 0;

		char size_string[128] = {0};
		const char *name = de->d_name;
        if (name[0] == '.') {
            if (name[1] == 0)
                continue;
            if ((name[1] == '.') && (name[2] == 0))
                continue;
        }

		if (strcmp(name, pkgid) != 0){
			continue;
		}

        dfd = dirfd(dir);
		if (de->d_type == DT_DIR) {
			int subfd = 0;

			subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
			if (subfd >= 0) {
		        if (fstat(subfd, &f_stat) == 0)	// root
		        {
		        	others_size += __stat_size(&f_stat);
		        }
		        others_size += __calculate_dir_size(subfd, 0, 1);
			}
			subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
			if (subfd >= 0) {
				int datafd = 0;
				datafd = openat(subfd, "data", O_RDONLY | O_DIRECTORY);
				if (datafd >= 0) {
			        if (fstat(datafd, &f_stat) == 0)	// data
			        {
			        	others_size += __stat_size(&f_stat);
			        }
					data_size = __calculate_dir_size(datafd, 1, 2);
				}
			}
		}

        total_size = others_size + data_size;
		if (get_type == PM_GET_TOTAL_SIZE) {
			*size = total_size;
		} else if(get_type == PM_GET_DATA_SIZE) {
			*size = data_size;
		} else {
			sprintf(size_string, "%s=%d/%d:", pkgid, total_size, data_size);
			strncat(package_size_info, size_string, info_len);
			__make_sizeinfo_file(package_size_info);
		}
    }
    closedir(dir);

	if(package_size_info)
		free(package_size_info);
	return 0;
}

int __create_size_info(void)
{
	char *package_size_info = NULL;
	int info_len = MAX_PKG_BUF_LEN * MAX_PKG_INFO_LEN;

	DIR *dir = NULL;
	int dfd = 0;
	struct stat f_stat;
    struct dirent *de = NULL;

	dir = opendir(PKG_RW_PATH);
	if (dir == NULL)
	{
		_LOGE("Couldn't open the directory %s \n", PKG_RW_PATH);
		return -1;
	}

	package_size_info = (char*)malloc(info_len);
	memset(package_size_info, 0, info_len);

    while ((de = readdir(dir)))
    {
		int total_size = 0;
		int others_size = 0;
		int data_size = 0;

		char size_string[128] = {0};
		const char *name = de->d_name;
        if (name[0] == '.') {
            if (name[1] == 0)
                continue;
            if ((name[1] == '.') && (name[2] == 0))
                continue;
        }

        dfd = dirfd(dir);
		if (de->d_type == DT_DIR) {
			int subfd = 0;

			subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
			if (subfd >= 0) {
		        if (fstat(subfd, &f_stat) == 0)	// root
		        {
		        	others_size += __stat_size(&f_stat);
		        }
		        others_size += __calculate_dir_size(subfd, 0, 1);
			}
			subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
			if (subfd >= 0) {
				int datafd = 0;
				datafd = openat(subfd, "data", O_RDONLY | O_DIRECTORY);
				if (datafd >= 0) {
			        if (fstat(datafd, &f_stat) == 0)	// data
			        {
			        	others_size += __stat_size(&f_stat);
			        }
					data_size = __calculate_dir_size(datafd, 1, 2);
				}
			}
		}

        total_size = others_size + data_size;

        sprintf(size_string, "%s=%d/%d:", name, total_size, data_size);
        strncat(package_size_info, size_string, info_len);
    }
    closedir(dir);

	__make_sizeinfo_file(package_size_info);
	if(package_size_info)
		free(package_size_info);

	return 0;
}

static int __pkg_list_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid;
	int size = 0;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if(ret < 0) {
		_LOGE("pkgmgr_pkginfo_get_pkgid() failed\n");
	}

	ret = __get_size_info(pkgid, PM_GET_TOTAL_SIZE, &size);
	if ((ret < 0) || (size < 0))
		return -1;

	* (int *) user_data += size;
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = -1;
	int size = 0;
	int get_type = 0;
	char *pkgid = NULL;

	pkgid = argv[0];
	if(pkgid == NULL) {
		_LOGE("pkgid is NULL\n");
		return -1;
	}
	get_type = atoi(argv[1]);

	if(get_type == PM_GET_SIZE_INFO) {
		ret = __create_size_info();
	} else if(get_type == PM_GET_ALL_PKGS) {
		ret = pkgmgrinfo_pkginfo_get_list(__pkg_list_cb, &size);
	} else {
		ret = __get_size_info(pkgid, get_type, &size);
	}

	_LOGD("_pkg_getsize [pkgid=%s, request type=%d, result=%d] \n", pkgid, get_type, ret);

	vconf_set_int(VCONFKEY_PKGMGR_STATUS, size);
	return 0;
}
