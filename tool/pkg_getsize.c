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

#include "pkgmgr_installer.h"
#include "pkgmgr-debug.h"

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR"
#endif				/* LOG_TAG */

#define MAX_PKG_BUF_LEN	128

static int _pkg_getsize(int argc, char **argv)
{
	int ret = 0;
	char *pkgid = NULL;
	char *type = NULL;
	pkgmgr_installer *pi = NULL;
	pkgmgrinfo_pkginfo_h handle;
	int size = 0;
	char buf[MAX_PKG_BUF_LEN] = {'\0'};

	/*make new pkgmgr_installer handle*/
	pi = pkgmgr_installer_new();
	retvm_if(!pi, PMINFO_R_ERROR, "service type is error\n");

	/*get args*/
	ret = pkgmgr_installer_receive_request(pi, argc, argv);
	tryvm_if(ret < 0, PMINFO_R_ERROR, "pkgmgr_installer_receive_request failed");

	/*get pkgid from installer handle*/
	pkgid = pkgmgr_installer_get_request_info(pi);
	tryvm_if(pkgid == NULL, ret = PMINFO_R_ERROR, "pkgmgr_installer_get_request_info failed");

	/*get pkgmgr handle from pkgid*/
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgrinfo_pkginfo_get_pkginfo[pkgid=%s] failed", pkgid);

	/*get type info from handle*/
	ret = pkgmgrinfo_pkginfo_get_type(handle, &type);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgrinfo_pkginfo_get_type[pkgid=%s] failed", pkgid);

	/*get size info from handle*/
	ret = pkgmgrinfo_pkginfo_get_total_size(handle, &size);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgrinfo_pkginfo_get_total_size[pkgid=%s] failed", pkgid);

	snprintf(buf, MAX_PKG_BUF_LEN - 1, "%d", size);

	/*send size to dbus*/
	ret =pkgmgr_installer_send_signal(pi, type, pkgid, "size", buf);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgr_installer_send_signal[pkgid=%s] failed", pkgid);

catch:

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	pkgmgr_installer_free(pi);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	ret = _pkg_getsize(argc, argv);
	if (ret < 0) {
		_LOGE("_pkg_getsize failed \n");
		return -1;
	}

	_LOGE("_pkg_getsize success \n");
	return 0;
}
