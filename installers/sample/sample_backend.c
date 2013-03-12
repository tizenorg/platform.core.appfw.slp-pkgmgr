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





/* sample_backend.c
 * test package
 */


/* Pkgmgr installer headers */
#include "pkgmgr_installer.h"

/* GUI headers */

/* glibc headers */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static int __confirm_ui(void *data, char *msg);
static int __install_package(const char *pkg_file_path);
static int __uninstall_package(const char *pkgid);
static int __recover_package_system(void);

static pkgmgr_installer *_pi;

static int __confirm_ui(void *data, char *msg)
{
	/* Show confirm ui */

	return 1;
}

static int __install_package(const char *pkg_file_path)
{
	if (__confirm_ui(NULL, "Install?")) {
		/* Install package, and send signal */

	}

	int ret = 0;
	ret = pkgmgr_installer_send_signal(_pi, "sample", "abc", "end", "ok");
	if (ret == 0) {
		system("touch /opt/etc/install_complete");
	}

	return 0;
}

static int __uninstall_package(const char *pkgid)
{
	return 0;
}

static int __clear_package(const char *pkgid)
{
	return 0;
}

static int __recover_package_system(void)
{
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;
	pkgmgr_installer *pi = pkgmgr_installer_new();

	_pi = pi;

	pkgmgr_installer_receive_request(pi, argc, argv);

	int req_type = pkgmgr_installer_get_request_type(pi);
	if (PKGMGR_REQ_INVALID >= req_type)
		return EINVAL;

	const char *pkg_info = pkgmgr_installer_get_request_info(pi);

	switch (req_type) {
	case PKGMGR_REQ_INSTALL:
		ret = __install_package(pkg_info);
		break;
	case PKGMGR_REQ_UNINSTALL:
		ret = __uninstall_package(pkg_info);
		break;
	case PKGMGR_REQ_CLEAR:
		ret = __clear_package(pkg_info);
		break;
	case PKGMGR_REQ_RECOVER:
		ret = __recover_package_system();
		break;
	default:
		ret = EINVAL;
	}

	return ret;
}

