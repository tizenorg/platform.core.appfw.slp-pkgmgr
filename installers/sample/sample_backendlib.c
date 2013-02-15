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





/* sample_backendlib.c
 * test package
 */

#include <stdio.h>
#include <string.h>
#include "package-manager-plugin.h"

static void pkg_native_plugin_on_unload(void);
static int pkg_plugin_app_is_installed(const char *pkgid);
static int pkg_plugin_get_installed_apps_list(const char *category,
					      const char *option,
					      package_manager_pkg_info_t **
					      list, int *count);
static int pkg_plugin_get_app_detail_info(const char *pkgid,
					  package_manager_pkg_detail_info_t *
					  pkg_detail_info);
static int pkg_plugin_get_app_detail_info_from_package(const char *pkg_path,
				       package_manager_pkg_detail_info_t
				       *pkg_detail_info);

static void pkg_native_plugin_on_unload(void)
{
	printf("pkg_native_plugin_unload() is called\n");
}

static int pkg_plugin_app_is_installed(const char *pkgid)
{
	printf("pkg_plugin_app_is_installed() is called\n");

	return 0;
}

static int pkg_plugin_get_installed_apps_list(const char *category,
					      const char *option,
					      package_manager_pkg_info_t **
					      list, int *count)
{
	printf("pkg_plugin_get_installed_apps_list() is called\n");

	return 0;
}

static int pkg_plugin_get_app_detail_info(const char *pkgid,
					  package_manager_pkg_detail_info_t *
					  pkg_detail_info)
{
	printf("pkg_plugin_get_app_detail_info() is called\n");

	return 0;
}

static int pkg_plugin_get_app_detail_info_from_package(const char *pkg_path,
				       package_manager_pkg_detail_info_t
				       *pkg_detail_info)
{
	printf("pkg_plugin_get_app_detail_info_from_package() is called\n");

	return 0;
}

__attribute__ ((visibility("default")))
int pkg_plugin_on_load(pkg_plugin_set *set)
{
	if (set == NULL) {
		return -1;
	}

	memset(set, 0x00, sizeof(pkg_plugin_set));

	set->plugin_on_unload = pkg_native_plugin_on_unload;
	set->pkg_is_installed = pkg_plugin_app_is_installed;
	set->get_installed_pkg_list = pkg_plugin_get_installed_apps_list;
	set->get_pkg_detail_info = pkg_plugin_get_app_detail_info;
	set->get_pkg_detail_info_from_package =
	    pkg_plugin_get_app_detail_info_from_package;

	return 0;
}

