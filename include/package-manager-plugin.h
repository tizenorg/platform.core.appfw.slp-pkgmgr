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









#ifndef __PKG_MANAGER_PLUGIN_H__
#define __PKG_MANAGER_PLUGIN_H__

#include "package-manager-types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*_pkg_plugin_unload) (void);
typedef int (*_pkg_plugin_pkg_is_installed) (const char *pkg_name);
typedef int (*_pkg_plugin_get_installed_pkg_list) (const char *category,
						   const char *option,
						   package_manager_pkg_info_t
						   **list, int *count);
typedef int (*_pkg_plugin_get_pkg_detail_info) (const char *pkg_name,
					package_manager_pkg_detail_info_t
					*pkg_detail_info);
typedef int (*_pkg_plugin_get_pkg_detail_info_from_package) (const char
					     *pkg_path,
					     package_manager_pkg_detail_info_t
					     *pkg_detail_info);

typedef struct _pkg_plugin_set {
char pkg_type[PKG_TYPE_STRING_LEN_MAX];
void *plugin_handle;
_pkg_plugin_unload plugin_on_unload;
_pkg_plugin_pkg_is_installed pkg_is_installed;
_pkg_plugin_get_installed_pkg_list get_installed_pkg_list;
_pkg_plugin_get_pkg_detail_info get_pkg_detail_info;
_pkg_plugin_get_pkg_detail_info_from_package
get_pkg_detail_info_from_package;
} pkg_plugin_set;

#ifdef __cplusplus
}
#endif

#endif				/* __PKG_MANAGER_PLUGIN_H__ */
