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





#ifndef __PKG_MANAGER_INTERNAL_H__
#define __PKG_MANAGER_INTERNAL_H__

#include <unistd.h>
#include <ctype.h>
#include <dlog.h>

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR"
#endif				/* LOG_TAG */

#include "package-manager-plugin.h"

typedef package_manager_pkg_info_t package_manager_app_info_t;


char *_get_pkg_type_from_desktop_file(const char *pkgid);

package_manager_pkg_info_t *_pkg_malloc_appinfo(int num);

pkg_plugin_set *_pkg_plugin_load_library(const char *pkg_type,
					 const char *library_path);

int _pkg_plugin_get_library_path(const char *pkg_type, char *library_path);

pkg_plugin_set *_package_manager_load_library(const char *pkg_type);

char *_get_info_string(const char *key,
		       const package_manager_pkg_detail_info_t *
		       pkg_detail_info);

int _get_info_int(const char *key,
		  const package_manager_pkg_detail_info_t *pkg_detail_info);

time_t _get_info_time(const char *key,
		      const package_manager_pkg_detail_info_t *
		      pkg_detail_info);


#define PKG_FRONTEND	"frontend:"
#define PKG_BACKEND		"backend:"
#define PKG_BACKENDLIB	"backendlib:"
#define PKG_PARSERLIB	"parserlib:"
#define PKG_CONF_PATH	"/usr/etc/package-manager/pkg_path.conf"

#define PKG_STATUS		"STATUS"

#define PKG_STRING_LEN_MAX 1024
#define PKG_EXT_LEN_MAX		 20
#define PKG_ARGC_MAX		 16

#define _LOGE(fmt, arg...) LOGE(fmt,##arg)
#define _LOGD(fmt, arg...) LOGD(fmt,##arg)

#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		_LOGE(fmt, ##arg); \
		_LOGE("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

#define retv_if(expr, val) do { \
	if (expr) { \
		_LOGE("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

void _app_str_trim(char *input);
char *_get_backend_path(const char *input_path);
char *_get_backend_path_with_type(const char *type);

int _get_mime_from_file(const char *filename, char *mimetype, int len);
int _get_mime_extension(const char *mimetype, char *ext, int len);

#endif				/* __PKG_MANAGER_INTERNAL_H__ */
