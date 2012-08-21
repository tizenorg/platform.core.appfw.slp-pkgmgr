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

#define PKG_FRONTEND	"frontend:"
#define PKG_BACKEND		"backend:"
#define PKG_BACKENDLIB	"backendlib:"
#define PKG_PARSERLIB	"parserlib:"
#define PKG_CONF_PATH	"/usr/etc/package-manager/pkg_path.conf"

#define PKG_STATUS		"STATUS"

#define PKG_STRING_LEN_MAX 1024
#define PKG_EXT_LEN_MAX		 20
#define PKG_ARGC_MAX		 16

#define _LOGE(fmt, arg...) LOGE("[%s,%d] "fmt, __FUNCTION__, __LINE__, ##arg)
#define _LOGD(fmt, arg...) LOGD("[%s,%d] "fmt, __FUNCTION__, __LINE__, ##arg)

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

#endif				/* __PKG_MANAGER_INTERNAL_H__ */
