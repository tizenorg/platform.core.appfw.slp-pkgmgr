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





#ifndef __COMM_PKG_MGR_SERVER_H__
#define __COMM_PKG_MGR_SERVER_H__

#include "comm_config.h"
#include <glib-object.h>

typedef struct PkgMgrObjectClass PkgMgrObjectClass;
typedef struct PkgMgrObject PkgMgrObject;

/* For returning server object's GType. 
 * I don't use this. Just forward declaration for G_DEFINE_TYPE() macro. */
API GType pkg_mgr_object_get_type(void);
#define PKG_MGR_TYPE_OBJECT (pkg_mgr_object_get_type())

typedef void (*request_callback) (void *cb_data, const char *req_id,
				  const int req_type, const char *pkg_type,
				  const char *pkg_name, const char *args,
				  const char *cookie, int *ret);

API void pkg_mgr_set_request_callback(PkgMgrObject *obj,
				      request_callback req_cb, void *cb_data);

#endif				/* __COMM_PKG_MGR_SERVER_H__ */
