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

#ifndef __COMM_CONFIG_H__
#define __COMM_CONFIG_H__

#include <stdlib.h>		/* for NULL */
#include <libgen.h>

/* from comm_pkg_mgr.xml
 */
#define COMM_PKGMGR_DBUS_SERVICE "org.tizen.pkgmgr"
#define COMM_PKGMGR_DBUS_OBJECT_PATH "/org/tizen/pkgmgr"
#define COMM_PKGMGR_DBUS_INTERFACE "org.tizen.pkgmgr"

/* from comm_status_broadcast
 */
#define COMM_STATUS_BROADCAST_INTERFACE "org.tizen.pkgmgr.signal"
#define COMM_STATUS_BROADCAST_OBJECT_PATH "/org/tizen/pkgmgr/signal"

#endif				/* __COMM_CONFIG_H__ */
