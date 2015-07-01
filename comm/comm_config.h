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

/* API export macro */
#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

/* from comm_pkg_mgr.xml
 */
#define COMM_PKG_MGR_DBUS_SERVICE "org.tizen.slp.pkgmgr"
#define COMM_PKG_MGR_DBUS_PATH "/org/tizen/slp/pkgmgr"
#define COMM_PKG_MGR_DBUS_INTERFACE "org.tizen.slp.pkgmgr"
#define COMM_PKG_MGR_METHOD_REQUEST "Request"
#define COMM_PKG_MGR_METHOD_ECHO_STRING "EchoString"

/* from comm_status_broadcast
 */
#define COMM_STATUS_BROADCAST_DBUS_SERVICE_PREFIX \
	"org.tizen.slp.pkgmgr_status"
#define COMM_STATUS_BROADCAST_DBUS_PATH \
	"/org/tizen/slp/pkgmgr_status"
#define COMM_STATUS_BROADCAST_DBUS_INTERFACE \
	"org.tizen.slp.pkgmgr_status"
#define COMM_STATUS_BROADCAST_SIGNAL_STATUS "status"

#define COMM_STATUS_BROADCAST_DBUS_INSTALL_SERVICE_PREFIX "org.tizen.slp.pkgmgr.install"
#define COMM_STATUS_BROADCAST_DBUS_INSTALL_PATH	"/org/tizen/slp/pkgmgr/install"
#define COMM_STATUS_BROADCAST_DBUS_INSTALL_INTERFACE "org.tizen.slp.pkgmgr.install"
#define COMM_STATUS_BROADCAST_EVENT_INSTALL "install"

#define COMM_STATUS_BROADCAST_DBUS_UNINSTALL_SERVICE_PREFIX "org.tizen.slp.pkgmgr.uninstall"
#define COMM_STATUS_BROADCAST_DBUS_UNINSTALL_PATH	"/org/tizen/slp/pkgmgr/uninstall"
#define COMM_STATUS_BROADCAST_DBUS_UNINSTALL_INTERFACE "org.tizen.slp.pkgmgr.uninstall"
#define COMM_STATUS_BROADCAST_EVENT_UNINSTALL "uninstall"

#define COMM_STATUS_BROADCAST_DBUS_MOVE_SERVICE_PREFIX "org.tizen.slp.pkgmgr.move"
#define COMM_STATUS_BROADCAST_DBUS_MOVE_PATH	"/org/tizen/slp/pkgmgr/move"
#define COMM_STATUS_BROADCAST_DBUS_MOVE_INTERFACE "org.tizen.slp.pkgmgr.move"
#define COMM_STATUS_BROADCAST_EVENT_MOVE "move"

#define COMM_STATUS_BROADCAST_DBUS_INSTALL_PROGRESS_SERVICE_PREFIX "org.tizen.slp.pkgmgr.install.progress"
#define COMM_STATUS_BROADCAST_DBUS_INSTALL_PROGRESS_PATH	"/org/tizen/slp/pkgmgr/install/progress"
#define COMM_STATUS_BROADCAST_DBUS_INSTALL_PROGRESS_INTERFACE "org.tizen.slp.pkgmgr.install.progress"
#define COMM_STATUS_BROADCAST_EVENT_INSTALL_PROGRESS "install_progress"

#define COMM_STATUS_BROADCAST_DBUS_UPGRADE_SERVICE_PREFIX "org.tizen.slp.pkgmgr.upgrade"
#define COMM_STATUS_BROADCAST_DBUS_UPGRADE_PATH	"/org/tizen/slp/pkgmgr/upgrade"
#define COMM_STATUS_BROADCAST_DBUS_UPGRADE_INTERFACE "org.tizen.slp.pkgmgr.upgrade"
#define COMM_STATUS_BROADCAST_EVENT_UPGRADE "upgrade"

#define COMM_STATUS_BROADCAST_DBUS_GET_SIZE_SERVICE_PREFIX "org.tizen.pkgmgr.get.size"
#define COMM_STATUS_BROADCAST_DBUS_GET_SIZE_PATH "/org/tizen/pkgmgr/get/size"
#define COMM_STATUS_BROADCAST_DBUS_GET_SIZE_INTERFACE "org.tizen.pkgmgr.get.size"
#define COMM_STATUS_BROADCAST_EVENT_GET_SIZE "get_size"

/********
 * enums
 ********/

/* req_type */
enum {
	/* to installer */
	COMM_REQ_TO_INSTALLER = 1,

	/* to activator */
	COMM_REQ_TO_ACTIVATOR,

	/* to clearer */
	COMM_REQ_TO_CLEARER,

	/* to mover*/
	COMM_REQ_TO_MOVER,

	/* cancel job */
	COMM_REQ_CANCEL,

	/*get package size */
	COMM_REQ_GET_SIZE,

	/*kill app */
	COMM_REQ_KILL_APP,

	/*check app */
	COMM_REQ_CHECK_APP,

	/* to cache clear */
	COMM_REQ_CLEAR_CACHE_DIR,

	COMM_REQ_MAX_SENTINEL
};

/* return value */
enum {
	COMM_RET_NOMEM = -2,
	COMM_RET_ERROR = -1,
	COMM_RET_OK = 0,
	COMM_RET_QUEUED,

	COMM_RET_MAX_SENTINEL
};

/* broadcast type */
enum {
	COMM_STATUS_BROADCAST_ALL = 1,
	COMM_STATUS_BROADCAST_INSTALL,
	COMM_STATUS_BROADCAST_UNINSTALL,
	COMM_STATUS_BROADCAST_MOVE,
	COMM_STATUS_BROADCAST_INSTALL_PROGRESS,
	COMM_STATUS_BROADCAST_UPGRADE,
	COMM_STATUS_BROADCAST_GET_SIZE,
	COMM_STATUS_BROADCAST_MAX
};

#endif				/* __COMM_CONFIG_H__ */
