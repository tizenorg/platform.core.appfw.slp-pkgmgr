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

/* Debug message macro */
#define USE_DLOG 1		/* Use dlog! */

#ifndef NDEBUG
#ifdef USE_DLOG
#define LOG_TAG "PKGMGR"
#include <dlog.h>
#define dbg(fmtstr, args...) \
	do { SLOGI("[comm]%s:%d:%s(): " \
	fmtstr "\n", basename(__FILE__), __LINE__, __func__, ##args); } \
	while (0)
#define ERR(fmtstr, args...) \
	do { SLOGE("[comm]%s:%d:%s(): " \
	fmtstr "\n", basename(__FILE__), __LINE__, __func__, ##args); } \
	while (0)
#else
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#define dbg(fmtstr, args...) \
	do {
		fprintf(stdout, "[%d:comm]%s:%d:%s(): " \
		fmtstr "\n", getpid(),\
		basename(__FILE__), __LINE__, __func__, ##args);\
	} while (0)

#define ERR(fmtstr, args...) \
	do {
		fprintf(stderr, "[%d:comm]%s:%d:%s(): " \
		fmtstr "\n", getpid(),\
		basename(__FILE__), __LINE__, __func__, ##args);\
	} while (0)
#endif				/* USE_DLOG */
#else
#define dbg(fmtstr, args...)
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

	/* cancel job */
	COMM_REQ_CANCEL,

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

#endif				/* __COMM_CONFIG_H__ */
