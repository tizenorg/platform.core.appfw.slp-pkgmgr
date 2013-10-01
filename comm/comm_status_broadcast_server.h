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





#ifndef __COMM_STATUS_BROADCAST_SERVER_H__
#define __COMM_STATUS_BROADCAST_SERVER_H__

#include "comm_config.h"
#include <dbus/dbus.h>

/* pure dbus api */
API DBusConnection *comm_status_broadcast_server_connect(int comm_status_type);
API void comm_status_broadcast_server_send_signal(int comm_status_type, DBusConnection *conn,
						  const char *req_id,
						  const char *pkg_type,
						  const char *pkgid,
						  const char *key,
						  const char *val);
API void comm_status_broadcast_server_disconnect(DBusConnection *conn);
#endif				/* __COMM_STATUS_BROADCAST_SERVER_H__ */
