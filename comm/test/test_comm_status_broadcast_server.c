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

#include "comm_status_broadcast_server.h"
#include <glib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
static int _main_dbus(int argc, char **argv);
static int _main_dbus(int argc, char **argv)
{
	DBusConnection *conn = comm_status_broadcast_server_connect();
	int i;
	for (i = 0; i < 100; i++) {
		comm_status_broadcast_server_send_signal(conn, "test_id",
							 "test", "test_pkgname",
							 "test_key",
							 "test_val");
		sleep(1);
		printf(">>> sent signal: %d\n", i);
	}

	return 0;
}

int main(int argc, char **argv)
{
	return _main_dbus(argc, argv);

}

