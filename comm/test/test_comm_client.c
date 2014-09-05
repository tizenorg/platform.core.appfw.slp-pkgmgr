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

#include "comm_client.h"
#include <stdio.h>
#include <glib.h>

static GMainLoop *mainloop;

void
stat_cb(void *data, const char *req_id, const char *pkg_type,
	const char *pkgid, const char *key, const char *val)
{
	printf(">>user callback>> Got: %s %s %s %s %s\n", req_id, pkg_type,
	       pkgid, key, val);

	g_main_loop_quit(mainloop);
}

int main(int argc, char **argv)
{

	g_type_init();
	mainloop = g_main_loop_new(NULL, FALSE);

	comm_client *cc = comm_client_new();

	gint ret;
	ret = comm_client_request(cc, "__test__req_key", COMM_REQ_TO_INSTALLER,
				  "dpkg", "test_pkg", "arg1 arg2 arg3",
				  "this_is_a_cookie", getuid(), 0);

	printf("client: waiting signal...\n");
	comm_client_set_status_callback(COMM_STATUS_BROADCAST_ALL,
                                    cc, stat_cb, NULL);

	g_main_loop_run(mainloop);

	comm_client_free(cc);

	return 0;
}

