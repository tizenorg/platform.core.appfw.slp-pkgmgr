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

#include "comm_pkg_mgr_server.h"
#include <glib.h>
#include <stdio.h>

void
req_cb(void *cb_data, uid_t uid, const char *req_id, const int req_type,
       const char *pkg_type, const char *pkgid, const char *args,
       const char *client, const char *session, const char *user, int *ret)
{
	/* TODO: Do your job here */
	printf(">> in callback >> Got request: %s %d %s %s %s\n",
	       req_id, req_type, pkg_type, pkgid, args);
}

gboolean queue_job(void *data)
{
	/* .i..

	if (no_need_more) {
		g_main_loop_quit(mainloop);
		return FALSE;

	*/
	return TRUE;
}

int main(int argc, char **argv) 
{
	g_type_init();

	GMainLoop *mainloop = g_main_loop_new(NULL, FALSE);

	PkgMgrObject *pkg_mgr;
	pkg_mgr = g_object_new(PKG_MGR_TYPE_OBJECT, NULL);

	pkg_mgr_set_request_callback(pkg_mgr, req_cb, NULL);

	g_timeout_add_seconds(1, queue_job, NULL);

	g_main_loop_run(mainloop);

	/* TODO: add cleanup code */

	return 0;
}

