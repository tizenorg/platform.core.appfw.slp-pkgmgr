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

#include "pkgmgr_installer.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "comm_client.h"
static int _argc;
static char **_argv;
static GMainLoop *mainloop;

static void __test_pi_new_free(void);
static void __test_pi_receive_request_standard_mode();
static void __test_pi_send_signal();
static void __test_pi_receive_request_quiet_mode();

static void __test_pi_new_free(void)
{
	pkgmgr_installer *pi = pkgmgr_installer_new();
	assert(NULL != pi);

	pkgmgr_installer_free(pi);
}

static void __test_pi_receive_request_standard_mode(void)
{
	pkgmgr_installer *pi;

	struct test_data {
		char *argv[1024];
		int size_argv;
		int desired_ret_type;
		char *desired_pkg_info;
		char *desired_session_id;
	};

	/* Test data collection: Add more test here, except -q */
	struct test_data td[] = {
		{ {"a", "-i", "abc" }, 3, PKGMGR_REQ_INSTALL, "abc", NULL},
		{ {"a", "-i", "ghi", "-k", "key1" }, 5, PKGMGR_REQ_INSTALL,
		  "ghi", "key1" },
		{ {"a", "-i", "abc", "-k", "key1", "-k", "key2" }, 7,
		  PKGMGR_REQ_INSTALL, "abc", "key2" },
		{ { NULL }, 0, 0, NULL, NULL }	/* sentinel */
	};

	/* Run test! */
	int i = 0;
	struct test_data *p_td = td + i;
	while (p_td && p_td->size_argv) {

		printf(">>> %s %d %d %s\n", p_td->argv[0], p_td->size_argv,
		       p_td->desired_ret_type, p_td->desired_pkg_info);

		pi = pkgmgr_installer_new();
		assert(NULL != pi);

		assert(0 == pkgmgr_installer_receive_request(
					pi, p_td->size_argv, p_td->argv));
		assert(p_td->desired_ret_type ==
		       pkgmgr_installer_get_request_type(pi));
		assert(pkgmgr_installer_get_request_info(pi));	/* NULL check */
		assert(!strcmp(p_td->desired_pkg_info,
			       pkgmgr_installer_get_request_info(pi)));
		if (p_td->desired_session_id) {
			assert(pkgmgr_installer_get_session_id(pi));
			assert(!strcmp(p_td->desired_session_id,
				       pkgmgr_installer_get_session_id(pi)));
		} else {
			assert(p_td->desired_session_id ==
			       pkgmgr_installer_get_session_id(pi));
		}
		pkgmgr_installer_free(pi);

		/* next */
		i++;
		p_td = td + i;
	}
}

struct signal_counter {
	int start;
	int install_percent;
	int end;
};

static gboolean timer_stop_mainloop(void *data)
{
	g_main_loop_quit(mainloop);
	return FALSE;
}

static void
get_signal_cb(void *cb_data, const char *req_id, const char *pkg_type,
	      const char *pkgid, const char *key, const char *val)
{
	struct signal_counter *counter = (struct signal_counter *)cb_data;

	printf("get_signal_cb() called\n");
	if (!strcmp("start", key))
		counter->start += 1;
	if (!strcmp("install_percent", key))
		counter->install_percent = atoi(val);
	if (!strcmp("end", key))
		counter->end += 1;

	g_main_loop_quit(mainloop);
}

static gboolean timer_send_signal(void *data)
{
	pkgmgr_installer *pi = (pkgmgr_installer *) data;
	printf("try to send signal\n");
	assert(0 == pkgmgr_installer_send_signal(pi, "deb", "testpkg", "start",
					         "install"));
	printf("sent signal\n");
	return FALSE;
}

static void __test_pi_send_signal(void)
{
	pkgmgr_installer *pi;
	pi = pkgmgr_installer_new();
	assert(NULL != pi);

	/* receiver */
	struct signal_counter counter = { 0, };
	comm_client *cc;
	cc = comm_client_new();
	comm_client_set_status_callback(COMM_STATUS_BROADCAST_ALL,
                                    cc, get_signal_cb, &counter);

	/* sender */
	g_timeout_add_seconds(1, timer_send_signal, pi);

	/* Set timeout, and run main loop */
	g_timeout_add_seconds(5, timer_stop_mainloop, NULL);

	printf("start loop\n");
	g_main_loop_run(mainloop);

	/* find values */
	printf("exit loop\n");
	assert(1 == counter.start);

	comm_client_free(cc);

	pkgmgr_installer_free(pi);
}

void __test_pi_receive_request_quiet_mode()
{
	pkgmgr_installer *pi;

	struct test_data {
		char *argv[1024];
		int size_argv;
		int desired_ret_type;
		char *desired_pkg_info;
		char *desired_session_id;
	};

	/* Test data collection: Add more test here, except -q */
	struct test_data td[] = {
		{ {"a", "-q", "-i", "abc" }, 4, PKGMGR_REQ_INSTALL, "abc", NULL},
		{ {"a", "-i", "ghi", "-k", "key1", "-q" }, 6,
		  PKGMGR_REQ_INSTALL, "ghi", "key1"},
		{ {NULL}, 0, 0, NULL, NULL }	/* sentinel */
	};

	/* Run test! */
	int i = 0;
	int r;
	struct test_data *p_td = td + i;
	while (p_td && p_td->size_argv) {

		printf(">>> %s %d %d %s\n", p_td->argv[0], p_td->size_argv,
		       p_td->desired_ret_type, p_td->desired_pkg_info);

		pi = pkgmgr_installer_new();
		assert(NULL != pi);
		r = pkgmgr_installer_receive_request(pi, p_td->size_argv,
						     p_td->argv);
		printf("desired=0, r=%d\n", r);
		assert(0 == r);
		assert(p_td->desired_ret_type ==
		       pkgmgr_installer_get_request_type(pi));
		assert(pkgmgr_installer_get_request_info(pi));	/* NULL check */
		assert(!strcmp
		       (p_td->desired_pkg_info,
			pkgmgr_installer_get_request_info(pi)));
		assert(pkgmgr_installer_is_quiet(pi));
		if (p_td->desired_session_id) {
			assert(pkgmgr_installer_get_session_id(pi));
			assert(!strcmp
			       (p_td->desired_session_id,
				pkgmgr_installer_get_session_id(pi)));
		} else {
			assert(p_td->desired_session_id ==
			       pkgmgr_installer_get_session_id(pi));
		}
		pkgmgr_installer_free(pi);

		/* next */
		i++;
		p_td = td + i;
	}
}

/* Test collection */
static void __test_pkgmgr_installer(void)
{
	__test_pi_new_free();
	__test_pi_receive_request_standard_mode();
	__test_pi_send_signal();
	__test_pi_receive_request_quiet_mode();
}

/* main function */
int main(int argc, char **argv)
{
	_argc = argc;
	_argv = argv;

	/* For event loop */
	g_type_init();
	mainloop = g_main_loop_new(NULL, FALSE);

	__test_pkgmgr_installer();

	return 0;
}

