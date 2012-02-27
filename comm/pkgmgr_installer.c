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
#include "pkgmgr_installer_config.h"

#include "comm_config.h"
#include "comm_socket.h"
#include "comm_status_broadcast_server.h"
#include "error_report.h"

#include <unistd.h>
#include <string.h>
#include <getopt.h>

#define MAX_STRLEN 512
#define CHK_PI_RET(r) \
	do { if (NULL == pi) return (r); } while (0)

/* ADT */
struct pkgmgr_installer {
	int request_type;
	int quiet;
	char *pkgmgr_info;
	char *session_id;
	char *license_path;
	char *quiet_socket_path;

	DBusConnection *conn;
};
static int __pkgmgr_installer_receive_request_by_socket(pkgmgr_installer *pi);

/* Internal func */

static int __pkgmgr_installer_receive_request_by_socket(pkgmgr_installer *pi)
{
	CHK_PI_RET(-EINVAL);
	int r = 0;

#ifdef USE_SOCKET
	/* TODO: implement this */

	/* Try to connect to socket */
	comm_socket_client *csc = 
		comm_socket_client_new(pi->quiet_socket_path);
	if (!csc)
		return -EINVAL;

	/* Receive request */
	char *req = NULL, *pkg_info = NULL;
	if (0 != comm_socket_client_receive_request(csc, &req, &pkg_info)) {
		r = -EINVAL;
		goto CLEANUP_RET;
	}

	/* Verify requester */

	/* Set request value */

	/* Cleanup */
 CLEANUP_RET:
	if (csc)
		comm_socket_client_free(csc);
#endif

	return r;
}

/* API */

API pkgmgr_installer *pkgmgr_installer_new(void)
{
	pkgmgr_installer *pi = NULL;
	pi = calloc(1, sizeof(struct pkgmgr_installer));
	if (NULL == pi)
		return ERR_PTR(-ENOMEM);

	pi->request_type = PKGMGR_REQ_INVALID;

	return pi;
}

API int pkgmgr_installer_free(pkgmgr_installer *pi)
{
	CHK_PI_RET(-EINVAL);

	/* free members */
	if (pi->pkgmgr_info)
		free(pi->pkgmgr_info);
	if (pi->session_id)
		free(pi->session_id);

	if (pi->conn)
		comm_status_broadcast_server_disconnect(pi->conn);

	free(pi);

	return 0;
}

API int
pkgmgr_installer_receive_request(pkgmgr_installer *pi,
				 const int argc, char **argv)
{
	CHK_PI_RET(-EINVAL);

	int r = 0;

	/* Parse argv */
	optind = 1;		/* Initialize optind to clear prev. index */
	int opt_idx = 0;
	int c;
	int mode = 0;
	while (1) {
		c = getopt_long(argc, argv, short_opts, long_opts, &opt_idx);
		/* printf("c=%d %c\n", c, c); //debug */
		if (-1 == c)
			break;	/* Parse is end */
		switch (c) {
		case 'k':	/* session id */
			if (pi->session_id)
				free(pi->session_id);
			pi->session_id = strndup(optarg, MAX_STRLEN);
			break;

		case 'l':	/* license path */
			if (pi->license_path)
				free(pi->license_path);
			pi->license_path = strndup(optarg, MAX_STRLEN);
			break;

		case 'i':	/* install */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'i';
			pi->request_type = PKGMGR_REQ_INSTALL;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;

		case 'd':	/* uninstall */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'd';
			pi->request_type = PKGMGR_REQ_UNINSTALL;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;


		case 'c':	/* clear */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'c';
			pi->request_type = PKGMGR_REQ_CLEAR;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;

		case 'r':	/* recover */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'r';
			break;

		case 'q':	/* quiet mode */
			/* if(mode) { r = -EINVAL; goto RET; }
			   mode = 'q'; */
			pi->quiet = 1;
			/* pi->quiet_socket_path = strndup(optarg, MAX_STRLEN);
			   maximum 255 bytes 
			   return 
			__pkgmgr_installer_receive_request_by_socket(pi); */

			break;

			/* Otherwise */
		case '?':	/* Not an option */
			break;

		case ':':	/* */
			break;

		}
	}

	/* quiet mode : get options from socket (to be impelemented) */

	/* normal mode : get options from argv */

 RET:
	return r;
}

API int pkgmgr_installer_get_request_type(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->request_type;
}

API const char *pkgmgr_installer_get_request_info(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->pkgmgr_info;
}

API const char *pkgmgr_installer_get_session_id(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->session_id;
}

API const char *pkgmgr_installer_get_license_path(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->license_path;
}

API int pkgmgr_installer_is_quiet(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->quiet;
}

API int
pkgmgr_installer_send_signal(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkg_name,
			     const char *key, const char *val)
{
	int r = 0;

	if (!pi->conn)
		pi->conn = comm_status_broadcast_server_connect();

	char *sid = pi->session_id;
	if (!sid)
		sid = "";
	comm_status_broadcast_server_send_signal(pi->conn, sid, pkg_type,
						 pkg_name, key, val);

	return r;
}
