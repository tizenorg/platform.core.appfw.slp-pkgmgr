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





#include "comm_socket.h"

#include <glib-2.0/glib.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#define __USE_GNU
#include <sys/socket.h>
#include <linux/un.h>		/* for sockaddr_un */

#define COMM_SOCKET_SERVER_SOCK_PATH_PREFIX "/tmp/comm_socket_"

#define CHK_CS_RET(r) \
	do { if (NULL == cs) return (r); } while (0)

struct comm_socket {
	int sockfd;
};

static int _get_new_socket(void)
{
	int fd = -1;
	fd = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		if (EINVAL == errno) {
			/* Try again, without SOCK_CLOEXEC option */
			fd = socket(AF_LOCAL, SOCK_STREAM, 0);
			if (fd < 0) {
				return -EINVAL;
			}
		} else {
			return -errno;
		}
	}

	return fd;
}

static void _set_sockaddr_un(struct sockaddr_un *saddr, const char *sock_path)
{
	saddr->sun_family = AF_UNIX;
	strncpy(saddr->sun_path, sock_path, UNIX_PATH_MAX);
}

static const char *_create_server_sock_path(void)
{
	static char sock_path[UNIX_PATH_MAX];

	snprintf(sock_path, UNIX_PATH_MAX, "%s_%d",
		 COMM_SOCKET_SERVER_SOCK_PATH_PREFIX, getpid());
	unlink(sock_path);
	return sock_path;
}

comm_socket *_comm_socket_new(void)
{
	comm_socket *cs;

	cs = (comm_socket *) calloc(1, sizeof(struct comm_socket));

	return cs;
}

int _comm_socket_free(comm_socket *cs)
{
	CHK_CS_RET(-EINVAL);
	free(cs);
	return 0;
}

int _comm_socket_create_server(comm_socket *cs, const char *sock_path)
{
	CHK_CS_RET(-EINVAL);
	if (cs->sockfd)
		return -EISCONN;


	int fd = -1;
	fd = _get_new_socket();
	if (fd < 0)
		return fd;

	struct sockaddr_un saddr;
	_set_sockaddr_un(&saddr, _create_server_sock_path());

	/* bind */
	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr))) {
		close(fd);
		return -errno;
	}

	/* chmod */
	if (chmod(saddr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
		close(fd);
		return -errno;
	}

	/* listen */
	if (-1 == listen(fd, 10)) {
		close(fd);
		return -errno;
	}

	cs->sockfd = fd;

	return 0;
}

static gboolean _read_socket(GIOChannel *source, GIOCondition io)
{
	return FALSE;
}

int comm_socket_server_add_wait_to_thread(comm_socket *cs, void *cb, 
					  void *cb_data, GMainContext *context)
{
	CHK_CS_RET(-EINVAL);
	if (!cs->sockfd)
		return -ENOTCONN;

	GIOChannel *channel;
	GSource *src;

	channel = g_io_channel_unix_new(cs->sockfd);
	src = g_io_create_watch(channel, G_IO_IN);
	g_source_set_callback(src, (GSourceFunc) _read_socket, NULL, NULL);
	g_source_attach(src, context);
	g_source_unref(src);

	return 0;
}

int comm_socket_connect_to_server(comm_socket *cs, 
				  const char *server_sock_path)
{
	CHK_CS_RET(-EINVAL);
	if (cs->sockfd)
		return -EISCONN;

	int r;

	int fd = -1;
	fd = _get_new_socket();
	if (fd < 0)
		return fd;

	/* Try to connect to server_sock_path */
	struct sockaddr_un saddr;
	_set_sockaddr_un(&saddr, server_sock_path);

	r = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (0 != r) {
		close(fd);
		return -r;
	}

	/* remember sockfd */
	cs->sockfd = fd;

	return 0;
}

int _comm_socket_disconnect(comm_socket *cs)
{
	CHK_CS_RET(-EINVAL);
	if (!cs->sockfd)
		return -EBADFD;

	if (close(cs->sockfd))
		return -errno;

	cs->sockfd = 0;

	return 0;
}

int _comm_socket_send(comm_socket *cs, void **data, int *datasize)
{
	CHK_CS_RET(-EINVAL);
	return 0;
}

int _comm_socket_recv(comm_socket *cs, void *data, int datasize)
{
	CHK_CS_RET(-EINVAL);
	return 0;
}

