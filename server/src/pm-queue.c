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





#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pkgmgr-server.h"
#include "pm-queue.h"

pm_queue_data *head = NULL;

void _pm_queue_init()
{
	head = NULL;
}

void _pm_queue_push(pm_dbus_msg item)
{
	pm_queue_data *data = NULL;
	pm_queue_data *cur = NULL;

	cur = head;

	data = _add_node();
	if (!data) {		/* fail to allocate mem */
		fprintf(stderr, "Fail to allocate memory\n");
		return;
	}

	strncpy(data->msg->req_id, item.req_id, strlen(item.req_id));
	data->msg->req_type = item.req_type;
	strncpy(data->msg->pkg_type, item.pkg_type, strlen(item.pkg_type));
	strncpy(data->msg->pkg_name, item.pkg_name, strlen(item.pkg_name));
	strncpy(data->msg->args, item.args, strlen(item.args));
	strncpy(data->msg->cookie, item.cookie, strlen(item.cookie));

	data->next = NULL;

	if (head == NULL)	/* first push */
		head = data;
	else {
		while (cur->next)
			cur = cur->next;

		cur->next = data;
	}
}

pm_dbus_msg _pm_queue_pop()
{
	pm_dbus_msg ret;
	pm_queue_data *cur = NULL;

	cur = head;

	memset(&ret, 0x00, sizeof(pm_dbus_msg));

	if (!head) {		/* queue is empty */
		ret.req_type = -1;
		return ret;
	}

	strncpy(ret.req_id, cur->msg->req_id, strlen(cur->msg->req_id));
	ret.req_type = cur->msg->req_type;
	strncpy(ret.pkg_type, cur->msg->pkg_type, strlen(cur->msg->pkg_type));
	strncpy(ret.pkg_name, cur->msg->pkg_name, strlen(cur->msg->pkg_name));
	strncpy(ret.args, cur->msg->args, strlen(cur->msg->args));
	strncpy(ret.cookie, cur->msg->cookie, strlen(cur->msg->cookie));

	head = cur->next;
	cur->next = NULL;

	free(cur->msg);
	free(cur);

	return ret;
}

pm_dbus_msg _pm_queue_get_head()
{
	pm_dbus_msg ret;
	pm_queue_data *cur = NULL;

	cur = head;

	memset(&ret, 0x00, sizeof(pm_dbus_msg));

	if (!head) {		/* queue is empty */
		ret.req_type = -1;
		return ret;
	}

	strncpy(ret.req_id, cur->msg->req_id, strlen(cur->msg->req_id));
	ret.req_type = cur->msg->req_type;
	strncpy(ret.pkg_type, cur->msg->pkg_type, strlen(cur->msg->pkg_type));
	strncpy(ret.pkg_name, cur->msg->pkg_name, strlen(cur->msg->pkg_name));
	strncpy(ret.args, cur->msg->args, strlen(cur->msg->args));
	strncpy(ret.cookie, cur->msg->cookie, strlen(cur->msg->cookie));

	return ret;
}

void _pm_queue_final()
{
	pm_queue_data *cur = NULL;
	pm_queue_data *tail = NULL;
	pm_queue_data *prev = NULL;

	if (!head) {		/* in case of head is NULL */
		fprintf(stderr, "queue is NULL\n");
		return;
	}

	while (head->next) {
		cur = head;

		while (cur->next) {
			printf(" -- [%p]\n", cur);
			prev = cur;
			cur = cur->next;
		}

		tail = cur;
		printf("%p\n", tail);

		free(tail->msg);
		free(tail);
		prev->next = NULL;
	}

	free(head->msg);
	free(head);

	head = NULL;
}

pm_queue_data *_add_node()
{
	pm_queue_data *newnode = NULL;

	newnode = (pm_queue_data *) malloc(sizeof(pm_queue_data));
	if (!newnode) {		/* if NULL */
		fprintf(stderr, "Mem alloc error\n");
		return NULL;
	}
	memset(newnode, 0x00, sizeof(pm_queue_data));

	newnode->msg = (pm_dbus_msg *) malloc(sizeof(pm_dbus_msg));
	if (!newnode->msg) {
		fprintf(stderr, "Mem alloc error\n");
		free(newnode);
		return NULL;
	}
	memset(newnode->msg, 0x00, sizeof(pm_dbus_msg));

	return newnode;
}

void _pm_queue_delete(pm_dbus_msg item)
{
	/* Assume that pacakge name is unique */
	pm_queue_data *cur = NULL;
	pm_queue_data *prev = NULL;

	cur = head;
	prev = cur;

	while (cur->next) {
		if (!strcmp(item.pkg_name, cur->msg->pkg_name)) {
			prev->next = cur->next;

			free(cur->msg);
			free(cur);

			break;
		}

		prev = cur;
		cur = cur->next;
	}
}

void _save_queue_status(pm_dbus_msg item, char *status)
{
	FILE *fp_status = NULL;

	fp_status = fopen(STATUS_FILE, "w");	/* overwrite always */
	if (!fp_status) {
		fprintf(stderr, "Can't open status file:%s\n", STATUS_FILE);
		return;
	}

	fprintf(fp_status, "%s\n", status);
	printf("[%s]\n", status);
	fprintf(fp_status, "%s\n", item.pkg_type);
	printf("[%s]\n", item.pkg_type);

	fsync(fp_status->_fileno);
	fclose(fp_status);
}

void _print_queue()
{
	pm_queue_data *cur = NULL;
	int index = 1;

	cur = head;

	if (!cur)
		printf(" ** queue is NULL **\n");

	while (cur) {
		printf(" * queue[%d]: [%s] [%d] [%s] [%s] [%s] [%s]\n",
		       index,
		       cur->msg->req_id,
		       cur->msg->req_type,
		       cur->msg->pkg_type,
		       cur->msg->pkg_name, cur->msg->args, cur->msg->cookie);

		index++;
		cur = cur->next;
	}
}
