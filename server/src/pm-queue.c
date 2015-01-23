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
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "pkgmgr-server.h"
#include "pm-queue.h"

#define BACKEND_INFO_DIR	"/etc/package-manager/backend"

static pm_queue_data *__get_head_from_pkgtype(pm_dbus_msg *item);
static void __update_head_from_pkgtype(pm_queue_data *data);
static int __entry_exist(char *backend);
static int __is_pkg_supported(char *pkgtype);

queue_info_map *start = NULL;
pthread_mutex_t pm_mutex;
int entries = 0;
int slot = 0;
int num_of_backends = 0;

/*Function to check whether a particular package type
is supported or not. It parses the queue info map
to get the information.
It will prevent the accidental hanging of server.
Returns 1 if found.*/
static int __is_pkg_supported(char *pkgtype)
{
	queue_info_map *ptr = NULL;
	ptr = start;
	int i = 0;
	for(i = 0; i < entries; i++)
	{
		if (!strncmp(ptr->pkgtype, pkgtype, MAX_PKG_TYPE_LEN))
			return 1;
		else {
			ptr++;
			continue;
		}
	}
	return 0;
}

/*tells whether a particular backend exists in the
* info map or not.
* on Success it return the queue slot of the already present entry
* on Failure -1 is returned*/
static int __entry_exist(char *backend)
{
	queue_info_map *ptr = NULL;
	ptr = start;
	int i = 0;
	for(i = 0; i < entries; i++)
	{
		if (!strncmp(ptr->backend, backend, MAX_PKG_NAME_LEN))
			return ptr->queue_slot;
		else {
			ptr++;
			continue;
		}
	}
	return -1;
}

/*In case of first push, it updates the queue head
and copies it to all duplicate entries in queue info map*/
static void __update_head_from_pkgtype(pm_queue_data *data)
{
	queue_info_map *ptr = NULL;
	ptr = start;
	int slot = -1;
	int i = 0;
	for(i = 0; i < entries; i++)
	{
		if (!strncmp(ptr->pkgtype, data->msg->pkg_type, MAX_PKG_TYPE_LEN)) {
			ptr->head = data;
			slot = ptr->queue_slot;
		}
		else {
			ptr++;
			continue;
		}
	}
	/*update head for each duplicate entry*/
	ptr = start;
	for(i = 0; i < entries; i++)
	{
		if(ptr->queue_slot == slot && !ptr->head) {
			ptr->head = data;
		}
		ptr++;
	}
	return;
}

/*Gets the queue head based on pkg type*/
static pm_queue_data *__get_head_from_pkgtype(pm_dbus_msg *item)
{
	queue_info_map *ptr = NULL;
	ptr = start;
	int i = 0;
	for(i = 0; i < entries; i++)
	{
		if (!strncmp(ptr->pkgtype, item->pkg_type, MAX_PKG_TYPE_LEN))
			return ptr->head;
		else {
			ptr++;
			continue;
		}
	}
	return NULL;

}

int _pm_queue_init()
{
	/*Find the num of backends currently supported and initialize
	that many queues. It is dynamically determined.*/
	struct dirent **namelist;
	struct stat fileinfo;
	queue_info_map *ptr = NULL;
	int n = 0;
	int c = 0;
	int i = 0;
	int ret = 0;
	char abs_filename[MAX_PKG_NAME_LEN] = {'\0'};
	char buf[MAX_PKG_NAME_LEN] = {'\0'};
	n = scandir(BACKEND_INFO_DIR, &namelist, NULL, alphasort);
	if (n < 0) {
		perror("scandir");
		return -1;
	}
	i = n;
	/*Find number of backends (symlinks + executables)
	The /usr/etc/package-manager/backend dir should not conatin
	any other file except the backends.*/
	while(n--)
	{
		if(!strcmp(namelist[n]->d_name, ".") ||
			!strcmp(namelist[n]->d_name, ".."))
				continue;
		snprintf(abs_filename, MAX_PKG_NAME_LEN, "%s/%s",
			BACKEND_INFO_DIR, namelist[n]->d_name);
		if (lstat(abs_filename, &fileinfo)) {
			perror("lstat");
			continue;
		}
		if (S_ISDIR(fileinfo.st_mode))
			continue;
		c++;
		memset(abs_filename, 0x00, MAX_PKG_NAME_LEN);
	}
	/*Add entries to info map.*/
	ptr = (queue_info_map*)calloc(c , sizeof(queue_info_map));
	memset(ptr, '\0', c * sizeof(queue_info_map));
	start = ptr;
	for(n = 0; n < c ; n++)
	{
		ptr->backend[0] = '\0';
		ptr->head = NULL;
		ptr->queue_slot = -2;/*-1 can be error return*/
		ptr->pkgtype[0] = '\0';
		ptr++;
	}
	n = i;
	ptr = start;
	while(n--)
	{
		if(!strcmp(namelist[n]->d_name, ".") ||
			!strcmp(namelist[n]->d_name, ".."))
				continue;
		snprintf(abs_filename, MAX_PKG_NAME_LEN, "%s/%s",
			BACKEND_INFO_DIR, namelist[n]->d_name);
		if (lstat(abs_filename, &fileinfo) < 0) {
			perror(abs_filename);
			return -1;
		}
		if (S_ISDIR(fileinfo.st_mode))
			continue;
		/*Found backend*/
		if (S_ISLNK(fileinfo.st_mode)) {
			/*found a symlink*/
			ret = readlink(abs_filename, buf, MAX_PKG_NAME_LEN - 1);
			if (ret == -1) {
				perror("readlink");
				return -1;
			}
			buf[ret] = '\0';
		}
		/*executable*/
		else {
			strncpy(buf, abs_filename, MAX_PKG_NAME_LEN - 1);
		}
		ret = __entry_exist(buf);
		if (ret == -1) {
			strncpy(ptr->backend, buf, MAX_PKG_NAME_LEN - 1);
			strncpy(ptr->pkgtype, namelist[n]->d_name, MAX_PKG_TYPE_LEN - 1);
			ptr->queue_slot = slot;
			ptr->head = NULL;
			entries++;
			slot++;
			ptr++;
		}
		else {
			strncpy(ptr->backend, buf, MAX_PKG_NAME_LEN - 1);
			strncpy(ptr->pkgtype, namelist[n]->d_name, MAX_PKG_TYPE_LEN - 1);
			ptr->queue_slot = ret;
			ptr->head = NULL;
			entries++;
			ptr++;
		}
		free(namelist[n]);
		memset(buf, 0x00, MAX_PKG_NAME_LEN);
		continue;
	}
	free(namelist);
	num_of_backends = slot;
	pthread_mutex_init(&pm_mutex, NULL);

#ifdef DEBUG_INFO
	/*Debug info*/
	DBG("Queue Info Map");
	DBG("Number of Backends is %d", num_of_backends);
	DBG("Number of Entries is %d", entries);
	DBG("Backend\tType\tSlot\tHead");
	ptr = start;
	for(n = 0; n < entries; n++)
	{
		DBG("%s\t%s\t%d\t%p", ptr->backend, ptr->pkgtype, ptr->queue_slot, ptr->head);
		ptr++;
	}
#endif

	return 0;
}

int _pm_queue_push(pm_dbus_msg *item)
{
	pm_queue_data *data = NULL;
	pm_queue_data *cur = NULL;
	pm_queue_data *tmp = NULL;
	int ret = 0;
	ret = __is_pkg_supported(item->pkg_type);
	if (ret == 0)
		return -1;

	pthread_mutex_lock(&pm_mutex);
	cur = __get_head_from_pkgtype(item);
	tmp = cur;

	data = _add_node();
	if (!data) { /* fail to allocate mem */
		ERR("Fail to allocate memory\n");
		pthread_mutex_unlock(&pm_mutex);
		return -1;
	}

	strncpy(data->msg->req_id, item->req_id, strlen(item->req_id));
	data->msg->req_type = item->req_type;
	data->msg->uid = item->uid;
	strncpy(data->msg->pkg_type, item->pkg_type, strlen(item->pkg_type));
	strncpy(data->msg->pkgid, item->pkgid, strlen(item->pkgid));
	strncpy(data->msg->args, item->args, strlen(item->args));
	strncpy(data->msg->cookie, item->cookie, strlen(item->cookie));

	data->next = NULL;

	if (cur == NULL) {
		/* first push */
		cur = data;
		__update_head_from_pkgtype(data);
	}
	else {
		while (tmp->next)
			tmp = tmp->next;

		tmp->next = data;
	}
	pthread_mutex_unlock(&pm_mutex);
	return 0;
}

/*pop request from queue slot "position" */
pm_dbus_msg *_pm_queue_pop(int position)
{
	pm_dbus_msg *ret;
	pm_queue_data *cur = NULL;
	pm_queue_data *saveptr = NULL;
	queue_info_map *ptr = NULL;
	int i = 0;

	ret = (pm_dbus_msg *) malloc(sizeof(pm_dbus_msg));
	if (!ret) {
		ERR("Mem alloc error");
		return NULL;
	}
	memset(ret, 0x00, sizeof(pm_dbus_msg));
	pthread_mutex_lock(&pm_mutex);
	ptr = start;
	for(i = 0; i < entries; i++)
	{
		if (ptr->queue_slot == position) {
				cur = ptr->head;
				break;
		}
		ptr++;
	}

	if (!cur) {		/* queue is empty */
		ret->req_type = -1;
		pthread_mutex_unlock(&pm_mutex);
		return ret;
	}

	strncpy(ret->req_id, cur->msg->req_id, strlen(cur->msg->req_id));
	ret->req_type = cur->msg->req_type;
	ret->uid = cur->msg->uid;
	strncpy(ret->pkg_type, cur->msg->pkg_type, strlen(cur->msg->pkg_type));
	strncpy(ret->pkgid, cur->msg->pkgid, strlen(cur->msg->pkgid));
	strncpy(ret->args, cur->msg->args, strlen(cur->msg->args));
	strncpy(ret->cookie, cur->msg->cookie, strlen(cur->msg->cookie));

	ptr->head = cur->next;
	saveptr = ptr->head;
	cur->next = NULL;
	free(cur->msg);
	free(cur);
	/*update head for each duplicate queue entry*/
	ptr = start;
	for(i = 0; i < entries; i++)
	{
		if(ptr->queue_slot == position) {
			ptr->head = saveptr;
		}
		ptr++;
	}
	pthread_mutex_unlock(&pm_mutex);
	return ret;
}

/*populate an array of all queue heads and delete them one by one*/
void _pm_queue_final()
{
	int c = 0;
	int i = 0;
	int slot = -1;
	pm_queue_data *cur = NULL;
	pm_queue_data *tail = NULL;
	pm_queue_data *prev = NULL;
	pm_queue_data *head[MAX_QUEUE_NUM] = {NULL,};
	queue_info_map *ptr = NULL;
	ptr = start;

	for(i = 0; i < num_of_backends; i++)
	{
		head[i] = NULL;
	}

	for(i = 0; i < entries; i++)
	{
		if (ptr->queue_slot <= slot) {
			ptr++;
			continue;
		}
		else {
			head[c] = ptr->head;
			slot = ptr->queue_slot;
			c++;
			ptr++;
		}
	}

	c = 0;
	while(c < num_of_backends) {
		if (!head[c]) { /* in case of head is NULL */
			ERR("queue is NULL");
			c = c + 1;
			continue;
		}

		while (head[c]->next) {
			cur = head[c]->next;

			while (cur->next) {
				prev = cur;
				cur = cur->next;
			}

			tail = cur;

			free(tail->msg);
			free(tail);
			prev->next = NULL;
		}

		free(head[c]->msg);
		free(head[c]);

		head[c] = NULL;
		c = c + 1;
	}
	/*Free the info map*/
	if (start) {
		free(start);
		start = NULL;
	}
}

pm_queue_data *_add_node()
{
	pm_queue_data *newnode = NULL;

	newnode = (pm_queue_data *) malloc(sizeof(pm_queue_data));
	if (!newnode) { /* if NULL */
		ERR("Mem alloc error");
		return NULL;
	}
	memset(newnode, 0x00, sizeof(pm_queue_data));

	newnode->msg = (pm_dbus_msg *) malloc(sizeof(pm_dbus_msg));
	if (!newnode->msg) {
		ERR("Mem alloc error");
		free(newnode);
		return NULL;
	}
	memset(newnode->msg, 0x00, sizeof(pm_dbus_msg));

	return newnode;
}

void _pm_queue_delete(pm_dbus_msg *item)
{
	/* Assume that pacakge name is unique */
	pm_queue_data *cur = NULL;
	pm_queue_data *prev = NULL;
	cur = __get_head_from_pkgtype(item);
	prev = cur;
	if (cur) {
		while (cur->next) {
			if (!strcmp(item->pkgid, cur->msg->pkgid)) {
				prev->next = cur->next;
				free(cur->msg);
				free(cur);
				break;
			}
			prev = cur;
			cur = cur->next;
		}
	}
}

void _save_queue_status(pm_dbus_msg *item, char *status)
{
	FILE *fp_status = NULL;

	fp_status = fopen(STATUS_FILE, "w");	/* overwrite always */
	if (!fp_status) {
		ERR("Can't open status file:%s", STATUS_FILE);
		return;
	}

	fprintf(fp_status, "%s\n", status);
	fprintf(fp_status, "%s\n", item->pkg_type);

	fsync(fileno(fp_status));

	fclose(fp_status);
}

void _print_queue(int position)
{
	pm_queue_data *cur = NULL;
	queue_info_map *ptr = start;
	int i = 0;
	for(i =0; i < entries; i++)
	{
		if (ptr->queue_slot == position) {
				cur = ptr->head;
				break;
		}
		ptr++;
	}
	int index = 1;
	if (!cur) {
		return;
	}

	while (cur) {
		index++;
		cur = cur->next;
	}
}
