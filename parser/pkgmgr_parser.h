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

#ifndef __PKGMGR_PARSER_H__
#define __PKGMGR_PARSER_H__

/**
 * @file pkgmgr_parser.h
 * @author Sewook Park <sewook7.park@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 * @version 0.1
 * @brief    This file declares API of pkgmgr_parser
 */

#include <libxml/xmlreader.h>

#ifdef __cplusplus
extern "C" {
#endif
#define DEFAULT_LOCALE		"No Locale"
/**
 * List definitions.
 * All lists are doubly-linked, the last element is stored to list pointer,
 * which means that lists must be looped using the prev pointer, or by
 * calling LISTHEAD first to go to start in order to use the next pointer.
 */
#define LISTADD(list, node)			\
    do {					\
	(node)->prev = (list);			\
	if (list) (node)->next = (list)->next;	\
	else (node)->next = NULL;		\
	if (list) (list)->next = (node);	\
	(list) = (node);			\
    } while (0);

#define NODEADD(node1, node2)					\
    do {							\
	(node2)->prev = (node1);				\
	(node2)->next = (node1)->next;				\
	if ((node1)->next) (node1)->next->prev = (node2);	\
	(node1)->next = (node2);				\
    } while (0);

#define LISTCAT(list, first, last)		\
    if ((first) && (last)) {			\
	(first)->prev = (list);			\
	(list) = (last);			\
    }

#define LISTDEL(list, node)					\
    do {							\
	if ((node)->prev) (node)->prev->next = (node)->next;	\
	if ((node)->next) (node)->next->prev = (node)->prev;	\
	if (!((node)->prev) && !((node)->next)) (list) = NULL;	\
    } while (0);

#define LISTHEAD(list, node)					\
    for ((node) = (list); (node)->prev; (node) = (node)->prev);
#define LISTTAIL(list, node)					\
    for ((node) = (list); (node)->next; (node) = (node)->next);

typedef struct icon_x {
	const char *name;
	const char *text;
	const char *lang;
	const char *section;
	const char *size;
	struct icon_x *prev;
	struct icon_x *next;
} icon_x;

typedef struct allowed_x {
	const char *name;
	const char *text;
	struct allowed_x *prev;
	struct allowed_x *next;
} allowed_x;

typedef struct request_x {
	const char *text;
	struct request_x *prev;
	struct request_x *next;
} request_x;

typedef struct define_x {
	const char *path;
	struct allowed_x *allowed;
	struct request_x *request;
	struct define_x *prev;
	struct define_x *next;
} define_x;

typedef struct timeout_x {
	const char *text;
	struct timeout_x *prev;
	struct timeout_x *next;
} timeout_x;

typedef struct network_x {
	const char *text;
	struct network_x *prev;
	struct network_x *next;
} network_x;

typedef struct period_x {
	const char *text;
	struct period_x *prev;
	struct period_x *next;
} period_x;

typedef struct autolaunch_x {
	const char *text;
	struct autolaunch_x *prev;
	struct autolaunch_x *next;
} autolaunch_x;

typedef struct file_x {
	const char *text;
	struct file_x *prev;
	struct file_x *next;
} file_x;

typedef struct size_x {
	const char *text;
	struct size_x *prev;
	struct size_x *next;
} size_x;


typedef struct datashare_x {
	struct define_x *define;
	struct request_x *request;
	struct datashare_x *prev;
	struct datashare_x *next;
} datashare_x;

typedef struct description_x {
	const char *name;
	const char *text;
	const char *lang;
	struct description_x *prev;
	struct description_x *next;
} description_x;

typedef struct registry_x {
	const char *name;
	const char *text;
	struct registry_x *prev;
	struct registry_x *next;
} registry_x;

typedef struct database_x {
	const char *name;
	const char *text;
	struct database_x *prev;
	struct database_x *next;
} database_x;

typedef struct layout_x {
	const char *name;
	const char *text;
	struct layout_x *prev;
	struct layout_x *next;
} layout_x;

typedef struct label_x {
	const char *name;
	const char *text;
	const char *lang;
	struct label_x *prev;
	struct label_x *next;
} label_x;

typedef struct author_x {
	const char *email;
	const char *href;
	const char *text;
	const char *lang;
	struct author_x *prev;
	struct author_x *next;
} author_x;

typedef struct license_x {
	const char *text;
	const char *lang;
	struct license_x *prev;
	struct license_x *next;
} license_x;

typedef struct operation_x {
	const char *name;
	const char *text;
	struct operation_x *prev;
	struct operation_x *next;
} operation_x;

typedef struct uri_x {
	const char *name;
	const char *text;
	struct uri_x *prev;
	struct uri_x *next;
} uri_x;

typedef struct mime_x {
	const char *name;
	const char *text;
	struct mime_x *prev;
	struct mime_x *next;
} mime_x;

typedef struct condition_x {
	const char *name;
	const char *text;
	struct condition_x *prev;
	struct condition_x *next;
} condition_x;

typedef struct notification_x {
	const char *name;
	const char *text;
	struct notification_x *prev;
	struct notification_x *next;
} notification_x;

typedef struct appsvc_x {
	const char *text;
	struct operation_x *operation;
	struct uri_x *uri;
	struct mime_x *mime;
	struct appsvc_x *prev;
	struct appsvc_x *next;
} appsvc_x;

typedef struct launchconditions_x {
	const char *text;
	struct condition_x *condition;
	struct launchconditions_x *prev;
	struct launchconditions_x *next;
} launchconditions_x;


typedef struct compatibility_x {
	const char *name;
	const char *text;
	struct compatibility_x *prev;
	struct compatibility_x *next;
}compatibility_x;

typedef struct deviceprofile_x {
	const char *name;
	const char *text;
	struct deviceprofile_x *prev;
	struct deviceprofile_x *next;
}deviceprofile_x;

typedef struct resolution_x {
	const char *mimetype;
	const char *urischeme;
	struct resolution_x *prev;
	struct resolution_x *next;
} resolution_x;

typedef struct capability_x {
	const char *operationid;
	const char *access;
	struct resolution_x *resolution;
	struct capability_x *prev;
	struct capability_x *next;
} capability_x;

typedef struct appcontrol_x {
	const char *providerid;
	const char *category;
	struct capability_x *capability;
	struct appcontrol_x *prev;
	struct appcontrol_x *next;
} appcontrol_x;

typedef struct datacontrol_x {
	const char *providerid;
	struct capability_x *capability;
	struct datacontrol_x *prev;
	struct datacontrol_x *next;
} datacontrol_x;

typedef struct uiapplication_x {
	const char *appid;
	const char *exec;
	const char *nodisplay;
	const char *multiple;
	const char *taskmanage;
	const char *type;
	const char *categories;
	const char *extraid;
	struct label_x *label;
	struct icon_x *icon;
	struct appsvc_x *appsvc;
	struct appcontrol_x *appcontrol;
	struct launchconditions_x *launchconditions;
	struct notification_x *notification;
	struct datashare_x *datashare;
	struct uiapplication_x *prev;
	struct uiapplication_x *next;
} uiapplication_x;

typedef struct serviceapplication_x {
	const char *appid;
	const char *exec;
	const char *onboot;
	const char *autorestart;
	const char *type;
	struct label_x *label;
	struct icon_x *icon;
	struct appsvc_x *appsvc;
	struct appcontrol_x *appcontrol;
	struct datacontrol_x *datacontrol;
	struct launchconditions_x *launchconditions;
	struct notification_x *notification;
	struct datashare_x *datashare;
	struct serviceapplication_x *prev;
	struct serviceapplication_x *next;
} serviceapplication_x;

typedef struct daemon_x {
	const char *name;
	const char *text;
	struct daemon_x *prev;
	struct daemon_x *next;
} daemon_x;

typedef struct theme_x {
	const char *name;
	const char *text;
	struct theme_x *prev;
	struct theme_x *next;
} theme_x;

typedef struct font_x {
	const char *name;
	const char *text;
	struct font_x *prev;
	struct font_x *next;
} font_x;

typedef struct ime_x {
	const char *name;
	const char *text;
	struct ime_x *prev;
	struct ime_x *next;
} ime_x;

typedef struct category_x{
	const char *name;
	struct category_x *prev;
	struct category_x *next;
} category_x;

typedef struct cluster_x{
	const char *name;
	struct category_x *category;
	struct cluster_x *prev;
	struct cluster_x *next;
} cluster_x;

typedef struct group_x{
	struct cluster_x *cluster;
	struct group_x *prev;
	struct group_x *next;
} group_x;

typedef struct grp_x{
	const char *text;
	struct grp_x *prev;
	struct grp_x *next;
} grp_x;

typedef struct security_x{
	const char *isolate;
	struct security_x *prev;
	struct security_x *next;
} security_x;

typedef struct libexec_x{
	const char *text;
	struct libexec_x *prev;
	struct libexec_x *next;
} libexec_x;

typedef struct lbox_x{
	const char *type;
	struct size_x *size;
	struct lbox_x *prev;
	struct lbox_x *next;
} lbox_x;

typedef struct pd_x {
	const char *type;
	const char *language;
	struct file_x *file;
	struct grp_x *grp;
	struct size_x *size;
	struct pd_x *prev;
	struct pd_x *next;
} pd_x;

typedef struct control_x {
	struct timeout_x *timeout;
	struct period_x *period;
	struct network_x *network;
	struct autolaunch_x *autolaunch;
	struct control_x *prev;
	struct control_x *next;
} control_x;

typedef struct content_x {
	struct lbox_x *lbox;
	struct pd_x *pd;
	struct content_x *prev;
	struct content_x *next;
} content_x;


typedef struct livebox_x {
	const char *application;
	const char *abi;
	const char *type;
	struct icon_x *icon;
	struct label_x *label;
	struct libexec_x *libexec;
	struct control_x *control;
	struct content_x *content;
	struct group_x *group;
	struct security_x *security;
	struct size_x *size;
	struct livebox_x *prev;
	struct livebox_x *next;
} livebox_x;

typedef struct manifest_x {
	const char *package;
	const char *version;
	const char *installlocation;;
	const char *ns;
	const char *removable;
	const char *preload;
	const char *readonly;
	const char *type;
	struct icon_x *icon;
	struct label_x *label;
	struct author_x *author;
	struct description_x *description;
	struct license_x *license;
	struct uiapplication_x *uiapplication;
	struct serviceapplication_x *serviceapplication;
	struct daemon_x *daemon;
	struct theme_x *theme;
	struct font_x *font;
	struct ime_x *ime;
	struct livebox_x *livebox;
	struct compatibility_x *compatibility;
	struct deviceprofile_x *deviceprofile;
} manifest_x;

/* These APIs are for installer backends */

/**
 * @brief routine to get the manifest file from pkgname.
 * @param[in] pkgname, the application package name
 * @return: on sucess it returns the manifest file path, on failure it returns NULL
 */
char *pkgmgr_parser_get_manifest_file(const char *pkgname);

/**
 * @brief routine to parse the manifest file after installation
 * @param[in] manifest, the application manifest file path
 * @return: on sucess it returns 0, on failure it returns -1
 */
int pkgmgr_parser_parse_manifest_for_installation(const char *manifest, char *const tagv[]);

/**
 * @brief routine to parse the manifest file after upgradation
 * @param[in] manifest, the application manifest file path
 * @return: on sucess it returns 0, on failure it returns -1
 */
int pkgmgr_parser_parse_manifest_for_upgrade(const char *manifest, char *const tagv[]);

/**
 * @brief routine to parse the manifest file after uninstallation
 * @param[in] manifest, the application manifest file path
 * @return: on sucess it returns 0, on failure it returns -1
 */
int pkgmgr_parser_parse_manifest_for_uninstallation(const char *manifest, char *const tagv[]);

/**
 * @check validation for manifest
 * @param[in] manifest, the application manifest file path
 * @return: on sucess it returns 0, on failure it returns -1
 */
int pkgmgr_parser_check_manifest_validation(const char *manifest);

/**
 * @brief routine to free the manifest pointer obtained after parsing
 * @param[in] mfx, the pointer to manifest structure
 */
void pkgmgr_parser_free_manifest_xml(manifest_x *mfx);
manifest_x *pkgmr_parser_process_manifest_xml(const char *manifest);

/* These APIs are intended to call parser directly */
typedef int (*ps_iter_fn) (const char *tag, int type, void *userdata);

int pkgmgr_parser_has_parser(const char *tag, int *type);
int pkgmgr_parser_get_list(ps_iter_fn iter_fn, void *data);
int pkgmgr_parser_run_parser_for_installation(xmlDocPtr docPtr, const char *tag, const char *pkgname);
int pkgmgr_parser_run_parser_for_upgrade(xmlDocPtr docPtr, const char *tag, const char *pkgname);
int pkgmgr_parser_run_parser_for_uninstallation(xmlDocPtr docPtr, const char *tag, const char *pkgname);

#ifdef __cplusplus
}
#endif
#endif				/* __PKGMGR_PARSER_H__ */
