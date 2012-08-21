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

#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemas.h>


#include "pkgmgr-internal.h"
#include "pkgmgr_parser.h"
#include "pkgmgr_parser_internal.h"
#include "pkgmgr_parser_db.h"
#include "package-manager.h"

#define MANIFEST_RW_DIRECTORY "/opt/share/packages"
#define MANIFEST_RO_DIRECTORY "/usr/share/packages"
#define ASCII(s) (const char *)s
#define XMLCHAR(s) (const xmlChar *)s

/* operation_type */
typedef enum {
	ACTION_INSTALL = 0,
	ACTION_UPGRADE,
	ACTION_UNINSTALL,
	ACTION_MAX
} ACTION_TYPE;

char *package;

static int __ps_process_content(xmlTextReaderPtr reader, content_x *content);
static int __ps_process_control(xmlTextReaderPtr reader, control_x *control);
static int __ps_process_group(xmlTextReaderPtr reader, group_x *group);
static int __ps_process_livebox(xmlTextReaderPtr reader, livebox_x *livebox);
static int __ps_process_pd(xmlTextReaderPtr reader, pd_x *pd);
static int __ps_process_label(xmlTextReaderPtr reader, label_x *label);
static int __ps_process_deviceprofile(xmlTextReaderPtr reader, deviceprofile_x *deviceprofile);
static int __ps_process_timeout(xmlTextReaderPtr reader, timeout_x *timeout);
static int __ps_process_network(xmlTextReaderPtr reader, network_x *network);
static int __ps_process_allowed(xmlTextReaderPtr reader, allowed_x *allowed);
static int __ps_process_period(xmlTextReaderPtr reader, period_x *period);
static int __ps_process_autolaunch(xmlTextReaderPtr reader, autolaunch_x *autolaunch);
static int __ps_process_file(xmlTextReaderPtr reader, file_x *file);
static int __ps_process_size(xmlTextReaderPtr reader, size_x *size);
static int __ps_process_grp(xmlTextReaderPtr reader, grp_x *grp);
static int __ps_process_operation(xmlTextReaderPtr reader, operation_x *operation);
static int __ps_process_uri(xmlTextReaderPtr reader, uri_x *uri);
static int __ps_process_mime(xmlTextReaderPtr reader, mime_x *mime);
static int __ps_process_condition(xmlTextReaderPtr reader, condition_x *condition);
static int __ps_process_notification(xmlTextReaderPtr reader, notification_x *notifiation);
static int __ps_process_category(xmlTextReaderPtr reader, category_x *category);
static int __ps_process_security(xmlTextReaderPtr reader, security_x *security);
static int __ps_process_libexec(xmlTextReaderPtr reader, libexec_x *libexec);
static int __ps_process_compatibility(xmlTextReaderPtr reader, compatibility_x *compatibility);
static int __ps_process_resolution(xmlTextReaderPtr reader, resolution_x *resolution);
static int __ps_process_request(xmlTextReaderPtr reader, request_x *request);
static int __ps_process_define(xmlTextReaderPtr reader, define_x *define);
static int __ps_process_registry(xmlTextReaderPtr reader, registry_x *registry);
static int __ps_process_database(xmlTextReaderPtr reader, database_x *database);
static int __ps_process_appsvc(xmlTextReaderPtr reader, appsvc_x *appsvc);
static int __ps_process_launchconditions(xmlTextReaderPtr reader, launchconditions_x *launchconditions);
static int __ps_process_datashare(xmlTextReaderPtr reader, datashare_x *datashare);
static int __ps_process_layout(xmlTextReaderPtr reader, layout_x *layout);
static int __ps_process_cluster(xmlTextReaderPtr reader, cluster_x *cluster);
static int __ps_process_icon(xmlTextReaderPtr reader, icon_x *icon);
static int __ps_process_lbox(xmlTextReaderPtr reader, lbox_x *lbox);
static int __ps_process_author(xmlTextReaderPtr reader, author_x *author);
static int __ps_process_description(xmlTextReaderPtr reader, description_x *description);
static int __ps_process_capability(xmlTextReaderPtr reader, capability_x *capability);
static int __ps_process_license(xmlTextReaderPtr reader, license_x *license);
static int __ps_process_appcontrol(xmlTextReaderPtr reader, appcontrol_x *appcontrol);
static int __ps_process_datacontrol(xmlTextReaderPtr reader, datacontrol_x *datacontrol);
static int __ps_process_uiapplication(xmlTextReaderPtr reader, uiapplication_x *uiapplication);
static int __ps_process_serviceapplication(xmlTextReaderPtr reader, serviceapplication_x *serviceapplication);
static int __ps_process_font(xmlTextReaderPtr reader, font_x *font);
static int __ps_process_theme(xmlTextReaderPtr reader, theme_x *theme);
static int __ps_process_daemon(xmlTextReaderPtr reader, daemon_x *daemon);
static int __ps_process_ime(xmlTextReaderPtr reader, ime_x *ime);
static void __ps_free_content(content_x *content);
static void __ps_free_control(control_x *control);
static void __ps_free_group(group_x *group);
static void __ps_free_livebox(livebox_x *livebox);
static void __ps_free_pd(pd_x *pd);
static void __ps_free_label(label_x *label);
static void __ps_free_deviceprofile(deviceprofile_x * deviceprofile);
static void __ps_free_timeout(timeout_x *timeout);
static void __ps_free_network(network_x *network);
static void __ps_free_allowed(allowed_x *allowed);
static void __ps_free_period(period_x *period);
static void __ps_free_autolaunch(autolaunch_x *autolaunch);
static void __ps_free_file(file_x *file);
static void __ps_free_size(size_x *size);
static void __ps_free_grp(grp_x *grp);
static void __ps_free_operation(operation_x *operation);
static void __ps_free_uri(uri_x *uri);
static void __ps_free_mime(mime_x *mime);
static void __ps_free_condition(condition_x *condition);
static void __ps_free_notification(notification_x *notifiation);
static void __ps_free_category(category_x *category);
static void __ps_free_security(security_x *security);
static void __ps_free_libexec(libexec_x *libexec);
static void __ps_free_compatibility(compatibility_x *compatibility);
static void __ps_free_resolution(resolution_x *resolution);
static void __ps_free_request(request_x *request);
static void __ps_free_define(define_x *define);
static void __ps_free_registry(registry_x *registry);
static void __ps_free_database(database_x *database);
static void __ps_free_appsvc(appsvc_x *appsvc);
static void __ps_free_launchconditions(launchconditions_x *launchconditions);
static void __ps_free_datashare(datashare_x *datashare);
static void __ps_free_layout(layout_x *layout);
static void __ps_free_cluster(cluster_x *cluster);
static void __ps_free_icon(icon_x *icon);
static void __ps_free_lbox(lbox_x *lbox);
static void __ps_free_author(author_x *author);
static void __ps_free_description(description_x *description);
static void __ps_free_capability(capability_x *capability);
static void __ps_free_license(license_x *license);
static void __ps_free_appcontrol(appcontrol_x *appcontrol);
static void __ps_free_datacontrol(datacontrol_x *datacontrol);
static void __ps_free_uiapplication(uiapplication_x *uiapplication);
static void __ps_free_serviceapplication(serviceapplication_x *serviceapplication);
static void __ps_free_font(font_x *font);
static void __ps_free_theme(theme_x *theme);
static void __ps_free_daemon(daemon_x *daemon);
static void __ps_free_ime(ime_x *ime);
static char *__pkgname_to_manifest(const char *pkgname);
static int __next_child_element(xmlTextReaderPtr reader, int depth);
static int __start_process(xmlTextReaderPtr reader, manifest_x * mfx);
static int __process_manifest(xmlTextReaderPtr reader, manifest_x * mfx);
static void __str_trim(char *input);
static char *__get_parser_plugin(const char *type);
static int __ps_run_parser(xmlDocPtr docPtr, const char *tag, ACTION_TYPE action, const char *pkgname);
static int __run_parser_prestep(xmlTextReaderPtr reader, ACTION_TYPE action, const char *pkgname);
static void __processNode(xmlTextReaderPtr reader, ACTION_TYPE action, char *const tagv[], const char *pkgname);
static void __streamFile(const char *filename, ACTION_TYPE action, char *const tagv[], const char *pkgname);
static int __validate_appid(const char *pkgname, const char *appid, char **newappid);

static void __str_trim(char *input)
{
	char *trim_str = input;

	if (input == NULL)
		return;

	while (*input != 0) {
		if (!isspace(*input)) {
			*trim_str = *input;
			trim_str++;
		}
		input++;
	}

	*trim_str = 0;
	return;
}

static int __validate_appid(const char *pkgname, const char *appid, char **newappid)
{
	if (!pkgname || !appid || !newappid) {
		DBG("Arg supplied is NULL\n");
		return -1;
	}
	int pkglen = strlen(pkgname);
	int applen = strlen(appid);
	char *ptr = NULL;
	char *newapp = NULL;
	int len = 0;
	if (strncmp(appid, ".", 1) == 0) {
		len = pkglen + applen + 1;
		newapp = calloc(1,len);
		if (newapp == NULL) {
			DBG("Malloc failed\n");
			return -1;
		}
		strncpy(newapp, pkgname, pkglen);
		strncat(newapp, appid, applen);
		DBG("new appid is %s\n", newapp);
		*newappid = newapp;
		return 0;
	}
	if (applen < pkglen) {
		DBG("app id is not proper\n");
		*newappid = NULL;
#ifdef _VALIDATE_APPID_
		return -1;
#else
		return 0;
#endif
	}
	if (!strcmp(appid, pkgname)) {
		DBG("appid is proper\n");
		*newappid = NULL;
		return 0;
	}
	else if (strncmp(appid, pkgname, pkglen) == 0) {
		ptr = strstr(appid, pkgname);
		ptr = ptr + pkglen;
		if (strncmp(ptr, ".", 1) == 0) {
			DBG("appid is proper\n");
			*newappid = NULL;
			return 0;
		}
		else {
			DBG("appid is not proper\n");
			*newappid = NULL;
#ifdef _VALIDATE_APPID_
			return -1;
#else
			return 0;
#endif
		}
	} else {
		DBG("appid is not proper\n");
		*newappid = NULL;
#ifdef _VALIDATE_APPID_
		return -1;
#else
		return 0;
#endif
	}
	return 0;
}


static char *__get_parser_plugin(const char *type)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	char temp_path[1024] = { 0 };
	char *lib_path = NULL;
	char *path = NULL;

	if (type == NULL) {
		_LOGE("invalid argument\n");
		return NULL;
	}

	fp = fopen(PKG_CONF_PATH, "r");
	if (fp == NULL) {
		_LOGE("no matching backendlib\n");
		return NULL;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		__str_trim(buffer);

		if ((path = strstr(buffer, PKG_PARSERLIB)) != NULL) {
			_LOGD("[%s]\n", path);
			path = path + strlen(PKG_PARSERLIB);
			_LOGD("[%s]\n", path);

			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if (path == NULL) {
		_LOGE("no matching backendlib\n");
		return NULL;
	}

	snprintf(temp_path, sizeof(temp_path) - 1, "%slib%s.so", path, type);

	return strdup(temp_path);
}

static int __ps_run_parser(xmlDocPtr docPtr, const char *tag,
			   ACTION_TYPE action, const char *pkgname)
{
	char *lib_path = NULL;
	void *lib_handle = NULL;
	int (*plugin_install) (xmlDocPtr, const char *);
	int ret = -1;
	char *ac;

	switch (action) {
	case ACTION_INSTALL:
		ac = "PKGMGR_PARSER_PLUGIN_INSTALL";
		break;
	case ACTION_UPGRADE:
		ac = "PKGMGR_PARSER_PLUGIN_UPGRADE";
		break;
	case ACTION_UNINSTALL:
		ac = "PKGMGR_PARSER_PLUGIN_UNINSTALL";
		break;
	default:
		goto END;
	}

	lib_path = __get_parser_plugin(tag);
	if (!lib_path) {
		goto END;
	}

	if ((lib_handle = dlopen(lib_path, RTLD_LAZY)) == NULL) {
		_LOGE("dlopen is failed lib_path[%s]\n", lib_path);
		goto END;
	}

	if ((plugin_install =
	     dlsym(lib_handle, ac)) == NULL || dlerror() != NULL) {
		_LOGE("can not find symbol \n");
		goto END;
	}

	ret = plugin_install(docPtr, pkgname);

 END:
	if (lib_path)
		free(lib_path);
	if (lib_handle)
		dlclose(lib_handle);
	return ret;
}

static char *__pkgname_to_manifest(const char *pkgname)
{
	char *manifest;
	int size;

	if (pkgname == NULL) {
		DBGE("pkgname is NULL");
		return NULL;
	}

	size = strlen(MANIFEST_RW_DIRECTORY) + strlen(pkgname) + 10;
	manifest = malloc(size);
	if (manifest == NULL) {
		DBGE("No memory");
		return NULL;
	}

	snprintf(manifest, size, MANIFEST_RW_DIRECTORY "/%s.xml", pkgname);

	if (access(manifest, F_OK)) {
		snprintf(manifest, size, MANIFEST_RO_DIRECTORY "/%s.xml", pkgname);
	}

	return manifest;
}

static int __run_parser_prestep(xmlTextReaderPtr reader, ACTION_TYPE action, const char *pkgname)
{
	int nLoop = 0;
	int pid = 0;
	char *parser_cmd = NULL;
	int ret = -1;
	const xmlChar *name;
	char *lib_path = NULL;
	void *lib_handle = NULL;
	int (*plugin_install) (xmlDocPtr);

	DBG("__run_parser_prestep");

	if (xmlTextReaderDepth(reader) != 1) {
		DBGE("Node depth is not 1");
		goto END;
	}

	if (!xmlTextReaderHasAttributes(reader)) {
		DBGE("No attributes");
		goto END;
	}

	if (xmlTextReaderNodeType(reader) != 1) {
		DBGE("Node type is not 1");
		goto END;
	}

	const xmlChar *value;
	name = xmlTextReaderConstName(reader);
	if (name == NULL) {
		DBGE("TEST TEST TES\n");
		name = BAD_CAST "--";
	}

	value = xmlTextReaderConstValue(reader);
	DBG("%d %d %s %d %d",
	    xmlTextReaderDepth(reader),
	    xmlTextReaderNodeType(reader),
	    name,
	    xmlTextReaderIsEmptyElement(reader), xmlTextReaderHasValue(reader));

	if (value == NULL) {
		DBG("ConstValue NULL");
	} else {
		if (xmlStrlen(value) > 40) {
			DBG(" %.40s...", value);
		} else {
			DBG(" %s", value);
		}
	}

	name = xmlTextReaderConstName(reader);
	if (name == NULL) {
		DBGE("TEST TEST TES\n");
		name = BAD_CAST "--";
	}

	xmlDocPtr docPtr = xmlTextReaderCurrentDoc(reader);
	DBG("docPtr->URL %s\n", (char *)docPtr->URL);
	xmlDocPtr copyDocPtr = xmlCopyDoc(docPtr, 1);
	if (copyDocPtr == NULL)
		return -1;
	xmlNode *rootElement = xmlDocGetRootElement(copyDocPtr);
	if (rootElement == NULL)
		return -1;
	xmlNode *cur_node = xmlFirstElementChild(rootElement);
	if (cur_node == NULL)
		return -1;
	xmlNode *next_node = NULL;
	next_node = xmlNextElementSibling(cur_node);
	if (next_node) {
		cur_node->next = NULL;
		next_node->prev = NULL;
		xmlFreeNodeList(next_node);
		xmlSetTreeDoc(cur_node, copyDocPtr);
	} else
		xmlSetTreeDoc(cur_node, copyDocPtr);

#ifdef __DEBUG__

//#else
	DBG("node type: %d, name: %s children->name: %s last->name: %s\n"
	    "parent->name: %s next->name: %s prev->name: %s\n",
	    cur_node->type, cur_node->name,
	    cur_node->children ? cur_node->children->name : "NULL",
	    cur_node->last ? cur_node->last->name : "NULL",
	    cur_node->parent ? cur_node->parent->name : "NULL",
	    cur_node->next ? cur_node->next->name : "NULL",
	    cur_node->prev ? cur_node->prev->name : "NULL");

	FILE *fp = fopen("/opt/share/test.xml", "a");
	xmlDocDump(fp, copyDocPtr);
	fprintf(fp, "\n");
	fclose(fp);
#endif

	ret = __ps_run_parser(copyDocPtr, name, action, pkgname);

 END:

	return ret;
}

static void
__processNode(xmlTextReaderPtr reader, ACTION_TYPE action, char *const tagv[], const char *pkgname)
{
	char *tag = NULL;
	int i = 0;

	switch (xmlTextReaderNodeType(reader)) {
	case XML_READER_TYPE_END_ELEMENT:
		{
			//            DBG("XML_READER_TYPE_END_ELEMENT");
			break;
		}

	case XML_READER_TYPE_ELEMENT:
		{
			// Elements without closing tag don't receive
			// XML_READER_TYPE_END_ELEMENT event.

			const xmlChar *elementName =
			    xmlTextReaderLocalName(reader);
			if (elementName) {
//				DBG("elementName %s\n", (char *)elementName);
			}

			const xmlChar *nameSpace =
			    xmlTextReaderConstNamespaceUri(reader);
			if (nameSpace) {
//				DBG("nameSpace %s\n", (char *)nameSpace);
			}
/*
			DBG("XML_READER_TYPE_ELEMENT %s, %s\n",
			    elementName ? elementName : "NULL",
			    nameSpace ? nameSpace : "NULL");
*/
			if (tagv == NULL) {
				DBG("__run_parser_prestep pkgname[%s]\n", pkgname);
				__run_parser_prestep(reader, action, pkgname);
			}
			else {
				i = 0;
				for (tag = tagv[0]; tag; tag = tagv[++i])
					if (strcmp(tag, elementName) == 0) {
						DBG("__run_parser_prestep tag[%s] pkgname[%s]\n", tag, pkgname);
						__run_parser_prestep(reader,
								     action, pkgname);
						break;
					}
			}

			break;
		}
	case XML_READER_TYPE_TEXT:
	case XML_READER_TYPE_CDATA:
		{
			const xmlChar *value = xmlTextReaderConstValue(reader);
			if (value) {
//				DBG("value %s\n", value);
			}

			const xmlChar *lang = xmlTextReaderConstXmlLang(reader);
			if (lang) {
//				DBG("lang\n", lang);
			}

/*			DBG("XML_READER_TYPE_TEXT %s, %s\n",
			    value ? value : "NULL", lang ? lang : "NULL");
*/
			break;
		}
	default:
//		DBG("Ignoring Node of Type: %d", xmlTextReaderNodeType(reader));
		break;
	}
}

static void
__streamFile(const char *filename, ACTION_TYPE action, char *const tagv[], const char *pkgname)
{
	xmlTextReaderPtr reader;
	int ret;

	reader = xmlReaderForFile(filename, NULL, 0);
	if (reader != NULL) {
		ret = xmlTextReaderRead(reader);
		while (ret == 1) {
			__processNode(reader, action, tagv, pkgname);
			ret = xmlTextReaderRead(reader);
		}
		xmlFreeTextReader(reader);

		if (ret != 0) {
			DBGE("%s : failed to parse", filename);
		}
	} else {
		DBGE("Unable to open %s", filename);
	}
}

static int __next_child_element(xmlTextReaderPtr reader, int depth)
{
	int ret = xmlTextReaderRead(reader);
	int cur = xmlTextReaderDepth(reader);
	while (ret == 1) {

		switch (xmlTextReaderNodeType(reader)) {
		case XML_READER_TYPE_ELEMENT:
			if (cur == depth + 1)
				return 1;
			break;
		case XML_READER_TYPE_TEXT:
			/*text is handled by each function separately*/
			if (cur == depth + 1)
				return 0;
			break;
		case XML_READER_TYPE_END_ELEMENT:
			if (cur == depth)
				return 0;
			break;
		default:
			if (cur <= depth)
				return 0;
			break;
		}
		ret = xmlTextReaderRead(reader);
		cur = xmlTextReaderDepth(reader);
	}
	return ret;
}

static void __ps_free_timeout(timeout_x *timeout)
{
	if (timeout == NULL)
		return;
	if (timeout->text) {
		free((void *)timeout->text);
		timeout->text = NULL;
	}
	free((void*)timeout);
	timeout = NULL;
}

static void __ps_free_network(network_x *network)
{
	if (network == NULL)
		return;
	if (network->text) {
		free((void *)network->text);
		network->text = NULL;
	}
	free((void*)network);
	network = NULL;
}

static void __ps_free_period(period_x *period)
{
	if (period == NULL)
		return;
	if (period->text) {
		free((void *)period->text);
		period->text = NULL;
	}
	free((void*)period);
	period = NULL;
}

static void __ps_free_autolaunch(autolaunch_x *autolaunch)
{
	if (autolaunch == NULL)
		return;
	if (autolaunch->text) {
		free((void *)autolaunch->text);
		autolaunch->text = NULL;
	}
	free((void*)autolaunch);
	autolaunch = NULL;
}

static void __ps_free_category(category_x *category)
{
	if (category == NULL)
		return;
	if (category->name) {
		free((void *)category->name);
		category->name = NULL;
	}
	free((void*)category);
	category = NULL;
}

static void __ps_free_security(security_x *security)
{
	if (security == NULL)
		return;
	if (security->isolate) {
		free((void *)security->isolate);
		security->isolate = NULL;
	}
	free((void*)security);
	security = NULL;
}

static void __ps_free_libexec(libexec_x *libexec)
{
	if (libexec == NULL)
		return;
	if (libexec->text) {
		free((void *)libexec->text);
		libexec->text = NULL;
	}
	free((void*)libexec);
	libexec = NULL;
}

static void __ps_free_file(file_x *file)
{
	if (file == NULL)
		return;
	if (file->text) {
		free((void *)file->text);
		file->text = NULL;
	}
	free((void*)file);
	file = NULL;
}

static void __ps_free_size(size_x *size)
{
	if (size == NULL)
		return;
	if (size->text) {
		free((void *)size->text);
		size->text = NULL;
	}
	free((void*)size);
	size = NULL;
}

static void __ps_free_grp(grp_x *grp)
{
	if (grp == NULL)
		return;
	if (grp->text) {
		free((void *)grp->text);
		grp->text = NULL;
	}
	free((void*)grp);
	grp = NULL;
}

static void __ps_free_icon(icon_x *icon)
{
	if (icon == NULL)
		return;
	if (icon->text) {
		free((void *)icon->text);
		icon->text = NULL;
	}
	if (icon->lang) {
		free((void *)icon->lang);
		icon->lang = NULL;
	}
	if (icon->name) {
		free((void *)icon->name);
		icon->name= NULL;
	}
	if (icon->section) {
		free((void *)icon->section);
		icon->section = NULL;
	}
	if (icon->size) {
		free((void *)icon->size);
		icon->size = NULL;
	}
	free((void*)icon);
	icon = NULL;
}

static void __ps_free_operation(operation_x *operation)
{
	if (operation == NULL)
		return;
	if (operation->text) {
		free((void *)operation->text);
		operation->text = NULL;
	}
	free((void*)operation);
	operation = NULL;
}

static void __ps_free_uri(uri_x *uri)
{
	if (uri == NULL)
		return;
	if (uri->text) {
		free((void *)uri->text);
		uri->text = NULL;
	}
	free((void*)uri);
	uri = NULL;
}

static void __ps_free_mime(mime_x *mime)
{
	if (mime == NULL)
		return;
	if (mime->text) {
		free((void *)mime->text);
		mime->text = NULL;
	}
	free((void*)mime);
	mime = NULL;
}

static void __ps_free_condition(condition_x *condition)
{
	if (condition == NULL)
		return;
	if (condition->text) {
		free((void *)condition->text);
		condition->text = NULL;
	}
	if (condition->name) {
		free((void *)condition->name);
		condition->name = NULL;
	}
	free((void*)condition);
	condition = NULL;
}

static void __ps_free_notification(notification_x *notification)
{
	if (notification == NULL)
		return;
	if (notification->text) {
		free((void *)notification->text);
		notification->text = NULL;
	}
	if (notification->name) {
		free((void *)notification->name);
		notification->name = NULL;
	}
	free((void*)notification);
	notification = NULL;
}

static void __ps_free_compatibility(compatibility_x *compatibility)
{
	if (compatibility == NULL)
		return;
	if (compatibility->text) {
		free((void *)compatibility->text);
		compatibility->text = NULL;
	}
	if (compatibility->name) {
		free((void *)compatibility->name);
		compatibility->name = NULL;
	}
	free((void*)compatibility);
	compatibility = NULL;
}

static void __ps_free_resolution(resolution_x *resolution)
{
	if (resolution == NULL)
		return;
	if (resolution->mimetype) {
		free((void *)resolution->mimetype);
		resolution->mimetype = NULL;
	}
	if (resolution->urischeme) {
		free((void *)resolution->urischeme);
		resolution->urischeme = NULL;
	}
	free((void*)resolution);
	resolution = NULL;
}

static void __ps_free_capability(capability_x *capability)
{
	if (capability == NULL)
		return;
	if (capability->operationid) {
		free((void *)capability->operationid);
		capability->operationid = NULL;
	}
	/*Free Resolution*/
	if (capability->resolution) {
		resolution_x *resolution = capability->resolution;
		resolution_x *tmp = NULL;
		while(resolution != NULL)
		{
			tmp = resolution->next;
			__ps_free_resolution(resolution);
			resolution = tmp;
		}
	}
	free((void*)capability);
	capability = NULL;
}

static void __ps_free_allowed(allowed_x *allowed)
{
	if (allowed == NULL)
		return;
	if (allowed->name) {
		free((void *)allowed->name);
		allowed->name = NULL;
	}
	if (allowed->text) {
		free((void *)allowed->text);
		allowed->text = NULL;
	}
	free((void*)allowed);
	allowed = NULL;
}

static void __ps_free_request(request_x *request)
{
	if (request == NULL)
		return;
	if (request->text) {
		free((void *)request->text);
		request->text = NULL;
	}
	free((void*)request);
	request = NULL;
}

static void __ps_free_cluster(cluster_x *cluster)
{
	if (cluster == NULL)
		return;
	if (cluster->name) {
		free((void *)cluster->name);
		cluster->name = NULL;
	}
	/*Free Category*/
	if (cluster->category) {
		category_x *category = cluster->category;
		category_x *tmp = NULL;
		while(category != NULL)
		{
			tmp = category->next;
			__ps_free_category(category);
			category = tmp;
		}
	}
	free((void*)cluster);
	cluster = NULL;
}

static void __ps_free_appcontrol(appcontrol_x *appcontrol)
{
	if (appcontrol == NULL)
		return;
	if (appcontrol->providerid) {
		free((void *)appcontrol->providerid);
		appcontrol->providerid = NULL;
	}
	if (appcontrol->category) {
		free((void *)appcontrol->category);
		appcontrol->category = NULL;
	}
	/*Free Capability*/
	if (appcontrol->capability) {
		capability_x *capability = appcontrol->capability;
		capability_x *tmp = NULL;
		while(capability != NULL)
		{
			tmp = capability->next;
			__ps_free_capability(capability);
			capability = tmp;
		}
	}
	free((void*)appcontrol);
	appcontrol = NULL;
}

static void __ps_free_datacontrol(datacontrol_x *datacontrol)
{
	if (datacontrol == NULL)
		return;
	if (datacontrol->providerid) {
		free((void *)datacontrol->providerid);
		datacontrol->providerid = NULL;
	}
	/*Free Capability*/
	if (datacontrol->capability) {
		capability_x *capability = datacontrol->capability;
		capability_x *tmp = NULL;
		while(capability != NULL)
		{
			tmp = capability->next;
			__ps_free_capability(capability);
			capability = tmp;
		}
	}
	free((void*)datacontrol);
	datacontrol = NULL;
}

static void __ps_free_launchconditions(launchconditions_x *launchconditions)
{
	if (launchconditions == NULL)
		return;
	if (launchconditions->text) {
		free((void *)launchconditions->text);
		launchconditions->text = NULL;
	}
	/*Free Condition*/
	if (launchconditions->condition) {
		condition_x *condition = launchconditions->condition;
		condition_x *tmp = NULL;
		while(condition != NULL)
		{
			tmp = condition->next;
			__ps_free_condition(condition);
			condition = tmp;
		}
	}
	free((void*)launchconditions);
	launchconditions = NULL;
}

static void __ps_free_appsvc(appsvc_x *appsvc)
{
	if (appsvc == NULL)
		return;
	if (appsvc->text) {
		free((void *)appsvc->text);
		appsvc->text = NULL;
	}
	/*Free Operation*/
	if (appsvc->operation) {
		operation_x *operation = appsvc->operation;
		operation_x *tmp = NULL;
		while(operation != NULL)
		{
			tmp = operation->next;
			__ps_free_operation(operation);
			operation = tmp;
		}
	}
	/*Free Uri*/
	if (appsvc->uri) {
		uri_x *uri = appsvc->uri;
		uri_x *tmp = NULL;
		while(uri != NULL)
		{
			tmp = uri->next;
			__ps_free_uri(uri);
			uri = tmp;
		}
	}
	/*Free Mime*/
	if (appsvc->mime) {
		mime_x *mime = appsvc->mime;
		mime_x *tmp = NULL;
		while(mime != NULL)
		{
			tmp = mime->next;
			__ps_free_mime(mime);
			mime = tmp;
		}
	}
	free((void*)appsvc);
	appsvc = NULL;
}

static void __ps_free_deviceprofile(deviceprofile_x *deviceprofile)
{
	return;
}



static void __ps_free_define(define_x *define)
{
	if (define == NULL)
		return;
	if (define->path) {
		free((void *)define->path);
		define->path = NULL;
	}
	/*Free Request*/
	if (define->request) {
		request_x *request = define->request;
		request_x *tmp = NULL;
		while(request != NULL)
		{
			tmp = request->next;
			__ps_free_request(request);
			request = tmp;
		}
	}
	/*Free Allowed*/
	if (define->allowed) {
		allowed_x *allowed = define->allowed;
		allowed_x *tmp = NULL;
		while(allowed != NULL)
		{
			tmp = allowed->next;
			__ps_free_allowed(allowed);
			allowed = tmp;
		}
	}
	free((void*)define);
	define = NULL;
}

static void __ps_free_registry(registry_x *registry)
{
	if (registry == NULL)
		return;
	if (registry->name) {
		free((void *)registry->name);
		registry->name = NULL;
	}
	if (registry->text) {
		free((void *)registry->text);
		registry->text = NULL;
	}
	free((void*)registry);
	registry = NULL;
}

static void __ps_free_database(database_x *database)
{
	if (database == NULL)
		return;
	if (database->name) {
		free((void *)database->name);
		database->name = NULL;
	}
	if (database->text) {
		free((void *)database->text);
		database->text = NULL;
	}
	free((void*)database);
	database = NULL;
}

static void __ps_free_datashare(datashare_x *datashare)
{
	if (datashare == NULL)
		return;
	/*Free Define*/
	if (datashare->define) {
		define_x *define =  datashare->define;
		define_x *tmp = NULL;
		while(define != NULL)
		{
			tmp = define->next;
			__ps_free_define(define);
			define = tmp;
		}
	}
	/*Free Request*/
	if (datashare->request) {
		request_x *request = datashare->request;
		request_x *tmp = NULL;
		while(request != NULL)
		{
			tmp = request->next;
			__ps_free_request(request);
			request = tmp;
		}
	}
	free((void*)datashare);
	datashare = NULL;
}

static void __ps_free_layout(layout_x *layout)
{
	if (layout == NULL)
		return;
	if (layout->name) {
		free((void *)layout->name);
		layout->name = NULL;
	}
	if (layout->text) {
		free((void *)layout->text);
		layout->text = NULL;
	}
	free((void*)layout);
	layout = NULL;
}

static void __ps_free_control(control_x *control)
{
	if (control == NULL)
		return;
	/*Free Timeout*/
	if (control->timeout) {
		timeout_x *timeout =  control->timeout;
		timeout_x *tmp = NULL;
		while(timeout != NULL)
		{
			tmp = timeout->next;
			__ps_free_timeout(timeout);
			timeout = tmp;
		}
	}
	/*Free Period*/
	if (control->period) {
		period_x *period =  control->period;
		period_x *tmp = NULL;
		while(period != NULL)
		{
			tmp = period->next;
			__ps_free_period(period);
			period = tmp;
		}
	}
	/*Free Network*/
	if (control->network) {
		network_x *network =  control->network;
		network_x *tmp = NULL;
		while(network != NULL)
		{
			tmp = network->next;
			__ps_free_network(network);
			network = tmp;
		}
	}
	/*Free Autolaunch*/
	if (control->autolaunch) {
		autolaunch_x *autolaunch =  control->autolaunch;
		autolaunch_x *tmp = NULL;
		while(autolaunch != NULL)
		{
			tmp = autolaunch->next;
			__ps_free_autolaunch(autolaunch);
			autolaunch = tmp;
		}
	}
	free((void*)control);
	control = NULL;
}

static void __ps_free_pd(pd_x *pd)
{
	if (pd == NULL)
		return;
	if (pd->type) {
		free((void *)pd->type);
		pd->type = NULL;
	}
	if (pd->language) {
		free((void *)pd->language);
		pd->language = NULL;
	}
	/*Free File*/
	if (pd->file) {
		file_x *file =  pd->file;
		file_x *tmp = NULL;
		while(file != NULL)
		{
			tmp = file->next;
			__ps_free_file(file);
			file = tmp;
		}
	}
	/*Free Group*/
	if (pd->grp) {
		grp_x *grp =  pd->grp;
		grp_x *tmp = NULL;
		while(grp != NULL)
		{
			tmp = grp->next;
			__ps_free_grp(grp);
			grp = tmp;
		}
	}
	/*Free Size*/
	if (pd->size) {
		size_x *size =  pd->size;
		size_x *tmp = NULL;
		while(size != NULL)
		{
			tmp = size->next;
			__ps_free_size(size);
			size = tmp;
		}
	}
	free((void*)pd);
	pd = NULL;
}

static void __ps_free_lbox(lbox_x *lbox)
{
	if (lbox == NULL)
		return;
	if (lbox->type) {
		free((void*)lbox->type);
		lbox->type = NULL;
	}
	/*Free Size*/
	if (lbox->size) {
		size_x *size =  lbox->size;
		size_x *tmp = NULL;
		while(size != NULL)
		{
			tmp = size->next;
			__ps_free_size(size);
			size = tmp;
		}
	}
	free((void*)lbox);
	lbox = NULL;
}

static void __ps_free_content(content_x *content)
{
	if (content == NULL)
		return;
	/*Free Livebox*/
	if (content->lbox) {
		lbox_x *lbox =  content->lbox;
		lbox_x *tmp = NULL;
		while(lbox != NULL)
		{
			tmp = lbox->next;
			__ps_free_lbox(lbox);
			lbox = tmp;
		}
	}
	/*Free Pd*/
	if (content->pd) {
		pd_x *pd =  content->pd;
		pd_x *tmp = NULL;
		while(pd != NULL)
		{
			tmp = pd->next;
			__ps_free_pd(pd);
			pd = tmp;
		}
	}
	free((void*)content);
	content = NULL;
}

static void __ps_free_group(group_x *group)
{
	if (group == NULL)
		return;
	/*Free Cluster*/
	if (group->cluster) {
		cluster_x *cluster =  group->cluster;
		cluster_x *tmp = NULL;
		while(cluster != NULL)
		{
			tmp = cluster->next;
			__ps_free_cluster(cluster);
			cluster = tmp;
		}
	}
	free((void*)group);
	group = NULL;
}

static void __ps_free_livebox(livebox_x *livebox)
{
	if (livebox == NULL)
		return;
	if (livebox->abi) {
		free((void *)livebox->abi);
		livebox->abi= NULL;
	}
	if (livebox->application) {
		free((void *)livebox->application);
		livebox->application = NULL;
	}
	if (livebox->type) {
		free((void *)livebox->type);
		livebox->type = NULL;
	}
	/*Free Icon*/
	if (livebox->icon) {
		icon_x *icon = livebox->icon;
		icon_x *tmp = NULL;
		while(icon != NULL)
		{
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free Label*/
	if (livebox->label) {
		label_x *label = livebox->label;
		label_x *tmp = NULL;
		while(label != NULL)
		{
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Libexec*/
	if (livebox->libexec) {
		libexec_x *libexec = livebox->libexec;
		libexec_x *tmp = NULL;
		while(libexec != NULL)
		{
			tmp = libexec->next;
			__ps_free_libexec(libexec);
			libexec = tmp;
		}
	}
	/*Free Control*/
	if (livebox->control) {
		control_x *control = livebox->control;
		control_x *tmp = NULL;
		while(control != NULL)
		{
			tmp = control->next;
			__ps_free_control(control);
			control = tmp;
		}
	}
	/*Free Content*/
	if (livebox->content) {
		content_x *content = livebox->content;
		content_x *tmp = NULL;
		while(content != NULL)
		{
			tmp = content->next;
			__ps_free_content(content);
			content = tmp;
		}
	}
	/*Free Group*/
	if (livebox->group) {
		group_x *group = livebox->group;
		group_x *tmp = NULL;
		while(group != NULL)
		{
			tmp = group->next;
			__ps_free_group(group);
			group = tmp;
		}
	}
	/*Free Security*/
	if (livebox->security) {
		security_x *security = livebox->security;
		security_x *tmp = NULL;
		while(security != NULL)
		{
			tmp = security->next;
			__ps_free_security(security);
			security = tmp;
		}
	}
	/*Free Size*/
	if (livebox->size) {
		size_x *size = livebox->size;
		size_x *tmp = NULL;
		while(size != NULL)
		{
			tmp = size->next;
			__ps_free_size(size);
			size = tmp;
		}
	}
	free((void*)livebox);
	livebox = NULL;
}

static void __ps_free_label(label_x *label)
{
	if (label == NULL)
		return;
	if (label->name) {
		free((void *)label->name);
		label->name = NULL;
	}
	if (label->text) {
		free((void *)label->text);
		label->text = NULL;
	}
	if (label->lang) {
		free((void *)label->lang);
		label->lang= NULL;
	}
	free((void*)label);
	label = NULL;
}

static void __ps_free_author(author_x *author)
{
	if (author == NULL)
		return;
	if (author->email) {
		free((void *)author->email);
		author->email = NULL;
	}
	if (author->text) {
		free((void *)author->text);
		author->text = NULL;
	}
	if (author->href) {
		free((void *)author->href);
		author->href = NULL;
	}
	if (author->lang) {
		free((void *)author->lang);
		author->lang = NULL;
	}
	free((void*)author);
	author = NULL;
}

static void __ps_free_description(description_x *description)
{
	if (description == NULL)
		return;
	if (description->name) {
		free((void *)description->name);
		description->name = NULL;
	}
	if (description->text) {
		free((void *)description->text);
		description->text = NULL;
	}
	if (description->lang) {
		free((void *)description->lang);
		description->lang = NULL;
	}
	free((void*)description);
	description = NULL;
}

static void __ps_free_license(license_x *license)
{
	if (license == NULL)
		return;
	if (license->text) {
		free((void *)license->text);
		license->text = NULL;
	}
	if (license->lang) {
		free((void *)license->lang);
		license->lang = NULL;
	}
	free((void*)license);
	license = NULL;
}

static void __ps_free_uiapplication(uiapplication_x *uiapplication)
{
	if (uiapplication == NULL)
		return;
	if (uiapplication->exec) {
		free((void *)uiapplication->exec);
		uiapplication->exec = NULL;
	}
	if (uiapplication->appid) {
		free((void *)uiapplication->appid);
		uiapplication->appid = NULL;
	}
	if (uiapplication->nodisplay) {
		free((void *)uiapplication->nodisplay);
		uiapplication->nodisplay = NULL;
	}
	if (uiapplication->multiple) {
		free((void *)uiapplication->multiple);
		uiapplication->multiple = NULL;
	}
	if (uiapplication->type) {
		free((void *)uiapplication->type);
		uiapplication->type = NULL;
	}
	if (uiapplication->categories) {
		free((void *)uiapplication->categories);
		uiapplication->categories = NULL;
	}
	if (uiapplication->extraid) {
		free((void *)uiapplication->extraid);
		uiapplication->extraid = NULL;
	}
	if (uiapplication->taskmanage) {
		free((void *)uiapplication->taskmanage);
		uiapplication->taskmanage = NULL;
	}
	/*Free Label*/
	if (uiapplication->label) {
		label_x *label = uiapplication->label;
		label_x *tmp = NULL;
		while(label != NULL)
		{
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Icon*/
	if (uiapplication->icon) {
		icon_x *icon = uiapplication->icon;
		icon_x *tmp = NULL;
		while(icon != NULL)
		{
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free AppControl*/
	if (uiapplication->appcontrol) {
		appcontrol_x *appcontrol = uiapplication->appcontrol;
		appcontrol_x *tmp = NULL;
		while(appcontrol != NULL)
		{
			tmp = appcontrol->next;
			__ps_free_appcontrol(appcontrol);
			appcontrol = tmp;
		}
	}
	/*Free LaunchConditions*/
	if (uiapplication->launchconditions) {
		launchconditions_x *launchconditions = uiapplication->launchconditions;
		launchconditions_x *tmp = NULL;
		while(launchconditions != NULL)
		{
			tmp = launchconditions->next;
			__ps_free_launchconditions(launchconditions);
			launchconditions = tmp;
		}
	}
	/*Free Notification*/
	if (uiapplication->notification) {
		notification_x *notification = uiapplication->notification;
		notification_x *tmp = NULL;
		while(notification != NULL)
		{
			tmp = notification->next;
			__ps_free_notification(notification);
			notification = tmp;
		}
	}
	/*Free DataShare*/
	if (uiapplication->datashare) {
		datashare_x *datashare = uiapplication->datashare;
		datashare_x *tmp = NULL;
		while(datashare != NULL)
		{
			tmp = datashare->next;
			__ps_free_datashare(datashare);
			datashare = tmp;
		}
	}
	/*Free AppSvc*/
	if (uiapplication->appsvc) {
		appsvc_x *appsvc = uiapplication->appsvc;
		appsvc_x *tmp = NULL;
		while(appsvc != NULL)
		{
			tmp = appsvc->next;
			__ps_free_appsvc(appsvc);
			appsvc = tmp;
		}
	}
	free((void*)uiapplication);
	uiapplication = NULL;
}

static void __ps_free_serviceapplication(serviceapplication_x *serviceapplication)
{
	if (serviceapplication == NULL)
		return;
	if (serviceapplication->exec) {
		free((void *)serviceapplication->exec);
		serviceapplication->exec = NULL;
	}
	if (serviceapplication->appid) {
		free((void *)serviceapplication->appid);
		serviceapplication->appid = NULL;
	}
	if (serviceapplication->onboot) {
		free((void *)serviceapplication->onboot);
		serviceapplication->onboot = NULL;
	}
	if (serviceapplication->autorestart) {
		free((void *)serviceapplication->autorestart);
		serviceapplication->autorestart = NULL;
	}
	if (serviceapplication->type) {
		free((void *)serviceapplication->type);
		serviceapplication->type = NULL;
	}
	/*Free Label*/
	if (serviceapplication->label) {
		label_x *label = serviceapplication->label;
		label_x *tmp = NULL;
		while(label != NULL)
		{
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Icon*/
	if (serviceapplication->icon) {
		icon_x *icon = serviceapplication->icon;
		icon_x *tmp = NULL;
		while(icon != NULL)
		{
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free AppControl*/
	if (serviceapplication->appcontrol) {
		appcontrol_x *appcontrol = serviceapplication->appcontrol;
		appcontrol_x *tmp = NULL;
		while(appcontrol != NULL)
		{
			tmp = appcontrol->next;
			__ps_free_appcontrol(appcontrol);
			appcontrol = tmp;
		}
	}
	/*Free DataControl*/
	if (serviceapplication->datacontrol) {
		datacontrol_x *datacontrol = serviceapplication->datacontrol;
		datacontrol_x *tmp = NULL;
		while(datacontrol != NULL)
		{
			tmp = datacontrol->next;
			__ps_free_datacontrol(datacontrol);
			datacontrol = tmp;
		}
	}
	/*Free LaunchConditions*/
	if (serviceapplication->launchconditions) {
		launchconditions_x *launchconditions = serviceapplication->launchconditions;
		launchconditions_x *tmp = NULL;
		while(launchconditions != NULL)
		{
			tmp = launchconditions->next;
			__ps_free_launchconditions(launchconditions);
			launchconditions = tmp;
		}
	}
	/*Free Notification*/
	if (serviceapplication->notification) {
		notification_x *notification = serviceapplication->notification;
		notification_x *tmp = NULL;
		while(notification != NULL)
		{
			tmp = notification->next;
			__ps_free_notification(notification);
			notification = tmp;
		}
	}
	/*Free DataShare*/
	if (serviceapplication->datashare) {
		datashare_x *datashare = serviceapplication->datashare;
		datashare_x *tmp = NULL;
		while(datashare != NULL)
		{
			tmp = datashare->next;
			__ps_free_datashare(datashare);
			datashare = tmp;
		}
	}
	/*Free AppSvc*/
	if (serviceapplication->appsvc) {
		appsvc_x *appsvc = serviceapplication->appsvc;
		appsvc_x *tmp = NULL;
		while(appsvc != NULL)
		{
			tmp = appsvc->next;
			__ps_free_appsvc(appsvc);
			appsvc = tmp;
		}
	}
	free((void*)serviceapplication);
	serviceapplication = NULL;
}

static void __ps_free_font(font_x *font)
{
	if (font == NULL)
		return;
	if (font->name) {
		free((void *)font->name);
		font->name = NULL;
	}
	if (font->text) {
		free((void *)font->text);
		font->text = NULL;
	}
	free((void*)font);
	font = NULL;
}

static void __ps_free_theme(theme_x *theme)
{
	if (theme == NULL)
		return;
	if (theme->name) {
		free((void *)theme->name);
		theme->name = NULL;
	}
	if (theme->text) {
		free((void *)theme->text);
		theme->text = NULL;
	}
	free((void*)theme);
	theme = NULL;
}

static void __ps_free_daemon(daemon_x *daemon)
{
	if (daemon == NULL)
		return;
	if (daemon->name) {
		free((void *)daemon->name);
		daemon->name = NULL;
	}
	if (daemon->text) {
		free((void *)daemon->text);
		daemon->text = NULL;
	}
	free((void*)daemon);
	daemon = NULL;
}

static void __ps_free_ime(ime_x *ime)
{
	if (ime == NULL)
		return;
	if (ime->name) {
		free((void *)ime->name);
		ime->name = NULL;
	}
	if (ime->text) {
		free((void *)ime->text);
		ime->text = NULL;
	}
	free((void*)ime);
	ime = NULL;
}


static int __ps_process_allowed(xmlTextReaderPtr reader, allowed_x *allowed)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		allowed->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_timeout(xmlTextReaderPtr reader, timeout_x *timeout)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		timeout->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_network(xmlTextReaderPtr reader, network_x *network)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		network->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_period(xmlTextReaderPtr reader, period_x *period)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		period->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_autolaunch(xmlTextReaderPtr reader, autolaunch_x *autolaunch)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		autolaunch->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_file(xmlTextReaderPtr reader, file_x *file)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		file->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_size(xmlTextReaderPtr reader, size_x *size)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		size->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_grp(xmlTextReaderPtr reader, grp_x *grp)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		grp->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_operation(xmlTextReaderPtr reader, operation_x *operation)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		operation->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		operation->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_uri(xmlTextReaderPtr reader, uri_x *uri)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		uri->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		uri->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_mime(xmlTextReaderPtr reader, mime_x *mime)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		mime->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		mime->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_condition(xmlTextReaderPtr reader, condition_x *condition)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		condition->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		condition->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_notification(xmlTextReaderPtr reader, notification_x *notification)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		notification->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		notification->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_category(xmlTextReaderPtr reader, category_x *category)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		category->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	return 0;
}

static int __ps_process_security(xmlTextReaderPtr reader, security_x *security)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("isolate")))
		security->isolate = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("isolate")));
	return 0;
}

static int __ps_process_libexec(xmlTextReaderPtr reader, libexec_x *libexec)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		libexec->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_compatibility(xmlTextReaderPtr reader, compatibility_x *compatibility)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		compatibility->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		compatibility->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_resolution(xmlTextReaderPtr reader, resolution_x *resolution)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("mime-type")))
		resolution->mimetype = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("mime-type")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("uri-scheme")))
		resolution->urischeme = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("uri-scheme")));
	return 0;
}

static int __ps_process_request(xmlTextReaderPtr reader, request_x *request)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		request->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_define(xmlTextReaderPtr reader, define_x *define)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	allowed_x *tmp1 = NULL;
	request_x *tmp2 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("path")))
		define->path = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("path")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "allowed")) {
			allowed_x *allowed= malloc(sizeof(allowed_x));
			if (allowed == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(allowed, '\0', sizeof(allowed_x));
			if (allowed) {
				LISTADD(define->allowed, allowed);
				ret =
				    __ps_process_allowed(reader, allowed);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "request")) {
			request_x *request = malloc(sizeof(request_x));
			if (request == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(request, '\0', sizeof(request_x));
			if (request) {
				LISTADD(define->request, request);
				ret =
				    __ps_process_request(reader, request);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing define failed\n");
			return ret;
		}
	}
	if (define->allowed) {
		LISTHEAD(define->allowed, tmp1);
		define->allowed = tmp1;
	}
	if (define->request) {
		LISTHEAD(define->request, tmp2);
		define->request = tmp2;
	}
	return ret;
}

static int __ps_process_registry(xmlTextReaderPtr reader, registry_x *registry)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_database(xmlTextReaderPtr reader, database_x *database)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_appsvc(xmlTextReaderPtr reader, appsvc_x *appsvc)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	operation_x *tmp1 = NULL;
	uri_x *tmp2 = NULL;
	mime_x *tmp3 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "operation")) {
			operation_x *operation = malloc(sizeof(operation_x));
			if (operation == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(operation, '\0', sizeof(operation_x));
			if (operation) {
				LISTADD(appsvc->operation, operation);
				ret =
				    __ps_process_operation(reader, operation);

				DBG("operation processing\n");
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "uri")) {
			uri_x *uri= malloc(sizeof(uri_x));
			if (uri == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(uri, '\0', sizeof(uri_x));
			if (uri) {
				LISTADD(appsvc->uri, uri);
				ret =
				    __ps_process_uri(reader, uri);

				DBG("uri processing\n");
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "mime")) {
			mime_x *mime = malloc(sizeof(mime_x));
			if (mime == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(mime, '\0', sizeof(mime_x));
			if (mime) {
				LISTADD(appsvc->mime, mime);
				ret =
				    __ps_process_mime(reader, mime);

				DBG("mime processing\n");
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing appsvc failed\n");
			return ret;
		}
	}
	if (appsvc->operation) {
		LISTHEAD(appsvc->operation, tmp1);
		appsvc->operation = tmp1;
	}
	if (appsvc->uri) {
		LISTHEAD(appsvc->uri, tmp2);
		appsvc->uri = tmp2;
	}
	if (appsvc->mime) {
		LISTHEAD(appsvc->mime, tmp3);
		appsvc->mime = tmp3;
	}

	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		appsvc->text = ASCII(xmlTextReaderValue(reader));

	return ret;
}

static int __ps_process_launchconditions(xmlTextReaderPtr reader, launchconditions_x *launchconditions)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	condition_x *tmp1 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (strcmp(ASCII(node), "condition") == 0) {
			condition_x *condition = malloc(sizeof(condition_x));
			if (condition == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(condition, '\0', sizeof(condition_x));
			if (condition) {
				LISTADD(launchconditions->condition, condition);
				ret =
				    __ps_process_condition(reader, condition);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing launchconditions failed\n");
			return ret;
		}
	}
	if (launchconditions->condition) {
		LISTHEAD(launchconditions->condition, tmp1);
		launchconditions->condition = tmp1;
	}

	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		launchconditions->text = ASCII(xmlTextReaderValue(reader));

	return ret;
}

static int __ps_process_datashare(xmlTextReaderPtr reader, datashare_x *datashare)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	define_x *tmp1 = NULL;
	request_x *tmp2 = NULL;
	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "define")) {
			define_x *define= malloc(sizeof(define_x));
			if (define == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(define, '\0', sizeof(define_x));
			if (define) {
				LISTADD(datashare->define, define);
				ret =
				    __ps_process_define(reader, define);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "request")) {
			request_x *request= malloc(sizeof(request_x));
			if (request == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(request, '\0', sizeof(request_x));
			if (request) {
				LISTADD(datashare->request, request);
				ret =
				    __ps_process_request(reader, request);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing data-share failed\n");
			return ret;
		}
	}
	if (datashare->define) {
		LISTHEAD(datashare->define, tmp1);
		datashare->define = tmp1;
	}
	if (datashare->request) {
		LISTHEAD(datashare->request, tmp2);
		datashare->request = tmp2;
	}
	return ret;
}

static int __ps_process_layout(xmlTextReaderPtr reader, layout_x *layout)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_cluster(xmlTextReaderPtr reader, cluster_x *cluster)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	category_x *tmp1 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		cluster->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "category")) {
			category_x *category = malloc(sizeof(category_x));
			if (category == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(category, '\0', sizeof(category_x));
			if (category) {
				LISTADD(cluster->category, category);
				ret =
				    __ps_process_category(reader, category);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing category failed\n");
			return ret;
		}
	}
	if (cluster->category) {
		LISTHEAD(cluster->category, tmp1);
		cluster->category = tmp1;
	}

	return ret;
}

static int __ps_process_icon(xmlTextReaderPtr reader, icon_x *icon)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		icon->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	if (xmlTextReaderConstXmlLang(reader)) {
		icon->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (icon->lang == NULL)
			icon->lang = strdup(DEFAULT_LOCALE);
	} else {
		icon->lang = strdup(DEFAULT_LOCALE);
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("section")))
		icon->section = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("section")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("size")))
		icon->size = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("size")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		icon->text = ASCII(xmlTextReaderValue(reader));

	return 0;
}

static int __ps_process_lbox(xmlTextReaderPtr reader, lbox_x *lbox)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	size_x *tmp1 = NULL;
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("type")))
		lbox->type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("type")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}
		if (!strcmp(ASCII(node), "size")) {
			size_x *size= malloc(sizeof(size_x));
			if (size == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(size, '\0', sizeof(size_x));
			if (size) {
				LISTADD(lbox->size, size);
				ret =
				    __ps_process_size(reader, size);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing lbox failed\n");
			return ret;
		}
	}

	if (lbox->size) {
		LISTHEAD(lbox->size, tmp1);
		lbox->size = tmp1;
	}

	return ret;
}

static int __ps_process_pd(xmlTextReaderPtr reader, pd_x *pd)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	file_x *tmp1 = NULL;
	grp_x *tmp2 = NULL;
	size_x *tmp3 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("type")))
		pd->type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("type")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("language")))
		pd->language = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("language")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}
		if (!strcmp(ASCII(node), "file")) {
			file_x *file = malloc(sizeof(file_x));
			if (file == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(file, '\0', sizeof(file_x));
			if (file) {
				LISTADD(pd->file, file);
				ret =
				    __ps_process_file(reader, file);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "group")) {
			grp_x *grp = malloc(sizeof(grp_x));
			if (grp == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(grp, '\0', sizeof(grp_x));
			if (grp) {
				LISTADD(pd->grp, grp);
				ret =
				    __ps_process_grp(reader, grp);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "size")) {
			size_x *size = malloc(sizeof(size_x));
			if (size == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(size, '\0', sizeof(size_x));
			if (size) {
				LISTADD(pd->size, size);
				ret =
				    __ps_process_size(reader, size);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing pd failed\n");
			return ret;
		}
	}

	if (pd->file) {
		LISTHEAD(pd->file, tmp1);
		pd->file = tmp1;
	}
	if (pd->grp) {
		LISTHEAD(pd->grp, tmp2);
		pd->grp = tmp2;
	}
	if (pd->size) {
		LISTHEAD(pd->size , tmp3);
		pd->size = tmp3;
	}

	return ret;
}

static int __ps_process_content(xmlTextReaderPtr reader, content_x *content)
{
	DBG("CONTENT\n");
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	lbox_x *tmp1 = NULL;
	pd_x *tmp2 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "livebox")) {
			lbox_x *lbox = malloc(sizeof(lbox_x));
			if (lbox == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(lbox, '\0', sizeof(lbox_x));
			if (lbox) {
				LISTADD(content->lbox, lbox);
				ret =
				    __ps_process_lbox(reader, lbox);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "pd")) {
			pd_x *pd = malloc(sizeof(pd_x));
			if (pd == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(pd, '\0', sizeof(pd_x));
			if (pd) {
				LISTADD(content->pd, pd);
				ret =
				    __ps_process_pd(reader, pd);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing content failed\n");
			return ret;
		}
	}

	if (content->lbox) {
		LISTHEAD(content->lbox, tmp1);
		content->lbox = tmp1;
	}
	if (content->pd) {
		LISTHEAD(content->pd, tmp2);
		content->pd = tmp2;
	}

	return ret;

}

static int __ps_process_control(xmlTextReaderPtr reader, control_x *control)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	timeout_x *tmp1 = NULL;
	network_x *tmp2 = NULL;
	period_x *tmp3 = NULL;
	autolaunch_x *tmp4 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "timeout")) {
			timeout_x *timeout = malloc(sizeof(timeout_x));
			if (timeout == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(timeout, '\0', sizeof(timeout_x));
			if (timeout) {
				LISTADD(control->timeout, timeout);
				ret =
				    __ps_process_timeout(reader, timeout);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "network")) {
			network_x *network = malloc(sizeof(network_x));
			if (network == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(network, '\0', sizeof(network_x));
			if (network) {
				LISTADD(control->network, network);
				ret =
				    __ps_process_network(reader, network);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "period")) {
			period_x *period = malloc(sizeof(period_x));
			if (period == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(period, '\0', sizeof(period_x));
			if (period) {
				LISTADD(control->period, period);
				ret =
				    __ps_process_period(reader, period);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "autolaunch")) {
			autolaunch_x *autolaunch = malloc(sizeof(autolaunch_x));
			if (autolaunch == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(autolaunch, '\0', sizeof(autolaunch_x));
			if (autolaunch) {
				LISTADD(control->autolaunch, autolaunch);
				ret =
				    __ps_process_autolaunch(reader, autolaunch);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing control failed\n");
			return ret;
		}
	}

	if (control->timeout) {
		LISTHEAD(control->timeout, tmp1);
		control->timeout = tmp1;
	}
	if (control->network) {
		LISTHEAD(control->network, tmp2);
		control->network = tmp2;
	}
	if (control->period) {
		LISTHEAD(control->period, tmp3);
		control->period = tmp3;
	}
	if (control->autolaunch) {
		LISTHEAD(control->autolaunch, tmp4);
		control->autolaunch = tmp4;
	}

	return ret;
}

static int __ps_process_group(xmlTextReaderPtr reader, group_x *group)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	cluster_x *tmp1 = NULL;
	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "cluster")) {
			cluster_x *cluster = malloc(sizeof(cluster_x));
			if (cluster == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(cluster, '\0', sizeof(cluster_x));
			if (cluster) {
				LISTADD(group->cluster, cluster);
				ret =
				    __ps_process_cluster(reader, cluster);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing group failed\n");
			return ret;
		}
	}

	if (group->cluster) {
		LISTHEAD(group->cluster, tmp1);
		group->cluster = tmp1;
	}

	return ret;
}

static int __ps_process_livebox(xmlTextReaderPtr reader, livebox_x *livebox)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	icon_x *tmp1 = NULL;
	label_x *tmp2 = NULL;
	libexec_x *tmp3 = NULL;
	control_x *tmp4 = NULL;
	content_x *tmp5 = NULL;
	group_x *tmp6 = NULL;
	security_x *tmp7 = NULL;
	size_x *tmp8 = NULL;
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("application")))
		livebox->application = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("application")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("abi")))
		livebox->abi = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("abi")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("type")))
		livebox->type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("type")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "label")) {
			label_x *label = malloc(sizeof(label_x));
			if (label == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(label, '\0', sizeof(label_x));
			if (label) {
				LISTADD(livebox->label, label);
				ret =
				    __ps_process_label(reader, label);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = malloc(sizeof(icon_x));
			if (icon == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(icon, '\0', sizeof(icon_x));
			if (icon) {
				LISTADD(livebox->icon, icon);
				ret =
				    __ps_process_icon(reader, icon);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "libexec")) {
			libexec_x *libexec = malloc(sizeof(libexec_x));
			if (libexec == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(libexec, '\0', sizeof(libexec_x));
			if (libexec) {
				LISTADD(livebox->libexec, libexec);
				ret =
				    __ps_process_libexec(reader, libexec);
			} else
				return -1;
		}else if (!strcmp(ASCII(node), "control")) {
			control_x *control = malloc(sizeof(control_x));
			if (control == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(control, '\0', sizeof(control_x));
			if (control) {
				LISTADD(livebox->control, control);
				ret =
				    __ps_process_control(reader, control);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "content")) {
			content_x *content= malloc(sizeof(content_x));
			if (content == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(content, '\0', sizeof(content_x));
			if (content) {
				LISTADD(livebox->content, content);
				ret =
				    __ps_process_content(reader, content);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "group")) {
			group_x *group= malloc(sizeof(group_x));
			if (group == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(group, '\0', sizeof(group_x));
			if (group) {
				LISTADD(livebox->group, group);
				ret =
				    __ps_process_group(reader, group);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "security")) {
			security_x *security= malloc(sizeof(security_x));
			if (security == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(security, '\0', sizeof(security_x));
			if (security) {
				LISTADD(livebox->security, security);
				ret =
				    __ps_process_security(reader, security);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "size")) {
			size_x *size= malloc(sizeof(size_x));
			if (size == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(size, '\0', sizeof(size_x));
			if (size) {
				LISTADD(livebox->size, size);
				ret =
				    __ps_process_size(reader, size);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing livebox failed\n");
			return ret;
		}
	}

	if (livebox->icon) {
		LISTHEAD(livebox->icon, tmp1);
		livebox->icon = tmp1;
	}
	if (livebox->label) {
		LISTHEAD(livebox->label, tmp2);
		livebox->label = tmp2;
	}
	if (livebox->libexec) {
		LISTHEAD(livebox->libexec, tmp3);
		livebox->libexec = tmp3;
	}
	if (livebox->control) {
		LISTHEAD(livebox->control, tmp4);
		livebox->control = tmp4;
	}
	if (livebox->content) {
		LISTHEAD(livebox->content, tmp5);
		livebox->content = tmp5;
	}
	if (livebox->group) {
		LISTHEAD(livebox->group, tmp6);
		livebox->group = tmp6;
	}
	if (livebox->security) {
		LISTHEAD(livebox->security, tmp7);
		livebox->security = tmp7;
	}
	if (livebox->size) {
		LISTHEAD(livebox->size, tmp8);
		livebox->size = tmp8;
	}

	return ret;
}

static int __ps_process_label(xmlTextReaderPtr reader, label_x *label)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		label->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	if (xmlTextReaderConstXmlLang(reader)) {
		label->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (label->lang == NULL)
			label->lang = strdup(DEFAULT_LOCALE);
	} else {
		label->lang = strdup(DEFAULT_LOCALE);
	}
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		label->text = ASCII(xmlTextReaderValue(reader));

/*	DBG("lable name %s\n", label->name);
	DBG("lable lang %s\n", label->lang);
	DBG("lable text %s\n", label->text);
*/
	return 0;

}

static int __ps_process_author(xmlTextReaderPtr reader, author_x *author)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("email")))
		author->email = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("email")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("href")))
		author->href = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("href")));
	if (xmlTextReaderConstXmlLang(reader)) {
		author->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (author->lang == NULL)
			author->lang = strdup(DEFAULT_LOCALE);
	} else {
		author->lang = strdup(DEFAULT_LOCALE);
	}
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		author->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_description(xmlTextReaderPtr reader, description_x *description)
{
	if (xmlTextReaderConstXmlLang(reader)) {
		description->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (description->lang == NULL)
			description->lang = strdup(DEFAULT_LOCALE);
	} else {
		description->lang = strdup(DEFAULT_LOCALE);
	}
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		description->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_license(xmlTextReaderPtr reader, license_x *license)
{
	if (xmlTextReaderConstXmlLang(reader)) {
		license->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (license->lang == NULL)
			license->lang = strdup(DEFAULT_LOCALE);
	} else {
		license->lang = strdup(DEFAULT_LOCALE);
	}
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		license->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_capability(xmlTextReaderPtr reader, capability_x *capability)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	resolution_x *tmp1 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("operation-id")))
		capability->operationid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("operation-id")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "resolution")) {
			resolution_x *resolution = malloc(sizeof(resolution_x));
			if (resolution == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(resolution, '\0', sizeof(resolution_x));
			if (resolution) {
				LISTADD(capability->resolution, resolution);
				ret =
				    __ps_process_resolution(reader, resolution);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing capability failed\n");
			return ret;
		}
	}

	if (capability->resolution) {
		LISTHEAD(capability->resolution, tmp1);
		capability->resolution = tmp1;
	}

	return ret;
}

static int __ps_process_appcontrol(xmlTextReaderPtr reader, appcontrol_x *appcontrol)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	capability_x *tmp1 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("provider-id")))
		appcontrol->providerid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("provider-id")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("category")))
		appcontrol->category = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("category")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "capability")) {
			capability_x *capability = malloc(sizeof(capability_x));
			if (capability == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(capability, '\0', sizeof(capability_x));
			if (capability) {
				LISTADD(appcontrol->capability, capability);
				ret =
				    __ps_process_capability(reader, capability);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing appcontrol failed\n");
			return ret;
		}
	}

	if (appcontrol->capability) {
		LISTHEAD(appcontrol->capability, tmp1);
		appcontrol->capability = tmp1;
	}

	return ret;
}

static int __ps_process_datacontrol(xmlTextReaderPtr reader, datacontrol_x *datacontrol)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	capability_x *tmp1 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("provider-id")))
		datacontrol->providerid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("provider-id")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "capability")) {
			capability_x *capability = malloc(sizeof(capability_x));
			if (capability == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(capability, '\0', sizeof(capability_x));
			if (capability) {
				LISTADD(datacontrol->capability, capability);
				ret =
				    __ps_process_capability(reader, capability);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing datacontrol failed\n");
			return ret;
		}
	}

	if (datacontrol->capability) {
		LISTHEAD(datacontrol->capability, tmp1);
		datacontrol->capability = tmp1;
	}

	return ret;
}

static int __ps_process_uiapplication(xmlTextReaderPtr reader, uiapplication_x *uiapplication)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	char *newappid = NULL;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	appsvc_x *tmp3 = NULL;
	appcontrol_x *tmp4 = NULL;
	launchconditions_x *tmp5 = NULL;
	notification_x *tmp6 = NULL;
	datashare_x *tmp7 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("appid"))) {
		uiapplication->appid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("appid")));
		if (uiapplication->appid == NULL) {
			DBG("appid cant be NULL\n");
			return -1;
		}
	} else {
		DBG("appid is mandatory\n");
		return -1;
	}
	/*check appid*/
	ret = __validate_appid(package, uiapplication->appid, &newappid);
	if (ret == -1) {
		DBG("appid is not proper\n");
		return -1;
	} else {
		if (newappid) {
			if (uiapplication->appid)
				free((void *)uiapplication->appid);
			uiapplication->appid = newappid;
		}
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("exec")))
		uiapplication->exec = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("exec")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("nodisplay"))) {
		uiapplication->nodisplay = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("nodisplay")));
		if (uiapplication->nodisplay == NULL)
			uiapplication->nodisplay = strdup("false");
	} else {
		uiapplication->nodisplay = strdup("false");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("multiple"))) {
		uiapplication->multiple = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("multiple")));
		if (uiapplication->multiple == NULL)
			uiapplication->multiple = strdup("false");
	} else {
		uiapplication->multiple = strdup("false");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("type")))
		uiapplication->type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("type")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("categories")))
		uiapplication->categories = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("categories")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("extraid")))
		uiapplication->extraid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("extraid")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("taskmanage"))) {
		uiapplication->taskmanage = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("taskmanage")));
		if (uiapplication->taskmanage == NULL)
			uiapplication->taskmanage = strdup("true");
	} else {
		uiapplication->taskmanage = strdup("true");
	}

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}
		if (!strcmp(ASCII(node), "label")) {
			label_x *label = malloc(sizeof(label_x));
			if (label == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(label, '\0', sizeof(label_x));
			if (label) {
				LISTADD(uiapplication->label, label);
				ret =
				    __ps_process_label(reader, label);

				DBG("label processing\n");
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = malloc(sizeof(icon_x));
			if (icon == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(icon, '\0', sizeof(icon_x));
			if (icon) {
				LISTADD(uiapplication->icon, icon);
				ret =
				    __ps_process_icon(reader, icon);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "app-control")) {
			appcontrol_x *appcontrol = malloc(sizeof(appcontrol_x));
			if (appcontrol == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(appcontrol, '\0', sizeof(appcontrol_x));
			if (appcontrol) {
				LISTADD(uiapplication->appcontrol, appcontrol);
				ret =
				    __ps_process_appcontrol(reader, appcontrol);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "application-service")) {
			DBG("appsvc processing start\n");

			appsvc_x *appsvc = malloc(sizeof(appsvc_x));
			if (appsvc == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(appsvc, '\0', sizeof(appsvc_x));
			if (appsvc) {
				LISTADD(uiapplication->appsvc, appsvc);
				ret =
				    __ps_process_appsvc(reader, appsvc);

				DBG("appsvc processing end\n");
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "data-share")) {
			datashare_x *datashare = malloc(sizeof(datashare_x));
			if (datashare == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(datashare, '\0', sizeof(datashare_x));
			if (datashare) {
				LISTADD(uiapplication->datashare, datashare);
				ret =
				    __ps_process_datashare(reader, datashare);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "launch-conditions")) {
			launchconditions_x *launchconditions = malloc(sizeof(launchconditions_x));
			if (launchconditions == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(launchconditions, '\0', sizeof(launchconditions_x));
			if (launchconditions) {
				LISTADD(uiapplication->launchconditions, launchconditions);
				ret =
				    __ps_process_launchconditions(reader, launchconditions);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "notification")) {
			notification_x *notification = malloc(sizeof(notification_x));
			if (notification == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(notification, '\0', sizeof(notification_x));
			if (notification) {
				LISTADD(uiapplication->notification, notification);
				ret =
				    __ps_process_notification(reader, notification);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing uiapplication failed\n");
			return ret;
		}
	}

	if (uiapplication->label) {
		LISTHEAD(uiapplication->label, tmp1);
		uiapplication->label = tmp1;
	}
	if (uiapplication->icon) {
		LISTHEAD(uiapplication->icon, tmp2);
		uiapplication->icon = tmp2;
	}
	if (uiapplication->appsvc) {
		LISTHEAD(uiapplication->appsvc, tmp3);
		uiapplication->appsvc = tmp3;
	}
	if (uiapplication->appcontrol) {
		LISTHEAD(uiapplication->appcontrol, tmp4);
		uiapplication->appcontrol = tmp4;
	}
	if (uiapplication->launchconditions) {
		LISTHEAD(uiapplication->launchconditions, tmp5);
		uiapplication->launchconditions = tmp5;
	}
	if (uiapplication->notification) {
		LISTHEAD(uiapplication->notification, tmp6);
		uiapplication->notification = tmp6;
	}
	if (uiapplication->datashare) {
		LISTHEAD(uiapplication->datashare, tmp7);
		uiapplication->datashare = tmp7;
	}

	return ret;
}

static int __ps_process_serviceapplication(xmlTextReaderPtr reader, serviceapplication_x *serviceapplication)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	char *newappid = NULL;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	appsvc_x *tmp3 = NULL;
	appcontrol_x *tmp4 = NULL;
	datacontrol_x *tmp5 = NULL;
	launchconditions_x *tmp6 = NULL;
	notification_x *tmp7 = NULL;
	datashare_x *tmp8 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("appid"))) {
		serviceapplication->appid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("appid")));
		if (serviceapplication->appid == NULL) {
			DBG("appid cant be NULL\n");
			return -1;
		}
	} else {
		DBG("appid is mandatory\n");
		return -1;
	}
	/*check appid*/
	ret = __validate_appid(package, serviceapplication->appid, &newappid);
	if (ret == -1) {
		DBG("appid is not proper\n");
		return -1;
	} else {
		if (newappid) {
			if (serviceapplication->appid)
				free((void *)serviceapplication->appid);
			serviceapplication->appid = newappid;
		}
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("exec")))
		serviceapplication->exec = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("exec")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("type")))
		serviceapplication->type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("type")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("on-boot"))) {
		serviceapplication->onboot = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("on-boot")));
		if (serviceapplication->onboot == NULL)
			serviceapplication->onboot = strdup("false");
	} else {
		serviceapplication->onboot = strdup("false");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("auto-restart"))) {
		serviceapplication->autorestart = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("auto-restart")));
		if (serviceapplication->autorestart == NULL)
			serviceapplication->autorestart = strdup("false");
	} else {
		serviceapplication->autorestart = strdup("false");
	}

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "label")) {
			label_x *label = malloc(sizeof(label_x));
			if (label == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(label, '\0', sizeof(label_x));
			if (label) {
				LISTADD(serviceapplication->label, label);
				ret =
				    __ps_process_label(reader, label);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = malloc(sizeof(icon_x));
			if (icon == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(icon, '\0', sizeof(icon_x));
			if (icon) {
				LISTADD(serviceapplication->icon, icon);
				ret =
				    __ps_process_icon(reader, icon);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "app-control")) {
			appcontrol_x *appcontrol = malloc(sizeof(appcontrol_x));
			if (appcontrol == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(appcontrol, '\0', sizeof(appcontrol_x));
			if (appcontrol) {
				LISTADD(serviceapplication->appcontrol, appcontrol);
				ret =
				    __ps_process_appcontrol(reader, appcontrol);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "application-service")) {
			appsvc_x *appsvc = malloc(sizeof(appsvc_x));
			if (appsvc == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(appsvc, '\0', sizeof(appsvc_x));
			if (appsvc) {
				LISTADD(serviceapplication->appsvc, appsvc);
				ret =
				    __ps_process_appsvc(reader, appsvc);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "data-share")) {
			datashare_x *datashare = malloc(sizeof(datashare_x));
			if (datashare == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(datashare, '\0', sizeof(datashare_x));
			if (datashare) {
				LISTADD(serviceapplication->datashare, datashare);
				ret =
				    __ps_process_datashare(reader, datashare);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "launch-conditions")) {
			launchconditions_x *launchconditions = malloc(sizeof(launchconditions_x));
			if (launchconditions == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(launchconditions, '\0', sizeof(launchconditions_x));
			if (launchconditions) {
				LISTADD(serviceapplication->launchconditions, launchconditions);
				ret =
				    __ps_process_launchconditions(reader, launchconditions);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "notification")) {
			notification_x *notification = malloc(sizeof(notification_x));
			if (notification == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(notification, '\0', sizeof(notification_x));
			if (notification) {
				LISTADD(serviceapplication->notification, notification);
				ret =
				    __ps_process_notification(reader, notification);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "data-control")) {
			datacontrol_x *datacontrol = malloc(sizeof(datacontrol_x));
			if (datacontrol == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(datacontrol, '\0', sizeof(datacontrol_x));
			if (datacontrol) {
				LISTADD(serviceapplication->datacontrol, datacontrol);
				ret =
				    __ps_process_datacontrol(reader, datacontrol);
			} else
				return -1;
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing serviceapplication failed\n");
			return ret;
		}
	}

	if (serviceapplication->label) {
		LISTHEAD(serviceapplication->label, tmp1);
		serviceapplication->label = tmp1;
	}
	if (serviceapplication->icon) {
		LISTHEAD(serviceapplication->icon, tmp2);
		serviceapplication->icon = tmp2;
	}
	if (serviceapplication->appsvc) {
		LISTHEAD(serviceapplication->appsvc, tmp3);
		serviceapplication->appsvc = tmp3;
	}
	if (serviceapplication->appcontrol) {
		LISTHEAD(serviceapplication->appcontrol, tmp4);
		serviceapplication->appcontrol = tmp4;
	}
	if (serviceapplication->datacontrol) {
		LISTHEAD(serviceapplication->datacontrol, tmp5);
		serviceapplication->datacontrol = tmp5;
	}
	if (serviceapplication->launchconditions) {
		LISTHEAD(serviceapplication->launchconditions, tmp6);
		serviceapplication->launchconditions = tmp6;
	}
	if (serviceapplication->notification) {
		LISTHEAD(serviceapplication->notification, tmp7);
		serviceapplication->notification = tmp7;
	}
	if (serviceapplication->datashare) {
		LISTHEAD(serviceapplication->datashare, tmp8);
		serviceapplication->datashare = tmp8;
	}

	return ret;
}

static int __ps_process_deviceprofile(xmlTextReaderPtr reader, deviceprofile_x *deviceprofile)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_font(xmlTextReaderPtr reader, font_x *font)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_theme(xmlTextReaderPtr reader, theme_x *theme)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_daemon(xmlTextReaderPtr reader, daemon_x *daemon)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_ime(xmlTextReaderPtr reader, ime_x *ime)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __start_process(xmlTextReaderPtr reader, manifest_x * mfx)
{
	DBG("__start_process\n");
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	label_x *tmp1 = NULL;
	author_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	license_x *tmp4 = NULL;
	uiapplication_x *tmp5 = NULL;
	serviceapplication_x *tmp6 = NULL;
	daemon_x *tmp7 = NULL;
	theme_x *tmp8 = NULL;
	font_x *tmp9 = NULL;
	ime_x *tmp10 = NULL;
	livebox_x *tmp11 = NULL;
	icon_x *tmp12 = NULL;
	compatibility_x *tmp13 = NULL;
	deviceprofile_x *tmp14 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "label")) {
			label_x *label = malloc(sizeof(label_x));
			if (label == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(label, '\0', sizeof(label_x));
			if (label) {
				LISTADD(mfx->label, label);
				ret =
				    __ps_process_label(reader, label);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "author")) {
			author_x *author = malloc(sizeof(author_x));
			if (author == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(author, '\0', sizeof(author_x));
			if (author) {
				LISTADD(mfx->author, author);
				ret =
				    __ps_process_author(reader, author);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "description")) {
			description_x *description = malloc(sizeof(description_x));
			if (description == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(description, '\0', sizeof(description_x));
			if (description) {
				LISTADD(mfx->description, description);
				ret =
				    __ps_process_description(reader, description);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "license")) {
			license_x *license = malloc(sizeof(license_x));
			if (license == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(license, '\0', sizeof(license_x));
			if (license) {
				LISTADD(mfx->license, license);
				ret =
				    __ps_process_license(reader, license);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "ui-application")) {
			uiapplication_x *uiapplication = malloc(sizeof(uiapplication_x));
			if (uiapplication == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(uiapplication, '\0', sizeof(uiapplication_x));
			if (uiapplication) {
				LISTADD(mfx->uiapplication, uiapplication);
				ret =
				    __ps_process_uiapplication(reader, uiapplication);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "service-application")) {
			serviceapplication_x *serviceapplication = malloc(sizeof(serviceapplication_x));
			if (serviceapplication == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(serviceapplication, '\0', sizeof(serviceapplication_x));
			if (serviceapplication) {
				LISTADD(mfx->serviceapplication, serviceapplication);
				ret =
				    __ps_process_serviceapplication(reader, serviceapplication);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "daemon")) {
			daemon_x *daemon = malloc(sizeof(daemon_x));
			if (daemon == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(daemon, '\0', sizeof(daemon_x));
			if (daemon) {
				LISTADD(mfx->daemon, daemon);
				ret =
				    __ps_process_daemon(reader, daemon);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "theme")) {
			theme_x *theme = malloc(sizeof(theme_x));
			if (theme == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(theme, '\0', sizeof(theme_x));
			if (theme) {
				LISTADD(mfx->theme, theme);
				ret =
				    __ps_process_theme(reader, theme);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "font")) {
			font_x *font = malloc(sizeof(font_x));
			if (font == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(font, '\0', sizeof(font_x));
			if (font) {
				LISTADD(mfx->font, font);
				ret =
				    __ps_process_font(reader, font);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "ime")) {
			ime_x *ime = malloc(sizeof(ime_x));
			if (ime == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(ime, '\0', sizeof(ime_x));
			if (ime) {
				LISTADD(mfx->ime, ime);
				ret =
				    __ps_process_ime(reader, ime);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "livebox")) {
			livebox_x *livebox = malloc(sizeof(livebox_x));
			if (livebox == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(livebox, '\0', sizeof(livebox_x));
			if (livebox) {
				LISTADD(mfx->livebox, livebox);
				ret =
				    __ps_process_livebox(reader, livebox);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = malloc(sizeof(icon_x));
			if (icon == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(icon, '\0', sizeof(icon_x));
			if (icon) {
				LISTADD(mfx->icon, icon);
				ret =
				    __ps_process_icon(reader, icon);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "device-profile")) {
			deviceprofile_x *deviceprofile = malloc(sizeof(deviceprofile_x));
			if (deviceprofile == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(deviceprofile, '\0', sizeof(deviceprofile_x));
			if (deviceprofile) {
				LISTADD(mfx->deviceprofile, deviceprofile);
				ret =
				    __ps_process_deviceprofile(reader, deviceprofile);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "compatibility")) {
			compatibility_x *compatibility = malloc(sizeof(compatibility_x));
			if (compatibility == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(compatibility, '\0', sizeof(compatibility_x));
			if (compatibility) {
				LISTADD(mfx->compatibility, compatibility);
				ret =
				    __ps_process_compatibility(reader, compatibility);
			} else
				return -1;
		} else if (!strcmp(ASCII(node), "shortcuts")) {
			return 0;
		} else
			return -1;

		if (ret < 0) {
			DBG("Processing manifest failed\n");
			return ret;
		}
	}
	if (mfx->label) {
		LISTHEAD(mfx->label, tmp1);
		mfx->label = tmp1;
	}
	if (mfx->author) {
		LISTHEAD(mfx->author, tmp2);
		mfx->author = tmp2;
	}
	if (mfx->description) {
		LISTHEAD(mfx->description, tmp3);
		mfx->description= tmp3;
	}
	if (mfx->license) {
		LISTHEAD(mfx->license, tmp4);
		mfx->license= tmp4;
	}
	if (mfx->uiapplication) {
		LISTHEAD(mfx->uiapplication, tmp5);
		mfx->uiapplication = tmp5;
	}
	if (mfx->serviceapplication) {
		LISTHEAD(mfx->serviceapplication, tmp6);
		mfx->serviceapplication = tmp6;
	}
	if (mfx->daemon) {
		LISTHEAD(mfx->daemon, tmp7);
		mfx->daemon= tmp7;
	}
	if (mfx->theme) {
		LISTHEAD(mfx->theme, tmp8);
		mfx->theme= tmp8;
	}
	if (mfx->font) {
		LISTHEAD(mfx->font, tmp9);
		mfx->font= tmp9;
	}
	if (mfx->ime) {
		LISTHEAD(mfx->ime, tmp10);
		mfx->ime= tmp10;
	}
	if (mfx->livebox) {
		LISTHEAD(mfx->livebox, tmp11);
		mfx->livebox= tmp11;
	}
	if (mfx->icon) {
		LISTHEAD(mfx->icon, tmp12);
		mfx->icon= tmp12;
	}
	if (mfx->compatibility) {
		LISTHEAD(mfx->compatibility, tmp13);
		mfx->compatibility= tmp13;
	}
	if (mfx->deviceprofile) {
		LISTHEAD(mfx->deviceprofile, tmp14);
		mfx->deviceprofile= tmp14;
	}

	return ret;
}

static int __process_manifest(xmlTextReaderPtr reader, manifest_x * mfx)
{
	const xmlChar *node;
	int ret = -1;

	if ((ret = __next_child_element(reader, -1))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "manifest")) {
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("xmlns")))
				mfx->ns = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("xmlns")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("package"))) {
				mfx->package= ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("package")));
				if (mfx->package == NULL) {
					DBG("package cant be NULL\n");
					return -1;
				}
			} else {
				DBG("package field is mandatory\n");
				return -1;
			}
			package = mfx->package;
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("version")))
				mfx->version= ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("version")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("install-location")))
				mfx->installlocation = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("install-location")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("type")))
				mfx->type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("type")));
			/*Assign default values. If required it will be overwritten in __add_preload_info()*/
			mfx->preload = strdup("False");
			mfx->removable = strdup("True");
			mfx->readonly = strdup("False");

			ret = __start_process(reader, mfx);
		} else {
			DBG("No Manifest element found\n");
			return -1;
		}
	}
	return ret;
}

#define DESKTOP_RW_PATH "/opt/share/applications/"
#define DESKTOP_RO_PATH "/usr/share/applications/"

static char* __convert_to_system_locale(const char *mlocale)
{
	if (mlocale == NULL)
		return NULL;
	char *locale = NULL;
	locale = (char *)calloc(1, 6);
	if (!locale) {
		_LOGE("Malloc Failed\n");
		return NULL;
	}

	strncpy(locale, mlocale, 2);
	strncat(locale, "_", 1);
	locale[3] = toupper(mlocale[3]);
	locale[4] = toupper(mlocale[4]);
	return locale;
}


/* desktop shoud be generated automatically based on manifest */
/* Currently removable, taskmanage, etc fields are not considerd. it will be decided soon.*/
static int __ps_make_nativeapp_desktop(manifest_x * mfx)
{
        FILE* file = NULL;
        int fd = 0;
        char filepath[PKG_STRING_LEN_MAX] = "";
        char buf[4096] = "";
	char buftemp[4096] = "";

	for(; mfx->uiapplication; mfx->uiapplication=mfx->uiapplication->next) {

		if(mfx->readonly && !strcasecmp(mfx->readonly, "True"))
		        snprintf(filepath, sizeof(filepath),"%s%s.desktop", DESKTOP_RO_PATH, mfx->uiapplication->appid);
		else
			snprintf(filepath, sizeof(filepath),"%s%s.desktop", DESKTOP_RW_PATH, mfx->uiapplication->appid);

		/* skip if desktop exists
		if (access(filepath, R_OK) == 0)
			continue;
		*/

	        file = fopen(filepath, "w");
	        if(file == NULL)
	        {
	            _LOGE("Can't open %s", filepath);
	            return -1;
	        }

	        snprintf(buf, sizeof(buf), "[Desktop Entry]\n");
	        fwrite(buf, 1, strlen(buf), file);

		for( ; mfx->uiapplication->label ; mfx->uiapplication->label = mfx->uiapplication->label->next) {
			if(!strcmp(mfx->uiapplication->label->lang, DEFAULT_LOCALE)) {
				snprintf(buf, sizeof(buf), "Name=%s\n",	mfx->uiapplication->label->text);
			} else {
				snprintf(buf, sizeof(buf), "Name[%s]=%s\n",
					__convert_to_system_locale(mfx->uiapplication->label->lang),
					mfx->uiapplication->label->text);
			}
	        	fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->label && mfx->uiapplication->label->text) {
		        snprintf(buf, sizeof(buf), "Name=%s\n", mfx->uiapplication->label->text);
	        	fwrite(buf, 1, strlen(buf), file);
		}
/*
		else if(mfx->label && mfx->label->text) {
			snprintf(buf, sizeof(buf), "Name=%s\n", mfx->label->text);
	        	fwrite(buf, 1, strlen(buf), file);
		} else {
			snprintf(buf, sizeof(buf), "Name=%s\n", mfx->package);
			fwrite(buf, 1, strlen(buf), file);
		}
*/


	        snprintf(buf, sizeof(buf), "Type=Application\n");
	        fwrite(buf, 1, strlen(buf), file);

		if(mfx->uiapplication->exec) {
		        snprintf(buf, sizeof(buf), "Exec=%s\n", mfx->uiapplication->exec);
		        fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->icon && mfx->uiapplication->icon->text) {
		        snprintf(buf, sizeof(buf), "Icon=%s\n", mfx->uiapplication->icon->text);
		        fwrite(buf, 1, strlen(buf), file);
		} else if(mfx->icon && mfx->icon->text) {
		        snprintf(buf, sizeof(buf), "Icon=%s\n", mfx->icon->text);
		        fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->version) {
		        snprintf(buf, sizeof(buf), "Version=%s\n", mfx->version);
		        fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->nodisplay) {
			snprintf(buf, sizeof(buf), "NoDisplay=%s\n", mfx->uiapplication->nodisplay);
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->categories) {
			snprintf(buf, sizeof(buf), "Categories=%s\n", mfx->uiapplication->categories);
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->taskmanage && !strcasecmp(mfx->uiapplication->taskmanage, "False")) {
		        snprintf(buf, sizeof(buf), "X-TIZEN-TaskManage=False\n");
		        fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->multiple && !strcasecmp(mfx->uiapplication->multiple, "True")) {
			snprintf(buf, sizeof(buf), "X-TIZEN-Multiple=True\n");
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->extraid) {
			snprintf(buf, sizeof(buf), "X-TIZEN-PackageID=%s\n", mfx->uiapplication->extraid);
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->removable && !strcasecmp(mfx->removable, "False")) {
			snprintf(buf, sizeof(buf), "X-TIZEN-Removable=False\n");
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->type) {
			snprintf(buf, sizeof(buf), "X-TIZEN-PackageType=%s\n", mfx->type);
			fwrite(buf, 1, strlen(buf), file);
		}

//		snprintf(buf, sizeof(buf), "X-TIZEN-PackageType=rpm\n");
//		fwrite(buf, 1, strlen(buf), file);


		if(mfx->uiapplication->appsvc) {
			snprintf(buf, sizeof(buf), "X-TIZEN-Svc=");
			DBG("buf[%s]\n", buf);


			uiapplication_x *up = mfx->uiapplication;
			appsvc_x *asvc = NULL;
			operation_x *op = NULL;
			mime_x *mi = NULL;
			uri_x *ui = NULL;
			int ret = -1;
			char query[PKG_STRING_LEN_MAX] = {'\0'};
			char *operation = NULL;
			char *mime = NULL;
			char *uri = NULL;
			int i = 0;


			asvc = up->appsvc;
			while(asvc != NULL)
			{
				op = asvc->operation;
				while(op != NULL)
				{
					if (op)
						operation = op->name;
					mi = asvc->mime;

					do
					{
						if (mi)
							mime = mi->name;
						ui = asvc->uri;
						do
						{
							if (ui)
								uri = ui->name;

							if(i++ > 0) {
								strncpy(buftemp, buf, sizeof(buftemp));
								snprintf(buf, sizeof(buf), "%s;", buftemp);
							}

							strncpy(buftemp, buf, sizeof(buftemp));
							snprintf(buf, sizeof(buf), "%s%s|%s|%s", buftemp, operation?operation:"NULL", uri?uri:"NULL", mime?mime:"NULL");
							DBG("buf[%s]\n", buf);

							if (ui)
								ui = ui->next;
							uri = NULL;
						} while(ui != NULL);
						if (mi)
							mi = mi->next;
						mime = NULL;
					}while(mi != NULL);
					if (op)
						op = op->next;
					operation = NULL;
				}
				asvc = asvc->next;
			}


			fwrite(buf, 1, strlen(buf), file);

//			strncpy(buftemp, buf, sizeof(buftemp));
//			snprintf(buf, sizeof(buf), "%s\n", buftemp);
//			fwrite(buf, 1, strlen(buf), file);
		}

	        fd = fileno(file);
	        fdatasync(fd);
	        fclose(file);
	}

        return 0;
}

static int __ps_remove_nativeapp_desktop(manifest_x *mfx)
{
        char filepath[PKG_STRING_LEN_MAX] = "";

	for(; mfx->uiapplication; mfx->uiapplication=mfx->uiapplication->next) {
	        snprintf(filepath, sizeof(filepath),"%s%s.desktop", DESKTOP_RW_PATH, mfx->uiapplication->appid);

		remove(filepath);
	}

        return 0;
}

#define MANIFEST_RO_PREFIX "/usr/share/packages/"
#define PRELOAD_PACKAGE_LIST "/usr/etc/package-manager/preload/preload_list.txt"
static int __add_preload_info(manifest_x * mfx, const char *manifest)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	int state = 0;

	if(strstr(manifest, MANIFEST_RO_PREFIX)) {
		free(mfx->readonly);
		mfx->readonly = strdup("True");

		free(mfx->preload);
		mfx->preload = strdup("True");

		free(mfx->removable);
		mfx->removable = strdup("False");

		return 0;
	}

	fp = fopen(PRELOAD_PACKAGE_LIST, "r");
	if (fp == NULL) {
		_LOGE("no preload list\n");
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (buffer[0] == '#') {
			if(strcasestr(buffer, "RW_NORM"))
				state = 2;
			else if(strcasestr(buffer, "RW_RM"))
				state = 3;
			else
				continue;
		}

		__str_trim(buffer);

		if(!strcmp(mfx->package, buffer)) {
			free(mfx->preload);
			mfx->preload = strdup("True");
			if(state == 2){
				free(mfx->readonly);
				mfx->readonly = strdup("False");
				free(mfx->removable);
				mfx->removable = strdup("False");
			} else if(state == 3){
				free(mfx->readonly);
				mfx->readonly = strdup("False");
				free(mfx->removable);
				mfx->removable = strdup("True");
			}
		}

		memset(buffer, 0x00, sizeof(buffer));
	}

	if (fp != NULL)
		fclose(fp);

	return 0;
}


API void pkgmgr_parser_free_manifest_xml(manifest_x *mfx)
{
	if (mfx == NULL)
		return;
	if (mfx->ns) {
		free((void *)mfx->ns);
		mfx->ns = NULL;
	}
	if (mfx->package) {
		free((void *)mfx->package);
		mfx->package = NULL;
	}
	if (mfx->version) {
		free((void *)mfx->version);
		mfx->version = NULL;
	}
	if (mfx->installlocation) {
		free((void *)mfx->installlocation);
		mfx->installlocation = NULL;
	}
	if (mfx->preload) {
		free((void *)mfx->preload);
		mfx->preload = NULL;
	}
	if (mfx->readonly) {
		free((void *)mfx->readonly);
		mfx->readonly = NULL;
	}
	if (mfx->removable) {
		free((void *)mfx->removable);
		mfx->removable = NULL;
	}
	if (mfx->type) {
		free((void *)mfx->type);
		mfx->type = NULL;
	}

	/*Free Icon*/
	if (mfx->icon) {
		icon_x *icon = mfx->icon;
		icon_x *tmp = NULL;
		while(icon != NULL)
		{
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free Label*/
	if (mfx->label) {
		label_x *label = mfx->label;
		label_x *tmp = NULL;
		while(label != NULL)
		{
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Author*/
	if (mfx->author) {
		author_x *author = mfx->author;
		author_x *tmp = NULL;
		while(author != NULL)
		{
			tmp = author->next;
			__ps_free_author(author);
			author = tmp;
		}
	}
	/*Free Description*/
	if (mfx->description) {
		description_x *description = mfx->description;
		description_x *tmp = NULL;
		while(description != NULL)
		{
			tmp = description->next;
			__ps_free_description(description);
			description = tmp;
		}
	}
	/*Free License*/
	if (mfx->license) {
		license_x *license = mfx->license;
		license_x *tmp = NULL;
		while(license != NULL)
		{
			tmp = license->next;
			__ps_free_license(license);
			license = tmp;
		}
	}
	/*Free UiApplication*/
	if (mfx->uiapplication) {
		uiapplication_x *uiapplication = mfx->uiapplication;
		uiapplication_x *tmp = NULL;
		while(uiapplication != NULL)
		{
			tmp = uiapplication->next;
			__ps_free_uiapplication(uiapplication);
			uiapplication = tmp;
		}
	}
	/*Free ServiceApplication*/
	if (mfx->serviceapplication) {
		serviceapplication_x *serviceapplication = mfx->serviceapplication;
		serviceapplication_x *tmp = NULL;
		while(serviceapplication != NULL)
		{
			tmp = serviceapplication->next;
			__ps_free_serviceapplication(serviceapplication);
			serviceapplication = tmp;
		}
	}
	/*Free Daemon*/
	if (mfx->daemon) {
		daemon_x *daemon = mfx->daemon;
		daemon_x *tmp = NULL;
		while(daemon != NULL)
		{
			tmp = daemon->next;
			__ps_free_daemon(daemon);
			daemon = tmp;
		}
	}
	/*Free Theme*/
	if (mfx->theme) {
		theme_x *theme = mfx->theme;
		theme_x *tmp = NULL;
		while(theme != NULL)
		{
			tmp = theme->next;
			__ps_free_theme(theme);
			theme = tmp;
		}
	}
	/*Free Font*/
	if (mfx->font) {
		font_x *font = mfx->font;
		font_x *tmp = NULL;
		while(font != NULL)
		{
			tmp = font->next;
			__ps_free_font(font);
			font = tmp;
		}
	}
	/*Free Ime*/
	if (mfx->ime) {
		ime_x *ime = mfx->ime;
		ime_x *tmp = NULL;
		while(ime != NULL)
		{
			tmp = ime->next;
			__ps_free_ime(ime);
			ime = tmp;
		}
	}
	/*Free Livebox*/
	if (mfx->livebox) {
		livebox_x *livebox = mfx->livebox;
		livebox_x *tmp = NULL;
		while(livebox != NULL)
		{
			tmp = livebox->next;
			__ps_free_livebox(livebox);
			livebox = tmp;
		}
	}
	/*Free Compatibility*/
	if (mfx->compatibility) {
		compatibility_x *compatibility = mfx->compatibility;
		compatibility_x *tmp = NULL;
		while(compatibility != NULL)
		{
			tmp = compatibility->next;
			__ps_free_compatibility(compatibility);
			compatibility = tmp;
		}
	}
	/*Free DeviceProfile*/
	if (mfx->deviceprofile) {
		deviceprofile_x *deviceprofile = mfx->deviceprofile;
		deviceprofile_x *tmp = NULL;
		while(deviceprofile != NULL)
		{
			tmp = deviceprofile->next;
			__ps_free_deviceprofile(deviceprofile);
			deviceprofile = tmp;
		}
	}
	free((void*)mfx);
	mfx = NULL;
	return;
}

manifest_x *pkgmgr_parser_process_manifest_xml(const char *manifest)
{
	DBG("parsing start\n");
	xmlTextReaderPtr reader;
	manifest_x *mfx = NULL;

	reader = xmlReaderForFile(manifest, NULL, 0);
	if (reader) {
		mfx = malloc(sizeof(manifest_x));
		if (mfx) {
			memset(mfx, '\0', sizeof(manifest_x));
			if (__process_manifest(reader, mfx) < 0) {
				DBG("Parsing Failed\n");
				pkgmgr_parser_free_manifest_xml(mfx);
				mfx = NULL;
			} else
				DBG("Parsing Success\n");
		} else {
			DBG("Memory allocation error\n");
		}
		xmlFreeTextReader(reader);
	} else {
		DBG("Unable to create xml reader\n");
	}
	return mfx;
}

/* These APIs are intended to call parser directly */

API int pkgmgr_parser_parse_manifest_for_installation(const char *manifest, char *const tagv[])
{
	char *temp[] = {"shortcuts", NULL};
	if (manifest == NULL) {
		DBG("argument supplied is NULL\n");
		return -1;
	}
	DBG("parsing manifest for installation: %s\n", manifest);
	manifest_x *mfx = NULL;
	int ret = -1;
	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	DBG("Parsing Finished\n");
	if (mfx) {
		__streamFile(manifest, ACTION_INSTALL, temp, mfx->package);
		__add_preload_info(mfx, manifest);
		DBG("Added preload infomation\n");
		ret = pkgmgr_parser_insert_manifest_info_in_db(mfx);
		if (ret == -1)
			DBG("DB Insert failed\n");
		else
			DBG("DB Insert Success\n");

		ret = __ps_make_nativeapp_desktop(mfx);
		if (ret == -1)
			DBG("Creating desktop file failed\n");
		else
			DBG("Creating desktop file Success\n");
	} else
		DBG("mfx is NULL\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	DBG("Free Done\n");
	xmlCleanupParser();

	return 0;
}

API int pkgmgr_parser_parse_manifest_for_upgrade(const char *manifest, char *const tagv[])
{
	char *temp[] = {"shortcuts", NULL};
	if (manifest == NULL) {
		DBG("argument supplied is NULL\n");
		return -1;
	}
	DBG("parsing manifest for upgradation: %s\n", manifest);
	manifest_x *mfx = NULL;
	int ret = -1;
	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	DBG("Parsing Finished\n");

	if (mfx) {
		__streamFile(manifest, ACTION_UPGRADE, temp, mfx->package);
		__add_preload_info(mfx, manifest);
		DBG("Added preload infomation\n");
		ret = pkgmgr_parser_update_manifest_info_in_db(mfx);
		if (ret == -1)
			DBG("DB Update failed\n");
		else
			DBG("DB Update Success\n");

		ret = __ps_make_nativeapp_desktop(mfx);
		if (ret == -1)
			DBG("Creating desktop file failed\n");
		else
			DBG("Creating desktop file Success\n");
	}
	pkgmgr_parser_free_manifest_xml(mfx);
	DBG("Free Done\n");
	xmlCleanupParser();

	return 0;
}

API int pkgmgr_parser_parse_manifest_for_uninstallation(const char *manifest, char *const tagv[])
{
	char *temp[] = {"shortcuts", NULL};
	if (manifest == NULL) {
		DBG("argument supplied is NULL\n");
		return -1;
	}
	DBG("parsing manifest for uninstallation: %s\n", manifest);
	manifest_x *mfx = NULL;
	int ret = -1;
	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	DBG("Parsing Finished\n");

	if (mfx) {
		__streamFile(manifest, ACTION_UNINSTALL, temp, mfx->package);
		__add_preload_info(mfx, manifest);
		DBG("Added preload infomation\n");

		ret = pkgmgr_parser_delete_manifest_info_from_db(mfx);
		if (ret == -1)
			DBG("DB Delete failed\n");
		else
			DBG("DB Delete Success\n");

		ret = __ps_remove_nativeapp_desktop(mfx);
		if (ret == -1)
			DBG("Removing desktop file failed\n");
		else
			DBG("Removing desktop file Success\n");
	}
	pkgmgr_parser_free_manifest_xml(mfx);
	DBG("Free Done\n");
	xmlCleanupParser();

	return 0;
}

API char *pkgmgr_parser_get_manifest_file(const char *pkgname)
{
	return __pkgname_to_manifest(pkgname);
}

API int pkgmgr_parser_run_parser_for_installation(xmlDocPtr docPtr, const char *tag, const char *pkgname)
{
	return __ps_run_parser(docPtr, tag, ACTION_INSTALL, pkgname);
}

API int pkgmgr_parser_run_parser_for_upgrade(xmlDocPtr docPtr, const char *tag, const char *pkgname)
{
	return __ps_run_parser(docPtr, tag, ACTION_UPGRADE, pkgname);
}

API int pkgmgr_parser_run_parser_for_uninstallation(xmlDocPtr docPtr, const char *tag, const char *pkgname)
{
	return __ps_run_parser(docPtr, tag, ACTION_UNINSTALL, pkgname);
}

#define SCHEMA_FILE "/usr/etc/package-manager/preload/manifest.xsd"
#if 1
API int pkgmgr_parser_check_manifest_validation(const char *manifest)
{
	if (manifest == NULL) {
		DBGE("manifest file is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	int ret = -1;
	xmlSchemaParserCtxtPtr ctx;
	xmlSchemaValidCtxtPtr vctx;
	xmlSchemaPtr xschema;
	ctx = xmlSchemaNewParserCtxt(SCHEMA_FILE);
	if (ctx == NULL) {
		DBGE("xmlSchemaNewParserCtxt() Failed\n");
		return PKGMGR_R_ERROR;
	}
	xschema = xmlSchemaParse(ctx);
	if (xschema == NULL) {
		DBGE("xmlSchemaParse() Failed\n");
		return PKGMGR_R_ERROR;
	}
	vctx = xmlSchemaNewValidCtxt(xschema);
	if (vctx == NULL) {
		DBGE("xmlSchemaNewValidCtxt() Failed\n");
		return PKGMGR_R_ERROR;
	}
	xmlSchemaSetValidErrors(vctx, (xmlSchemaValidityErrorFunc) fprintf, (xmlSchemaValidityWarningFunc) fprintf, stderr);
	ret = xmlSchemaValidateFile(vctx, manifest, 0);
	if (ret == -1) {
		DBGE("xmlSchemaValidateFile() failed\n");
		return PKGMGR_R_ERROR;
	} else if (ret == 0) {
		DBGE("Manifest is Valid\n");
		return PKGMGR_R_OK;
	} else {
		DBGE("Manifest Validation Failed with error code %d\n", ret);
		return PKGMGR_R_ERROR;
	}
	return PKGMGR_R_OK;
}

#else
API int pkgmgr_parser_check_manifest_validation(const char *manifest)
{
	int err = 0;
	int status = 0;
	pid_t pid;

	pid = fork();

	switch (pid) {
	case -1:
		DBGE("fork failed\n");
		return -1;
	case 0:
		/* child */
		{
			int dev_null_fd = open ("/dev/null", O_RDWR);
			if (dev_null_fd >= 0)
			{
			        dup2 (dev_null_fd, 0);/*stdin*/
			        dup2 (dev_null_fd, 1);/*stdout*/
			        dup2 (dev_null_fd, 2);/*stderr*/
			}

			if (execl("/usr/bin/xmllint", "xmllint", manifest, "--schema",
				SCHEMA_FILE, NULL) < 0) {
				DBGE("execl error\n");
			}

			_exit(100);
		}
	default:
		/* parent */
		break;
	}

	while ((err = waitpid(pid, &status, WNOHANG)) != pid) {
		if (err < 0) {
			if (errno == EINTR)
				continue;
			DBGE("waitpid failed\n");
			return -1;
		}
	}


	if(WIFEXITED(status) && !WEXITSTATUS(status))
		return 0;
	else
		return -1;
}
#endif
