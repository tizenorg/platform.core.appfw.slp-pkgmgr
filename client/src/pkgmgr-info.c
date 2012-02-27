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
#include <dlfcn.h>
#include <sys/time.h>
#include <ail.h>
#include <aul.h>

#include "package-manager.h"
#include "pkgmgr-internal.h"
#include "pkgmgr-info.h"

char *_get_pkg_type_from_desktop_file(const char *pkg_name)
{
	static char pkg_type[PKG_EXT_LEN_MAX];
	
	ail_appinfo_h handle;
	ail_error_e ret;
	char *str;

	ret = ail_package_get_appinfo(pkg_name, &handle);
	if (ret != AIL_ERROR_OK) {
		return NULL;
	}

	ret = ail_appinfo_get_str(handle, AIL_PROP_X_SLP_PACKAGETYPE_STR, &str);
	if (ret != AIL_ERROR_OK) {
		ail_package_destroy_appinfo(handle);
		return NULL;
	}
	snprintf(pkg_type, sizeof(pkg_type) - 1, str);

	ret = ail_package_destroy_appinfo(handle);
	if (ret != AIL_ERROR_OK) {
		return NULL;
	}

	return pkg_type;
}

package_manager_pkg_info_t *_pkg_malloc_appinfo(int num)
{
	package_manager_app_info_t *app_info = NULL;
	package_manager_app_info_t *first = NULL;
	package_manager_app_info_t *last = NULL;
	int i = 0;

	for (i = 0; i < num; i++) {
		app_info = (package_manager_app_info_t *)
		    malloc(sizeof(package_manager_app_info_t));
		if (app_info == NULL) {
			package_manager_app_info_t *temp_info;
			package_manager_app_info_t *next;

			for (temp_info = first; temp_info != NULL;
			     temp_info = next) {
				next = temp_info->next;
				free(temp_info);
				temp_info = NULL;
			}

			return NULL;
		}

		memset(app_info, 0x00, sizeof(package_manager_app_info_t));

		if (first == NULL)
			first = app_info;

		if (last == NULL)
			last = app_info;
		else {
			last->next = app_info;
			last = app_info;
		}
	}

	return first;

}

static pkg_plugin_set *plugin_set_list[24] = { 0, };

pkg_plugin_set *_pkg_plugin_load_library(const char *pkg_type,
					 const char *library_path)
{
	void *library_handle = NULL;
	int i = 0;

	/* _pkg_plugin_on_load onload = NULL; */
	bool(*on_load) (pkg_plugin_set *plugin);

	if (library_path == NULL) {
		_LOGE("pkg library path = [%s] \n", library_path);
		return NULL;
	}

	if ((library_handle = dlopen(library_path, RTLD_LAZY)) == NULL) {
		_LOGE("dlopen is failed library_path[%s]\n", library_path);
		return NULL;
	}

	if ((on_load = dlsym(library_handle, "pkg_plugin_on_load")) == NULL || 
	    dlerror() != NULL) {
		_LOGE("can not find symbol \n");
		dlclose(library_handle);
		return NULL;
	}

	for (i = 0; plugin_set_list[i]; i++) {
		if (strcmp(plugin_set_list[i]->pkg_type, pkg_type) == 0) {
			_LOGD("already loaded [%s] is done well \n",
			      library_path);
			goto END;
		}
	}

	plugin_set_list[i] = (pkg_plugin_set *) malloc(sizeof(pkg_plugin_set));
	if (plugin_set_list[i] == NULL) {
		_LOGE("malloc of the plugin_set_list element is failed \n");
		dlclose(library_handle);
		return NULL;
	}

	memset(plugin_set_list[i], 0x0, sizeof(pkg_plugin_set));

	if (on_load(plugin_set_list[i]) != 0) {
		_LOGE("on_load is failed \n");

		dlclose(library_handle);

		free(plugin_set_list[i]);
		plugin_set_list[i] = NULL;

		return NULL;
	}

	plugin_set_list[i]->plugin_handle = library_handle;
	strncpy(plugin_set_list[i]->pkg_type, pkg_type,
		PKG_TYPE_STRING_LEN_MAX - 1);

	_LOGD("load library [%s] is done well \n", library_path);

 END:
	return plugin_set_list[i];

}

int _pkg_plugin_get_library_path(const char *pkg_type, char *library_path)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };

	if (pkg_type == NULL || library_path == NULL) {
		_LOGE("invalid argument\n");
		return -1;
	}

	fp = fopen(PKG_CONF_PATH, "r");
	if (fp == NULL) {
		_LOGE("no matching backendlib\n");
		return PKGMGR_R_ERROR;
	}

	char *path = NULL;
	while (fgets(buffer, 1024, fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		_app_str_trim(buffer);

		if ((path = strstr(buffer, PKG_BACKENDLIB)) != NULL) {
			_LOGD("[%s]\n", buffer);
			_LOGD("[%s]\n", path);
			path = path + strlen(PKG_BACKENDLIB);
			_LOGD("[%s]\n", path);

			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if (path == NULL) {
		_LOGE("no matching backendlib\n");
		return PKGMGR_R_ERROR;
	}

	snprintf(library_path, 1024, "%slib%s.so", path, pkg_type);

	return PKGMGR_R_OK;

}

pkg_plugin_set *_package_manager_load_library(const char *pkg_type)
{
	char package_path[1024] = { 0 };
	pkg_plugin_set *plugin_set = NULL;

	if (pkg_type == NULL) {
		_LOGE("can not load library - pkg_type is null\n");
		return NULL;
	}

	if (_pkg_plugin_get_library_path(pkg_type, package_path) ==
	    PKGMGR_R_OK) {
		plugin_set = _pkg_plugin_load_library(pkg_type, package_path);
		if (plugin_set == NULL) {
			_LOGE("can not load library \n");
			return NULL;
		}
	} else {
		_LOGE("can not find path \n");
		return NULL;
	}

	return plugin_set;
}

typedef struct _detail_info_map_t {
	char *name;
	void *field;
	char *type;
} detail_info_map_t;

/*
	typedef struct _package_manager_pkg_detail_info_t {
		char pkg_type[PKG_TYPE_STRING_LEN_MAX];
		char pkg_name[PKG_NAME_STRING_LEN_MAX];
		char version[PKG_VERSION_STRING_LEN_MAX];
		char pkg_description[PKG_VALUE_STRING_LEN_MAX];
		char min_platform_version[PKG_VERSION_STRING_LEN_MAX];
		time_t installed_time;	
		int installed_size;
		int app_size;
		int data_size;
		char optional_id[PKG_NAME_STRING_LEN_MAX];
		void *pkg_optional_info;
	} package_manager_pkg_detail_info_t;
*/

static package_manager_pkg_detail_info_t tmp_pkg_detail_info;

static detail_info_map_t info_map[] = {
	{"pkg_type", tmp_pkg_detail_info.pkg_type, "string"},
	{"pkg_name", tmp_pkg_detail_info.pkg_name, "string"},
	{"version", tmp_pkg_detail_info.version, "string"},
	{"pkg_description", tmp_pkg_detail_info.pkg_description, "string"},
	{"min_platform_version", tmp_pkg_detail_info.min_platform_version,
	 "string"},
	{"installed_time", &tmp_pkg_detail_info.installed_time, "time_t"},
	{"installed_size", &tmp_pkg_detail_info.installed_size, "int"},
	{"app_size", &tmp_pkg_detail_info.app_size, "int"},
	{"data_size", &tmp_pkg_detail_info.data_size, "int"},
	{"optional_id", tmp_pkg_detail_info.optional_id, "string"}
};

char *_get_info_string(const char *key,
		       const package_manager_pkg_detail_info_t *
		       pkg_detail_info)
{
	detail_info_map_t *tmp;
	int i = 0;

	if (pkg_detail_info == NULL)
		return NULL;

	memcpy(&tmp_pkg_detail_info, pkg_detail_info,
	       sizeof(package_manager_pkg_detail_info_t));
	
	for (i = 0; i < sizeof(info_map) / sizeof(detail_info_map_t); i++) {
		tmp = &info_map[i];
		if (strcmp(key, tmp->name) == 0) {
			if (strcmp(tmp->type, "string") == 0) {
				return strdup((char *)(tmp->field));
			} else if (strcmp(tmp->type, "bool") == 0) {
				char temp[PKG_VALUE_STRING_LEN_MAX];
				snprintf(temp, PKG_VALUE_STRING_LEN_MAX - 1, 
					"%d", (int)*(bool *) (tmp->field));
				return strdup(temp);
			} else if (strcmp(tmp->type, "int") == 0) {
				char temp[PKG_VALUE_STRING_LEN_MAX];
				snprintf(temp, PKG_VALUE_STRING_LEN_MAX - 1, 
					"%d", (int)*(int *)(tmp->field));
				return strdup(temp);
			} else if (strcmp(tmp->type, "time_t") == 0) {
				char temp[PKG_VALUE_STRING_LEN_MAX];
				snprintf(temp, PKG_VALUE_STRING_LEN_MAX - 1, 
					"%d", (int)*(time_t *) (tmp->field));
				return strdup(temp);
			} else
				return NULL;
		}
	}
	return NULL;
}

int _get_info_int(const char *key,
		  const package_manager_pkg_detail_info_t *pkg_detail_info)
{
	detail_info_map_t *tmp;
	int i = 0;

	if (pkg_detail_info == NULL)
		return -1;

	memcpy(&tmp_pkg_detail_info, pkg_detail_info,
	       sizeof(package_manager_pkg_detail_info_t));
	for (i = 0; i < sizeof(info_map) / sizeof(detail_info_map_t); i++) {
		tmp = &info_map[i];
		if (strcmp(key, tmp->name) == 0) {
			if (strcmp(tmp->type, "int") == 0) {
				return (int)*(int *)(tmp->field);
			} else
				return -1;
		}
	}
	return -1;
}

time_t _get_info_time(const char *key,
		      const package_manager_pkg_detail_info_t *pkg_detail_info)
{
	detail_info_map_t *tmp;
	int i = 0;

	if (pkg_detail_info == NULL)
		return -1;

	memcpy(&tmp_pkg_detail_info, pkg_detail_info,
	       sizeof(package_manager_pkg_detail_info_t));
	for (i = 0; i < sizeof(info_map) / sizeof(detail_info_map_t); i++) {
		tmp = &info_map[i];
		if (strcmp(key, tmp->name) == 0) {
			if (strcmp(tmp->type, "time_t") == 0) {
				return (time_t) *(time_t *) (tmp->field);
			} else
				return (time_t) -1;
		}
	}
	return (time_t) -1;
}

