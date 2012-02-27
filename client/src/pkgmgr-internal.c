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
#include <stdbool.h>
#include <aul.h>

#include "pkgmgr-internal.h"

#define IS_WHITESPACE(CHAR) \
	((CHAR == ' ' || CHAR == '\t' || CHAR == '\r' || CHAR == '\n') ? \
	true : false)

void _app_str_trim(char *input)
{
	char *trim_str = input;

	if (input == NULL)
		return;

	while (*input != 0) {
		if (!IS_WHITESPACE(*input)) {
			*trim_str = *input;
			trim_str++;
		}
		input++;
	}

	*trim_str = 0;
	return;
}

char *_get_backend_path(const char *input_path)
{
	FILE *fp = NULL;
	char buffer[1024] = { '\0', };
	char *type = NULL;
	char installer_path[PKG_STRING_LEN_MAX] = { '\0', };
	char pkg_path[PKG_STRING_LEN_MAX] = { '\0', };
	char backend_path[PKG_STRING_LEN_MAX] = { '\0', };

	if (strrchr(input_path, '/')) {
		strncpy(pkg_path, strrchr(input_path, '/') + 1,
			PKG_STRING_LEN_MAX - 1);
	} else {
		strncpy(pkg_path, input_path, PKG_STRING_LEN_MAX - 1);
	}

	_LOGD("pkg_path[%s]\n", pkg_path);

	fp = fopen(PKG_CONF_PATH, "r");
	if (fp == NULL) {
		return NULL;
	}

	char *path = NULL;
	while (fgets(buffer, 1024, fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		_app_str_trim(buffer);

		if ((path = strstr(buffer, PKG_BACKEND)) != NULL) {
			_LOGD("[%s]\n", buffer);
			_LOGD("[%s]\n", path);
			path = path + strlen(PKG_BACKEND);
			_LOGD("[%s]\n", path);

			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if (path == NULL)
		return NULL;

/*	if(path[strlen(path)] == '/') */
	snprintf(backend_path, PKG_STRING_LEN_MAX - 1, "%s", path);
/*	else
		sprintf(backend_path, "%s/", path); */

	type = strrchr(pkg_path, '.');
	if (type == NULL)
		type = pkg_path;
	else
		type++;

	snprintf(installer_path, PKG_STRING_LEN_MAX - 1, 
					"%s%s", backend_path, type);

	_LOGD("installer_path[%s]\n", installer_path);

	if (access(installer_path, F_OK) != 0)
		return NULL;

	return strdup(installer_path);
}

char *_get_backend_path_with_type(const char *type)
{
	FILE *fp = NULL;
	char buffer[1024] = { '\0', };
	char installer_path[PKG_STRING_LEN_MAX] = { '\0', };
	char backend_path[PKG_STRING_LEN_MAX] = { '\0', };

	_LOGD("type[%s]\n", type);

	fp = fopen(PKG_CONF_PATH, "r");
	if (fp == NULL) {
		return NULL;
	}

	char *path = NULL;
	while (fgets(buffer, 1024, fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		_app_str_trim(buffer);

		if ((path = strstr(buffer, PKG_BACKEND)) != NULL) {
			_LOGD("[%s]\n", buffer);
			_LOGD("[%s]\n", path);
			path = path + strlen(PKG_BACKEND);
			_LOGD("[%s]\n", path);

			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if(path == NULL)
		return NULL;

/*	if(path[strlen(path)] == '/') */
	snprintf(backend_path, PKG_STRING_LEN_MAX - 1, "%s", path);
/*	else
       sprintf(backend_path, "%s/", path); */

	snprintf(installer_path, PKG_STRING_LEN_MAX - 1, 
					"%s%s", backend_path, type);
	_LOGD("installer_path[%s]\n", installer_path);

	if (access(installer_path, F_OK) != 0) {
		char extlist[256] = { '\0', };
		aul_get_mime_extension(type, extlist, sizeof(extlist));
		_LOGD("extlist[%s]\n", extlist);

		if (strlen(extlist) == 0)
			return NULL;

		if (strchr(extlist, ',')) {
			extlist[strlen(extlist) -
				strlen(strchr(extlist, ','))] = '\0';
		}
		type = strchr(extlist, '.') + 1;

		snprintf(installer_path, PKG_STRING_LEN_MAX - 1, 
						"%s%s", backend_path, type);
	}

	return strdup(installer_path);
}

