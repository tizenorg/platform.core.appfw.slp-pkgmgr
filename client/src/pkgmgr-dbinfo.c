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
#include <malloc.h>
#include <sys/time.h>

#include "package-manager.h"
#include "package-manager-types.h"
#include "pkgmgr-internal.h"
#include "pkgmgr-api.h"
#include "pkgmgr_parser.h"
#include "pkgmgr-dbinfo.h"

API int pkgmgr_create_pkgdbinfo(const char *pkg_name, pkgmgr_pkgdbinfo_h *handle)
{
	if (!pkg_name || !handle) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	manifest_x *mfx = NULL;
	mfx = calloc(1, sizeof(manifest_x));
	if (!mfx) {
		_LOGE("Malloc Failed\n");
		return PKGMGR_R_ERROR;
	}
	mfx->package = strdup(pkg_name);
	*handle = (void *)mfx;
	return PKGMGR_R_OK;
}

API int pkgmgr_set_type_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *type)
{
	if (!type || !handle) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	int len = strlen(type);
	manifest_x *mfx = (manifest_x *)handle;
	if (len > PKG_TYPE_STRING_LEN_MAX) {
		_LOGE("pkg type length exceeds the max limit\n");
		return PKGMGR_R_EINVAL;
	}
	if (mfx->type == NULL)
		mfx->type = strndup(type, PKG_TYPE_STRING_LEN_MAX);
	else
		mfx->type = type;

	return PKGMGR_R_OK;
}

API int pkgmgr_set_version_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *version)
{
	if (!version || !handle) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	int len = strlen(version);
	manifest_x *mfx = (manifest_x *)handle;
	if (len > PKG_VERSION_STRING_LEN_MAX) {
		_LOGE("pkg version length exceeds the max limit\n");
		return PKGMGR_R_EINVAL;
	}
	if (mfx->version == NULL)
		mfx->version = strndup(version, PKG_VERSION_STRING_LEN_MAX);
	else
		mfx->version = version;

	return PKGMGR_R_OK;
}

API int pkgmgr_set_install_location_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, INSTALL_LOCATION location)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (location < 0 || location > 1) {
		_LOGE("Argument supplied is invalid\n");
		return PKGMGR_R_EINVAL;
	}
	manifest_x *mfx = (manifest_x *)handle;
	if (mfx->installlocation == NULL) {
		mfx->installlocation = (char *)calloc(1, strlen("prefer-external"));
		if (mfx->installlocation == NULL) {
			_LOGE("Malloc Failed\n");
			return PKGMGR_R_ERROR;
		}
	}
	if (location == INSTALL_INTERNAL) {
		strcpy(mfx->installlocation, "internal-only");
	} else if (location == INSTALL_EXTERNAL) {
		strcpy(mfx->installlocation, "prefer-external");
	} else {
		_LOGE("Invalid location type\n");
		return PKGMGR_R_ERROR;
	}
	return PKGMGR_R_OK;
}

API int pkgmgr_set_label_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *label_txt, const char *locale)
{
	if (!handle || !label_txt) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	int len = strlen(label_txt);
	manifest_x *mfx = (manifest_x *)handle;
	if (len > PKG_VALUE_STRING_LEN_MAX) {
		_LOGE("label length exceeds the max limit\n");
		return PKGMGR_R_EINVAL;
	}
	label_x *label = calloc(1, sizeof(label_x));
	if (label == NULL) {
		_LOGE("Malloc Failed\n");
		return PKGMGR_R_ERROR;
	}
	LISTADD(mfx->label, label);
	if (locale)
		mfx->label->lang = strdup(locale);
	else
		mfx->label->lang = strdup(DEFAULT_LOCALE);
	mfx->label->text = strdup(label_txt);

	return PKGMGR_R_OK;
}

API int pkgmgr_set_icon_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *icon_txt, const char *locale)
{
	if (!handle || !icon_txt) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	int len = strlen(icon_txt);
	manifest_x *mfx = (manifest_x *)handle;
	if (len > PKG_VALUE_STRING_LEN_MAX) {
		_LOGE("icon length exceeds the max limit\n");
		return PKGMGR_R_EINVAL;
	}
	icon_x *icon = calloc(1, sizeof(icon_x));
	if (icon == NULL) {
		_LOGE("Malloc Failed\n");
		return PKGMGR_R_ERROR;
	}
	LISTADD(mfx->icon, icon);
	if (locale)
		mfx->icon->lang = strdup(locale);
	else
		mfx->icon->lang = strdup(DEFAULT_LOCALE);
	mfx->icon->text = strdup(icon_txt);

	return PKGMGR_R_OK;
}

API int pkgmgr_set_description_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *desc_txt, const char *locale)
{
	if (!handle || !desc_txt) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	int len = strlen(desc_txt);
	manifest_x *mfx = (manifest_x *)handle;
	if (len > PKG_VALUE_STRING_LEN_MAX) {
		_LOGE("description length exceeds the max limit\n");
		return PKGMGR_R_EINVAL;
	}
	description_x *description = calloc(1, sizeof(description_x));
	if (description == NULL) {
		_LOGE("Malloc Failed\n");
		return PKGMGR_R_ERROR;
	}
	LISTADD(mfx->description, description);
	if (locale)
		mfx->description->lang = strdup(locale);
	else
		mfx->description->lang = strdup(DEFAULT_LOCALE);
	mfx->description->text = strdup(desc_txt);

	return PKGMGR_R_OK;
}

API int pkgmgr_set_author_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *author_name,
										const char *author_email, const char *author_href, const char *locale)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	manifest_x *mfx = (manifest_x *)handle;
	author_x *author = calloc(1, sizeof(author_x));
	if (author == NULL) {
		_LOGE("Malloc Failed\n");
		return PKGMGR_R_ERROR;
	}
	LISTADD(mfx->author, author);
	if (author_name)
		mfx->author->text = strdup(author_name);
	if (author_email)
		mfx->author->email = strdup(author_email);
	if (author_href)
		mfx->author->href = strdup(author_href);
	if (locale)
		mfx->author->lang = strdup(locale);
	else
		mfx->author->lang = strdup(DEFAULT_LOCALE);
	return PKGMGR_R_OK;
}

API int pkgmgr_set_removable_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, int removable)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (removable < 0 || removable > 1) {
		_LOGE("Argument supplied is invalid\n");
		return PKGMGR_R_EINVAL;
	}
	manifest_x *mfx = (manifest_x *)handle;
	if (mfx->removable == NULL) {
		mfx->removable = (char *)calloc(1, strlen("false"));
		if (mfx->removable == NULL) {
			_LOGE("Malloc Failed\n");
			return PKGMGR_R_ERROR;
		}
	}
	if (removable == 0) {
		strcpy(mfx->removable, "false");
	} else if (removable == 1) {
		strcpy(mfx->removable, "true");
	} else {
		_LOGE("Invalid removable type\n");
		return PKGMGR_R_ERROR;
	}
	PKGMGR_R_OK;
}

API int pkgmgr_set_preload_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, int preload)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	if (preload < 0 || preload > 1) {
		_LOGE("Argument supplied is invalid\n");
		return PKGMGR_R_EINVAL;
	}
	manifest_x *mfx = (manifest_x *)handle;
	if (mfx->preload == NULL) {
		mfx->preload = (char *)calloc(1, strlen("false"));
		if (mfx->preload == NULL) {
			_LOGE("Malloc Failed\n");
			return PKGMGR_R_ERROR;
		}
	}
	if (preload == 0) {
		strcpy(mfx->preload, "false");
	} else if (preload == 1) {
		strcpy(mfx->preload, "true");
	} else {
		_LOGE("Invalid preload type\n");
		return PKGMGR_R_ERROR;
	}
	PKGMGR_R_OK;
}

API int pkgmgr_save_pkgdbinfo(pkgmgr_pkgdbinfo_h handle)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	int ret = 0;
	manifest_x *mfx = NULL;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	author_x *tmp4 = NULL;
	mfx = (manifest_x *)handle;
	/*First move to head of all list pointers*/
	if (mfx->label) {
		LISTHEAD(mfx->label, tmp1);
		mfx->label = tmp1;
	}
	if (mfx->icon) {
		LISTHEAD(mfx->icon, tmp2);
		mfx->icon = tmp2;
	}
	if (mfx->description) {
		LISTHEAD(mfx->description, tmp3);
		mfx->description= tmp3;
	}
	if (mfx->author) {
		LISTHEAD(mfx->author, tmp4);
		mfx->author = tmp4;
	}
	ret = pkgmgr_parser_insert_manifest_info_in_db(mfx);
	if (ret == 0) {
		_LOGE("Successfully stored info in DB\n");
		return PKGMGR_R_OK;
	} else {
		_LOGE("Failed to store info in DB\n");
		return PKGMGR_R_ERROR;
	}
}

API int pkgmgr_destroy_pkgdbinfo(pkgmgr_pkgdbinfo_h handle)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	manifest_x *mfx = NULL;
	mfx = (manifest_x *)handle;
	pkgmgr_parser_free_manifest_xml(mfx);
	return PKGMGR_R_OK;
}

