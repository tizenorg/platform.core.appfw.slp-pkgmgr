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
#include "pkgmgr-dbinfo.h"
#include <pkgmgr-info.h>

API int pkgmgr_create_pkgdbinfo(const char *pkgid, pkgmgr_pkgdbinfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_create_pkgdbinfo(pkgid, handle);
	return ret;
}
API int pkgmgr_create_pkgusrdbinfo(const char *pkgid, uid_t uid, pkgmgr_pkgdbinfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_create_pkgusrdbinfo(pkgid, uid, handle);
	return ret;
}

API int pkgmgr_set_type_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *type)
{
	int ret = 0;
	ret = pkgmgrinfo_set_type_to_pkgdbinfo(handle, type);
	return ret;
}

API int pkgmgr_set_version_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *version)
{
	int ret = 0;
	ret = pkgmgrinfo_set_version_to_pkgdbinfo(handle, version);
	return ret;
}

API int pkgmgr_set_install_location_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, PM_INSTALL_LOCATION location)
{
	int ret = 0;
	ret = pkgmgrinfo_set_install_location_to_pkgdbinfo(handle, location);
	return ret;
}

API int pkgmgr_set_size_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *size)
{
	int ret = 0;
	ret = pkgmgrinfo_set_size_to_pkgdbinfo(handle, size);
	return ret;
}

API int pkgmgr_set_label_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *label, const char *locale)
{
	int ret = 0;
	ret = pkgmgrinfo_set_label_to_pkgdbinfo(handle, label, locale);
	return ret;
}

API int pkgmgr_set_icon_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *icon, const char *locale)
{
	int ret = 0;
	ret = pkgmgrinfo_set_icon_to_pkgdbinfo(handle, icon, locale);
	return ret;
}

API int pkgmgr_set_description_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *description, const char *locale)
{
	int ret = 0;
	ret = pkgmgrinfo_set_description_to_pkgdbinfo(handle, description, locale);
	return ret;
}

API int pkgmgr_set_author_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *author_name,
			const char *author_email, const char *author_href, const char *locale)
{
	int ret = 0;
	ret = pkgmgrinfo_set_author_to_pkgdbinfo(handle, author_name, author_email, author_href, locale);
	return ret;
}

API int pkgmgr_set_removable_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, int removable)
{
	int ret = 0;
	ret = pkgmgrinfo_set_removable_to_pkgdbinfo(handle, removable);
	return ret;
}

API int pkgmgr_set_preload_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, int preload)
{
	int ret = 0;
	ret = pkgmgrinfo_set_preload_to_pkgdbinfo(handle, preload);
	return ret;
}

API int pkgmgr_save_pkgdbinfo(pkgmgr_pkgdbinfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_save_pkgdbinfo(handle);
	return ret;
}

API int pkgmgr_save_pkgusrdbinfo(pkgmgr_pkgdbinfo_h handle, uid_t uid)
{
	int ret = 0;
	ret = pkgmgrinfo_save_pkgusrdbinfo(handle, uid);
	return ret;
}

API int pkgmgr_destroy_pkgdbinfo(pkgmgr_pkgdbinfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_destroy_pkgdbinfo(handle);
	return ret;
}

