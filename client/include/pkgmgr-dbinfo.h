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


/**
 * @file			pkgmgr-dbinfo.h
 * @author		Shobhit Srivastava <shobhit.s@samsung.com>
 * @version		0.1
 * @brief			This file declares db set API for backend installers
 *
 * @addtogroup APPLICATION_FRAMEWORK
 * @{
 *
  * @defgroup	PackageManager
 * @section	Header to use them:
 * @code
 * #include "pkgmgr-dbinfo.h"
 * @endcode
 *
 * @addtogroup PackageManager
 * @{
 */

#ifndef __PKGMGR_DBINFO_H__
#define __PKGMGR_DBINFO_H__

#include <stdbool.h>
#include <tzplatform_config.h>

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEPRECATED
#define DEPRECATED	__attribute__ ((__deprecated__))
#endif

typedef enum {
	PM_INSTALL_INTERNAL = 0,
	PM_INSTALL_EXTERNAL,
} PM_INSTALL_LOCATION;

typedef void *pkgmgr_pkgdbinfo_h;

/**
 * @brief	This API creates package info handle to set info in the db.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		pkgid		package id.
 * @param[in]	uid	the addressee user id of the instruction
 * @param[out]	handle			package info handle.
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_create_pkgdbinfo(const char *pkgid, pkgmgr_pkgdbinfo_h *handle);
int pkgmgr_create_pkgusrdbinfo(const char *pkgid, uid_t uid, pkgmgr_pkgdbinfo_h *handle);
/**
 * @brief	This API sets the package type in DB.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]		type			package type.
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_set_type_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *type);

/**
 * @brief	This API sets the package version in DB.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]		version		package version.
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_set_version_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *version);

/**
 * @brief	This API sets install location in DB
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]		location		install location.
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_set_install_location_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, PM_INSTALL_LOCATION location);

/**
 * @brief	This API sets package size in DB
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]		size		package size.
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_set_size_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *size);

/**
 * @brief	This API sets label in DB.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]		label			label text.
 * @param[in]		locale		locale (NULL for default).
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_set_label_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *label, const char *locale);

/**
 * @brief	This API sets icon in DB.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]		icon			icon name.
 * @param[in]		locale		locale (NULL for default).
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_set_icon_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *icon, const char *locale);

/**
 * @brief	This API sets description in DB.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]		description	description of the package.
 * @param[in]		locale		locale (NULL for default).
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_set_description_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *description, const char *locale);

/**
 * @brief	This API sets author's name, email, href in DB.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]		author_name	author' name.
 * @param[in]		author_email	author's email.
 * @param[in]		author_href	author's href.
 * @param[in]		locale		locale (NULL for default).
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_set_author_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, const char *author_name,
			const char *author_email, const char *author_href, const char *locale);

/**
 * @brief	This API sets removable in DB.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]		removable	removable (0 | 1)
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_set_removable_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, int removable);

/**
 * @brief	This API sets preload in DB.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]		preload		preload (0 | 1)
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_set_preload_to_pkgdbinfo(pkgmgr_pkgdbinfo_h handle, int preload);

/**
 * @brief	This API save pakage info entry into the db.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @param[in]	uid	the addressee user id of the instruction
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_save_pkgdbinfo(pkgmgr_pkgdbinfo_h handle);
int pkgmgr_save_pkgusrdbinfo(pkgmgr_pkgdbinfo_h handle, uid_t uid);

/**
 * @brief	This API destroy pakage info handle and free the resources.
 *
 *              This API is for backend installers.\n
 *
 * @param[in]		handle		package info handle.
 * @return		0 if success, error code(<0) if fail\n
*/
int pkgmgr_destroy_pkgdbinfo(pkgmgr_pkgdbinfo_h handle);

#ifdef __cplusplus
}
#endif
#endif		/* __PKGMGR_DBINFO_H__ */
/**
 * @}
 * @}
 */

