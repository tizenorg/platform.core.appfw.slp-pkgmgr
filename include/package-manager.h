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
 * @file		package-manager.h
 * @author		Sewook Park <sewook7.park@samsung.com>
 * @version		0.1
 * @brief		This file declares API of slp-pkgmgr library
 *
 * @addtogroup APPLICATION_FRAMEWORK
 * @{
 *
  * @defgroup	PackageManager
 * @section		Header to use them:
 * @code
 * #include "package-manager.h"
 * @endcode
 *
 * @addtogroup PackageManager
 * @{
 */

#ifndef __PKG_MANAGER_H__
#define __PKG_MANAGER_H__

#include <errno.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEPRECATED
#define DEPRECATED	__attribute__ ((__deprecated__))
#endif

/**
 * @mainpage
 * 
 * This is package manager
 *
 * Packaeg manager is used to install/uninstall the packages.\n
 * package includes dpkg, java, widget, etc. and it can be added\n
 * Security is considered on current package manager\n
 * 
 */

/**
 * @file	package-manager.h
 * @brief Package Manager header
 *
 * Generated by    Sewook Park <sewook7.park@samsung.com>
 */



/**
 * @addtogroup PackageManager
 * @{
 */

/**
 * @brief pkgmgr info types. 
 */
#define PKGMGR_INFO_STR_PKGTYPE		"pkg_type"
#define PKGMGR_INFO_STR_PKGNAME		"pkg_name"
#define PKGMGR_INFO_STR_VERSION		"version"
#define PKGMGR_INFO_STR_INSTALLED_SIZE	"installed_size"
#define PKGMGR_INFO_STR_DATA_SIZE	"data_size"
#define PKGMGR_INFO_STR_APP_SIZE	"app_size"
#define PKGMGR_INFO_STR_INSTALLED_TIME	"installed_time"
/** @} */


/**
 * @brief Return values in pkgmgr. 
 */
typedef enum _pkgmgr_return_val {
	PKGMGR_R_ETIMEOUT = -4,		/**< Timeout */
	PKGMGR_R_EINVAL = -3,		/**< Invalid argument */
	PKGMGR_R_ECOMM = -2,		/**< Comunication Error */
	PKGMGR_R_ERROR = -1,		/**< General error */
	PKGMGR_R_OK = 0			/**< General success */
} pkgmgr_return_val;
/** @} */

/**
 * @defgroup pkg_operate	APIs to install /uninstall / activate application
 * @ingroup pkgmgr
 * @brief
 *	APIs to install /uninstall / activate application 
 *	- Install application using application package filepath
 *	- Uninstall application using application package name
 *	- Activate application using application package name
 *
 */


/**
 * @addtogroup pkg_operate
 * @{
 */

typedef void* pkgmgr_pkginfo_h;
typedef void* pkgmgr_appinfo_h;

typedef int (*pkgmgr_iter_fn)(const char* pkg_type, const char* pkg_name,
				const char* version, void *data);

typedef int (*pkgmgr_handler)(int req_id, const char *pkg_type,
				const char *pkg_name, const char *key,
				const char *val, const void *pmsg, void *data);

typedef int (*pkgmgr_info_app_list_cb ) (const pkgmgr_appinfo_h handle,
				const char *appid, void *user_data);


typedef void pkgmgr_client;

typedef enum {
	PC_REQUEST = 0,
	PC_LISTENING,
	PC_BROADCAST,
}client_type;

typedef enum {
	PM_DEFAULT,
	PM_QUIET
}pkgmgr_mode;

typedef enum {
	PM_LOCATION_INTERNAL = 0,
	PM_LOCATION_EXTERNAL
}pkgmgr_install_location;

typedef enum {
	PM_UI_APP,
	PM_SVC_APP
}pkgmgr_app_component;

/**
 * @brief	This API creates pkgmgr client.
 *
 * This API is for package-manager client application.\n
 *  
 * @param[in]	ctype	client type - PC_REQUEST, PC_LISTENING, PC_BROADCAST 
 * @return	pkgmgr_client object
 * @retval	NULL	on failure creating an object
*/
pkgmgr_client *pkgmgr_client_new(client_type ctype);

/**
 * @brief	This API deletes pkgmgr client.
 *
 * This API is for package-manager client application.\n
 *  
 * @param[in]	pc	pkgmgr_client
 * @return	Operation result;
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR	internal error
*/
int pkgmgr_client_free(pkgmgr_client *pc);

/**
 * @brief	This API installs package.
 *
 * This API is for package-manager client application.\n
 * 
 * @param[in]	pc	pkgmgr_client 
 * @param[in]	pkg_type		package type 
 * @param[in]	descriptor_path	full path that descriptor is located
 * @param[in]	pkg_path		full path that package file is located
 * @param[in]	optional_file	optional file which is used for installation
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_install(pkgmgr_client *pc, const char *pkg_type,
			    const char *descriptor_path, const char *pkg_path,
			    const char *optional_file, pkgmgr_mode mode,
			    pkgmgr_handler event_cb, void *data);

/**
 * @brief	This API uninstalls package.
 *
 * This API is for package-manager client application.\n
 * 
 * @param[in]	pc	pkgmgr_client 
 * @param[in]	pkg_type		package type 
 * @param[in]	pkg_name	package name
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @return	request_id (>0), error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkg_name, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data);

/**
 * @brief	This API activates package.
 *
 * This API is for package-manager client application.\n
 * 
 * @param[in]	pc	pkgmgr_client 
 * @param[in]	pkg_type		package type 
 * @param[in]	pkg_name	package name
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_activate(pkgmgr_client *pc, const char *pkg_type,
				const char *pkg_name);

/**
 * @brief	This API deactivates package.
 *
 * This API is for package-manager client application.\n
 * 
 * @param[in]	pc	pkgmgr_client 
 * @param[in]	pkg_type		package type 
 * @param[in]	pkg_name	package name
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkg_name);

/**
 * @brief	This API deletes application's private data.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkg_name	package name
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				const char *pkg_name, pkgmgr_mode mode);

/**
 * @brief	This API request to listen the pkgmgr's broadcasting
 *
 * This API is for package-manager client application.\n
 * 
 * @param[in]	pc	pkgmgr_client 
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
*/
int pkgmgr_client_listen_status(pkgmgr_client *pc, pkgmgr_handler event_cb,
				    void *data);

/**
 * @brief	This API broadcasts pkgmgr's status
 *
 * This API is for package-manager client application.\n
 * 
 * @param[in]	pc	pkgmgr_client 
 * @param[in]	pkg_type		package type 
 * @param[in]	pkg_name	package name
 * @param[in]	key		key to broadcast
 * @param[in]	val		value to broadcast
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
*/
int pkgmgr_client_broadcast_status(pkgmgr_client *pc, const char *pkg_type,
					 const char *pkg_name,  const char *key,
					 const char *val);

/**
 * @brief	This API provides package list
 *
 * This API is for package-manager client application.\n
 * 
 * @param[in]	iter_fn	iteration function for list 
 * @param[in]	data		user data
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR	internal error
*/
int pkgmgr_get_pkg_list(pkgmgr_iter_fn iter_fn, void *data);
/** @} */

/**
 * @defgroup pkg_list		APIs to get package information
 * @ingroup pkgmgr
 * @brief
 *	API to get package information
*/

/**
 * @addtogroup pkg_list
 * @{
 */
 
typedef void pkgmgr_info;

/**
 * @brief	This API  gets the package's information.
 *
 *              This API is for package-manager client application.\n
 * 
 * @param[in]	pkg_type		package type for the package to get infomation
 * @param[in]	pkg_name	package name for the package to get infomation
 * @return	package entry pointer if success, NULL if fail\n
*/
pkgmgr_info * pkgmgr_info_new(const char *pkg_type, const char *pkg_name);

/**
 * @brief	This API  gets the package's information.
 *
 *              This API is for package-manager client application.\n
 * 
 * @param[in]	pkg_type		package type for the package to get infomation
 * @param[in]	pkg_path		package file path to get infomation
 * @return	package entry pointer if success, NULL if fail\n
*/
pkgmgr_info * pkgmgr_info_new_from_file(const char *pkg_type,
					     const char *pkg_path);

/**
 * @brief	This API  get package information value
 *
 *              This API is for package-manager client application.\n
 * 
 * @param[in]	pkg_info	pointer for package info entry
 * @param[in]	key				key for package info field
 * @return	string value if success, NULL if fail\n
*/
char * pkgmgr_info_get_string(pkgmgr_info * pkg_info, const char *key);

/**
 * @brief	This API  get package information value
 *
 *              This API is for package-manager client application.\n
 * 
 * @param[in]	pkg_info			pointer for package info entry
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_info_free(pkgmgr_info * pkg_info);

/**
 * @brief	This API  get package info entry from db
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	pkg_name			pointer to package name
 * @param[out]	handle				pointer to the package info handle.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo(const char *pkg_name, pkgmgr_pkginfo_h *handle);

/**
 * @brief	This API  gets type of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	type				to hold package type.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_type(pkgmgr_pkginfo_h handle, char **type);

/**
 * @brief	This API  gets version  of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	version				to hold package version.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_version(pkgmgr_pkginfo_h handle, char **version);

/**
 * @brief	This API  gets install location of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	location			to hold install location.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_install_location(pkgmgr_pkginfo_h handle, pkgmgr_install_location *location);

/**
 * @brief	This API gets label of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	label				to hold package label.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_label(pkgmgr_pkginfo_h handle, char **label);

/**
 * @brief	This API gets icon of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	icon				to hold package icon.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_icon(pkgmgr_pkginfo_h handle, char **icon);

/**
 * @brief	This API gets desription of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	description			to hold package description.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_descriptioon(pkgmgr_pkginfo_h handle, char **description);

/**
 * @brief	This API gets author's name of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	author_name			to hold author's name.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_author_name(pkgmgr_pkginfo_h handle, char **author_name);

/**
 * @brief	This API gets author's email of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	author_email			to hold author's email id.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_author_email(pkgmgr_pkginfo_h handle, char **author_email);

/**
 * @brief	This API gets author's href of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	author_href			to hold author's href.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_author_href(pkgmgr_pkginfo_h handle, char **author_href);

/**
 * @brief	This API gets removable of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	removable			to hold removable value.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_removable(pkgmgr_pkginfo_h handle, bool *removable);

/**
 * @brief	This API gets preload of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	preload				to hold preload value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_preload(pkgmgr_pkginfo_h handle, bool *preload);

/**
 * @brief	This API gets readonly value of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[out]	readonly				to hold readonly value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_readonly(pkgmgr_pkginfo_h handle, bool *readonly);

/**
 * @brief	This API gets list of ui-application/service application of the given package.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @param[in]	component		application component type.
 * @param[in]	app_func			application's callback function.
 * @param[in]	user_data			user data to be passed to callback function
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_info_app(pkgmgr_pkginfo_h handle, pkgmgr_app_component component,
							pkgmgr_info_app_list_cb app_func, void *user_data);

/**
 * @brief	This API gets list of installed applications.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	iter_fn	iteration function for list
 * @param[in]	user_data			user data to be passed to callback function
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_info_list(pkgmgr_iter_fn iter_fn, void *user_data);


/**
 * @brief	This API destroy the pacakge info handle
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to package info handle
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_destroy_pkginfo(pkgmgr_pkginfo_h handle);

/**
 * @brief	This API gets application info entry from db.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	appid				application id
 * @param[out]	handle				pointer to app info handle
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_appinfo(const char *appid, pkgmgr_appinfo_h *handle);

/**
 * @brief	This API gets exec of the given appid.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to app info handle
 * @param[out]	exec				to hold exec value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_exec(pkgmgr_appinfo_h  handle, char **exec);

/**
 * @brief	This API gets component type of the given appid.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to app info handle
 * @param[out]	component				to hold component value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_component(pkgmgr_appinfo_h  handle, char **component);

/**
 * @brief	This API gets app type of the given appid.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to app info handle
 * @param[out]	app_type			to hold the apptype.
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_apptype(pkgmgr_appinfo_h  handle, char **app_type);

/**
 * @brief	This API gets nodisplay value of the given appid.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to app info handle
 * @param[out]	nodisplay			to hold the nodisplay value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_nodisplay(pkgmgr_appinfo_h  handle, bool *nodisplay);

/**
 * @brief	This API gets multiple value of the given appid.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to app info handle
 * @param[out]	multiple			to hold the multiple value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_multiple(pkgmgr_appinfo_h  handle, bool *multiple);

/**
 * @brief	This API gets taskmanage value of the given appid.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to app info handle
 * @param[out]	taskmanage			to hold the taskmanage value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_taskmanage(pkgmgr_appinfo_h  handle, bool *taskmanage);

/**
 * @brief	This API gets onboot value of the given appid.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to app info handle
 * @param[out]	onboot			to hold the onboot value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_onboot(pkgmgr_appinfo_h  handle, bool *onboot);

/**
 * @brief	This API gets autorestart value of the given appid.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to app info handle
 * @param[out]	autorestart			to hold the autorestart value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_get_pkginfo_autorestart(pkgmgr_appinfo_h  handle, bool *autorestart);

/**
 * @brief	This API destroy the appinfo handle.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to app info handle
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_destroy_appinfo(pkgmgr_appinfo_h  handle);
/** @} */

#ifdef __cplusplus
}
#endif
#endif				/* __PKG_MANAGER_H__ */
/**
 * @}
 * @}
 */

