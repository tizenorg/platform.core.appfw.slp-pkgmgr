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
#include <stdio.h>
#include <sys/types.h>

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

/**
 * @brief listening status type in pkgmgr.
 */
#define PKGMGR_CLIENT_STATUS_ALL				0x00
#define PKGMGR_CLIENT_STATUS_INSTALL				0x01
#define PKGMGR_CLIENT_STATUS_UNINSTALL				0x02
#define PKGMGR_CLIENT_STATUS_UPGRADE				0x04
#define PKGMGR_CLIENT_STATUS_MOVE				0x08
#define PKGMGR_CLIENT_STATUS_CLEAR_DATA				0x10
#define PKGMGR_CLIENT_STATUS_INSTALL_PROGRESS			0x20
#define PKGMGR_CLIENT_STATUS_GET_SIZE				0x40
#define PKGMGR_CLIENT_STATUS_ENABLE_APP				0x80
#define PKGMGR_CLIENT_STATUS_DISABLE_APP			0x100
#define PKGMGR_CLIENT_STATUS_ENABLE_APP_SPLASH_SCREEN		0x200
#define PKGMGR_CLIENT_STATUS_DISABLE_APP_SPLASH_SCREEN		0x400

/** @} */

/* new common error codes */
/* since 3.0 */
/* TODO(jongmyeong.ko): it should be checked with SDK part if we can define new error in 3.0 */
#define PKGCMD_ERRCODE_UNDEFINED_ERROR (-999)
#define PKGCMD_ERRCODE_UNZIP_ERROR (-23)  /* Unzip error */
#define PKGCMD_ERRCODE_SECURITY_ERROR (-22)  /* Security error */
#define PKGCMD_ERRCODE_REGISTER_ERROR (-21)  /* Register application error */
#define PKGCMD_ERRCODE_PRIVILEGE_ERROR (-20)  /* Privilege error */
#define PKGCMD_ERRCODE_PARSE_ERROR (-19)  /* Parsing error */
#define PKGCMD_ERRCODE_RECOVERY_ERROR (-18)  /* Recovery error */
#define PKGCMD_ERRCODE_DELTA_ERROR (-17)  /* Delta patch error */
#define PKGCMD_ERRCODE_APP_DIR_ERROR (-16)  /* Application directory error */
#define PKGCMD_ERRCODE_CONFIG_ERROR (-15)  /* Configuration error */
#define PKGCMD_ERRCODE_SIGNATURE_ERROR (-14)  /* Signature error */
#define PKGCMD_ERRCODE_SIGNATURE_INVALID (-13)  /* Signature invalid */
#define PKGCMD_ERRCODE_CERT_ERROR (-12)  /* Check certificate error */
#define PKGCMD_ERRCODE_AUTHOR_CERT_NOT_MATCH (-11)  /* Author certificate not match */
#define PKGCMD_ERRCODE_AUTHOR_CERT_NOT_FOUND (-10)  /* Author certificate not found */
#define PKGCMD_ERRCODE_ICON_ERROR (-9)  /* Icon error */
#define PKGCMD_ERRCODE_ICON_NOT_FOUND (-8)  /* Icon not found */
#define PKGCMD_ERRCODE_MANIFEST_ERROR (-7)  /* Manifest error */
#define PKGCMD_ERRCODE_MANIFEST_NOT_FOUND (-6)  /* Manifest not found */
#define PKGCMD_ERRCODE_PACKAGE_NOT_FOUND (-5)  /* Package not found */
#define PKGCMD_ERRCODE_OPERATION_NOT_ALLOWED (-4)  /* Operation not allowed */
#define PKGCMD_ERRCODE_OUT_OF_SPACE (-3)  /* Out of disc space */
#define PKGCMD_ERRCODE_INVALID_VALUE (-2)  /* Invalid argument */
#define PKGCMD_ERRCODE_ERROR (-1)  /* General error */
#define PKGCMD_ERRCODE_OK (0)  /* Success */

#define PKGCMD_ERRCODE_UNZIP_ERROR_STR "Unzip error"
#define PKGCMD_ERRCODE_SECURITY_ERROR_STR "Security error"
#define PKGCMD_ERRCODE_REGISTER_ERROR_STR "Register application error"
#define PKGCMD_ERRCODE_PRIVILEGE_ERROR_STR "Privilege error"
#define PKGCMD_ERRCODE_PARSE_ERROR_STR "Parsing error"
#define PKGCMD_ERRCODE_RECOVERY_ERROR_STR "Recovery error"
#define PKGCMD_ERRCODE_DELTA_ERROR_STR "Delta patch error"
#define PKGCMD_ERRCODE_APP_DIR_ERROR_STR "Application directory error"
#define PKGCMD_ERRCODE_CONFIG_ERROR_STR "Configuration error"
#define PKGCMD_ERRCODE_SIGNATURE_ERROR_STR "Signature error"
#define PKGCMD_ERRCODE_SIGNATURE_INVALID_STR "Signature invalid"
#define PKGCMD_ERRCODE_CERT_ERROR_STR "Check certificate error"
#define PKGCMD_ERRCODE_AUTHOR_CERT_NOT_MATCH_STR "Author certificate not match"
#define PKGCMD_ERRCODE_AUTHOR_CERT_NOT_FOUND_STR "Author certificate not found"
#define PKGCMD_ERRCODE_ICON_ERROR_STR "Icon error"
#define PKGCMD_ERRCODE_ICON_NOT_FOUND_STR "Icon not found"
#define PKGCMD_ERRCODE_MANIFEST_ERROR_STR "Manifest error"
#define PKGCMD_ERRCODE_MANIFEST_NOT_FOUND_STR "Manifest not found"
#define PKGCMD_ERRCODE_PACKAGE_NOT_FOUND_STR "Package not found"
#define PKGCMD_ERRCODE_OPERATION_NOT_ALLOWED_STR "Operation not allowed"
#define PKGCMD_ERRCODE_OUT_OF_SPACE_STR "Out of disc space"
#define PKGCMD_ERRCODE_INVALID_VALUE_STR "Invalid argument"
#define PKGCMD_ERRCODE_ERROR_STR "General error"
#define PKGCMD_ERRCODE_OK_STR "Success"

/* 1 -100 : Package command errors */
/* 101-120 : reserved for Core installer */
/* 121-140 : reserved for Web installer */
/* 141-160 : reserved for Native installer */
#define PKGCMD_ERR_PACKAGE_NOT_FOUND					1
#define PKGCMD_ERR_PACKAGE_INVALID						2
#define PKGCMD_ERR_PACKAGE_LOWER_VERSION				3
#define PKGCMD_ERR_PACKAGE_EXECUTABLE_NOT_FOUND			4
#define PKGCMD_ERR_MANIFEST_NOT_FOUND					11
#define PKGCMD_ERR_MANIFEST_INVALID						12
#define PKGCMD_ERR_CONFIG_NOT_FOUND						13
#define PKGCMD_ERR_CONFIG_INVALID						14
#define PKGCMD_ERR_SIGNATURE_NOT_FOUND					21
#define PKGCMD_ERR_SIGNATURE_INVALID					22
#define PKGCMD_ERR_SIGNATURE_VERIFICATION_FAILED		23
#define PKGCMD_ERR_ROOT_CERTIFICATE_NOT_FOUND			31
#define PKGCMD_ERR_CERTIFICATE_INVALID					32
#define PKGCMD_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED	33
#define PKGCMD_ERR_CERTIFICATE_EXPIRED					34
#define PKGCMD_ERR_INVALID_PRIVILEGE					41
#define PKGCMD_ERR_MENU_ICON_NOT_FOUND					51
#define PKGCMD_ERR_FATAL_ERROR							61
#define PKGCMD_ERR_OUT_OF_STORAGE						62
#define PKGCMD_ERR_OUT_OF_MEMORY						63
#define PKGCMD_ERR_ARGUMENT_INVALID						64

#define PKGCMD_ERR_PACKAGE_NOT_FOUND_STR					"PACKAGE_NOT_FOUND"
#define PKGCMD_ERR_PACKAGE_INVALID_STR						"PACKAGE_INVALID"
#define PKGCMD_ERR_PACKAGE_LOWER_VERSION_STR				"PACKAGE_LOWER_VERSION"
#define PKGCMD_ERR_PACKAGE_EXECUTABLE_NOT_FOUND_STR			"PACKAGE_EXECUTABLE_NOT_FOUND"
#define PKGCMD_ERR_MANIFEST_NOT_FOUND_STR					"MANIFEST_NOT_FOUND"
#define PKGCMD_ERR_MANIFEST_INVALID_STR						"MANIFEST_INVALID"
#define PKGCMD_ERR_CONFIG_NOT_FOUND_STR						"CONFIG_NOT_FOUND"
#define PKGCMD_ERR_CONFIG_INVALID_STR						"CONFIG_INVALID"
#define PKGCMD_ERR_SIGNATURE_NOT_FOUND_STR					"SIGNATURE_NOT_FOUND"
#define PKGCMD_ERR_SIGNATURE_INVALID_STR					"SIGNATURE_INVALID"
#define PKGCMD_ERR_SIGNATURE_VERIFICATION_FAILED_STR		"SIGNATURE_VERIFICATION_FAILED"
#define PKGCMD_ERR_ROOT_CERTIFICATE_NOT_FOUND_STR			"ROOT_CERTIFICATE_NOT_FOUND"
#define PKGCMD_ERR_CERTIFICATE_INVALID_STR					"CERTIFICATE_INVALID"
#define PKGCMD_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED_STR	"CERTIFICATE_CHAIN_VERIFICATION_FAILED"
#define PKGCMD_ERR_CERTIFICATE_EXPIRED_STR					"CERTIFICATE_EXPIRED"
#define PKGCMD_ERR_INVALID_PRIVILEGE_STR					"INVALID_PRIVILEGE"
#define PKGCMD_ERR_MENU_ICON_NOT_FOUND_STR					"MENU_ICON_NOT_FOUND"
#define PKGCMD_ERR_FATAL_ERROR_STR							"FATAL_ERROR"
#define PKGCMD_ERR_OUT_OF_STORAGE_STR						"OUT_OF_STORAGE"
#define PKGCMD_ERR_OUT_OF_MEMORY_STR						"OUT_OF_MEMORY"
#define PKGCMD_ERR_ARGUMENT_INVALID_STR						"ARGUMENT_INVALID"
#define PKGCMD_ERR_UNKNOWN_STR								"Unknown Error"

#define PKG_SIZE_INFO_FILE "/tmp/pkgmgr_size_info.txt"
#define PKG_SIZE_INFO_PATH "/tmp/pkgmgr"

#define PKG_SIZE_INFO_TOTAL "__TOTAL__"
#define PKG_CLEAR_ALL_CACHE "__ALL__"
/**
 * @brief Return values in pkgmgr.
 */
typedef enum _pkgmgr_return_val {
	PKGMGR_R_ESYSTEM = -9,		/**< Severe system error */
	PKGMGR_R_EIO = -8,		/**< IO error */
	PKGMGR_R_ENOMEM = -7,		/**< Out of memory */
	PKGMGR_R_ENOPKG = -6,		/**< No such package */
	PKGMGR_R_EPRIV = -5,		/**< Privilege denied */
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

typedef void pkgmgr_client;
typedef void pkgmgr_info;

typedef struct {
	long long data_size;
	long long cache_size;
	long long app_size;
	long long ext_data_size;
	long long ext_cache_size;
	long long ext_app_size;
} pkg_size_info_t;

typedef int (*pkgmgr_iter_fn)(const char* pkg_type, const char* pkgid,
				const char* version, void *data);

typedef int (*pkgmgr_handler)(uid_t target_uid, int req_id, const char *pkg_type,
				const char *pkgid, const char *key,
				const char *val, const void *pmsg, void *data);

typedef int (*pkgmgr_app_handler)(uid_t target_uid, int req_id, const char *pkg_type,
				const char *pkgid, const char *appid, const char *key,
				const char *val, const void *pmsg, void *data);

typedef void (*pkgmgr_pkg_size_info_receive_cb)(pkgmgr_client *pc, const char *pkgid,
		const pkg_size_info_t *size_info, void *user_data);

typedef void (*pkgmgr_total_pkg_size_info_receive_cb)(pkgmgr_client *pc,
		const pkg_size_info_t *size_info, void *user_data);

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
	PM_MOVE_TO_INTERNAL = 0,
	PM_MOVE_TO_SDCARD = 1,
}pkgmgr_move_type;

typedef enum {
	PM_REQUEST_CSC = 0,
	PM_REQUEST_MOVE = 1,
	PM_REQUEST_GET_SIZE = 2,
	PM_REQUEST_KILL_APP = 3,
	PM_REQUEST_CHECK_APP = 4,
	PM_REQUEST_MAX
}pkgmgr_request_service_type;

typedef enum {
	/* sync, get data, total size for one requested pkgid */
	PM_GET_TOTAL_SIZE = 0,
	PM_GET_DATA_SIZE = 1,

	/* async, get total used storage size */
	PM_GET_ALL_PKGS = 2,

	/* async, get a pkgid's data, total size for all installed pkg */
	PM_GET_SIZE_INFO = 3,

	/* deprecated */
	PM_GET_TOTAL_AND_DATA = 4,
	PM_GET_SIZE_FILE = 5,

	/* async, get data, cache, app size based on "pkg_size_info_t" */
	PM_GET_PKG_SIZE_INFO = 6,
	PM_GET_TOTAL_PKG_SIZE_INFO = 7,
	PM_GET_MAX
} pkgmgr_getsize_type;

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
 * @brief	This API set information to install tep package.
 * @details	Use this API before calling installation API.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	tep_path	full path that tep file is located at
 * @param[in]	tep_move	if TRUE, source file will be moved, else it will be copied
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
*/
int pkgmgr_client_set_tep_path(pkgmgr_client *pc, char *tep_path, char *tep_move);

/**
 * @brief	This API installs package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	descriptor_path	full path that descriptor is located
 * @param[in]	pkg_path		full path that package file is located
 * @param[in]	optional_data	optional data which is used for installation
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
			    const char *optional_data, pkgmgr_mode mode,
			    pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_install(pkgmgr_client *pc, const char *pkg_type,
			    const char *descriptor_path, const char *pkg_path,
			    const char *optional_data, pkgmgr_mode mode,
			    pkgmgr_handler event_cb, void *data, uid_t uid);
/**
 * @brief	This API reinstalls package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkg_path		full path that package file is located
 * @param[in]	optional_data	optional data which is used for installation
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_reinstall(pkgmgr_client *pc, const char *pkg_type, const char *pkgid,
			    const char *optional_data, pkgmgr_mode mode,
			    pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_reinstall(pkgmgr_client * pc, const char *pkg_type, const char *pkgid,
				  const char *optional_data, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data, uid_t uid);
/**
 * @brief	This API uninstalls package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	package id
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @param[in]	uid	the addressee user id of the instruction
 * @return	request_id (>0), error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data, uid_t uid);

/**
 * @brief	This API moves installed package to SD card or vice versa.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	application package id
 * @param[in]	move_type		PM_MOVE_TO_INTERNAL or PM_MOVE_TO_SDCARD
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	uid	the addressee user id of the instruction
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR	general error
*/
int pkgmgr_client_move(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_move_type move_type, pkgmgr_mode mode);
int pkgmgr_client_usr_move(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_move_type move_type, pkgmgr_mode mode, uid_t uid);
/**
 * @brief	This API moves installed package to SD card or vice versa.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	application package id
 * @param[in]	move_type		PM_MOVE_TO_INTERNAL or PM_MOVE_TO_SDCARD
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR	general error
*/
int pkgmgr_client_move_pkg(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_move_type move_type, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data);

/**
 * @brief	This API activates package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	package id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_activate(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid);
int pkgmgr_client_usr_activate(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, uid_t uid);
/**
 * @brief	This API deactivates package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	package id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkgid);
int pkgmgr_client_usr_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkgid, uid_t uid);

/**
 * @brief	This API activates package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @param[in]	argv	argument vector
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_activate_appv(pkgmgr_client * pc, const char *appid, char *const argv[]);
int pkgmgr_client_usr_activate_appv(pkgmgr_client * pc, const char *appid, char *const argv[], uid_t uid);

/**
 * @brief	This API deactivates app.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @param[in]	app_event_cb	user callback
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_deactivate_app(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb);
int pkgmgr_client_usr_deactivate_app(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb, uid_t uid);

/**
 * @brief	This API deactivates global app for user specified by uid.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @param[in]	app_event_cb	user callback
 * @param[in]	uid	user id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_deactivate_global_app_for_uid(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb, uid_t uid);

/**
 * @brief	This API activates app.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @param[in]	app_event_cb	user callback
 * @param[in]	uid	user id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_activate_app(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb);
int pkgmgr_client_usr_activate_app(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb, uid_t uid);

/**
 * @brief	This API activates global app for user specified by uid.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @param[in]	app_event_cb	user callback
 * @param[in]	uid	user id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_activate_global_app_for_uid(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb, uid_t uid);

/**
 * @brief	This API deletes application's private data.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	package id
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				const char *appid, pkgmgr_mode mode);
int pkgmgr_client_usr_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				const char *appid, pkgmgr_mode mode, uid_t uid);
/**
 * @brief	This API set status type to listen for the pkgmgr's broadcasting
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	status_type	status type to listen
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
*/
int pkgmgr_client_set_status_type(pkgmgr_client *pc, int status_type);

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
 * @brief	This API request to listen the pkgmgr's broadcasting about apps
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
int pkgmgr_client_listen_app_status(pkgmgr_client *pc, pkgmgr_app_handler event_cb,
				    void *data);

/**
 * @brief	This API request to stop listen the pkgmgr's broadcasting
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR		internal error
*/
int pkgmgr_client_remove_listen_status(pkgmgr_client *pc);

/**
 * @brief	This API broadcasts pkgmgr's status
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	package id
 * @param[in]	key		key to broadcast
 * @param[in]	val		value to broadcast
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
*/
int pkgmgr_client_broadcast_status(pkgmgr_client *pc, const char *pkg_type,
					 const char *pkgid,  const char *key,
					 const char *val);

/**
 * @brief	This API  gets the package's information.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	pkg_path		package file path to get infomation
 * @return	package entry pointer if success, NULL if fail\n
*/
pkgmgr_info *pkgmgr_client_check_pkginfo_from_file(const char *pkg_path);

/**
 * @brief	This API  get package information value
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	pkg_info			pointer for package info entry
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_client_free_pkginfo(pkgmgr_info * pkg_info);

/**
 * @brief	This API requests service
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	service_type		pkgmgr_request_service_type
 * @param[in]	service_mode 	mode which is used for addtional mode selection
 * @param[in]	pc				pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid			package id
 * @param[in]	custom_info		custom information which is used for addtional information
 * @param[in]	event_cb		user callback
 * @param[in]	data			user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_request_service(pkgmgr_request_service_type service_type, int service_mode,
					pkgmgr_client * pc, const char *pkg_type, const char *pkgid,
					const char *custom_info, pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_request_service(pkgmgr_request_service_type service_type, int service_mode,
					pkgmgr_client * pc, const char *pkg_type, const char *pkgid, uid_t uid,
					const char *custom_info, pkgmgr_handler event_cb, void *data);
/**
 * @brief	This API get package size
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc				pkgmgr_client
 * @param[in]	pkgid			package id
 * @param[in]	get_type		type for pkgmgr client request to get package size
 * @param[in]	event_cb		user callback
 * @param[in]	data			user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_get_size(pkgmgr_client * pc, const char *pkgid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_get_size(pkgmgr_client * pc, const char *pkgid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data, uid_t uid);

/**
 * @brief		Gets the package size information.
 * @details		The package size info is asynchronously obtained by the specified callback function.
 *
 * @param[in] pc		The pointer to pkgmgr_client instance
 * @param[in] pkgid		The package ID
 * @param[in] result_cb	The asynchronous callback function to get the package size information
 * @param[in] user_data	User data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #PKGMGR_R_OK			Successful
 * @retval #PKGMGR_R_EINVAL		Invalid parameter
 * @retval #PKGMGR_R_ERROR		Internal error
 */
int pkgmgr_client_get_package_size_info(pkgmgr_client *pc, const char *pkgid, pkgmgr_pkg_size_info_receive_cb result_cb, void *user_data);
int pkgmgr_client_usr_get_package_size_info(pkgmgr_client *pc, const char *pkgid, pkgmgr_pkg_size_info_receive_cb result_cb, void *user_data, uid_t uid);

/**
 * @brief		Gets the sum of the entire package size information.
 * @details		The package size info is asynchronously obtained by the specified callback function.
 *
 * @param[in] pc		The pointer to pkgmgr_client instance
 * @param[in] result_cb	The asynchronous callback function to get the total package size information
 * @param[in] user_data	User data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #PKGMGR_R_OK			Successful
 * @retval #PKGMGR_R_EINVAL		Invalid parameter
 * @retval #PKGMGR_R_ERROR		Internal error
 */
int pkgmgr_client_get_total_package_size_info(pkgmgr_client *pc, pkgmgr_total_pkg_size_info_receive_cb result_cb, void *user_data);
int pkgmgr_client_usr_get_total_package_size_info(pkgmgr_client *pc, pkgmgr_total_pkg_size_info_receive_cb result_cb, void *user_data, uid_t uid);

/**
 * @brief	This API removes cache directories
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pkgid			package id
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @retval	PKGMGR_R_ERROR	internal error
*/
int pkgmgr_client_clear_cache_dir(const char *pkgid);
int pkgmgr_client_usr_clear_cache_dir(const char *pkgid, uid_t uid);

/**
 * @brief	This API removes all cache directories
 *
 * This API is for package-manager client application.\n
 *
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @retval	PKGMGR_R_ERROR	internal error
*/
int pkgmgr_client_clear_all_cache_dir(void);
int pkgmgr_client_usr_clear_all_cache_dir(uid_t uid);

/**
 * @brief	Generates request for getting license
 *
 * This API generates request for getting license.\n
 *
 * @remarks	You must release @a req_data and @a license_url by yourself.
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	resp_data	The response data string of the purchase request
 * @param[out]	req_data	License request data
 * @param[out]	license_url	License acquisition url data
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV	privilege denied
 * @retval	PKGMGR_R_ESYSTEM	severe system error
 */
int pkgmgr_client_generate_license_request(pkgmgr_client *pc, const char *resp_data, char **req_data, char **license_url);

/**
 * @brief	Registers encrypted license
 *
 * This API registers encrypted license.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	resp_data	The response data string of the purchase request
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @retval	PKGMGR_R_ESYSTEM	severe system error
 */
int pkgmgr_client_register_license(pkgmgr_client *pc, const char *resp_data);

/**
 * @brief	Decrypts contents which is encrypted
 *
 * This API decrypts contents which is encrypted.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	drm_file_path	The pointer to pkgmgr_client instance
 * @param[in]	decrypted_file_path	The pointer to pkgmgr_client instance
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @retval	PKGMGR_R_ESYSTEM	severe system error
 */
int pkgmgr_client_decrypt_package(pkgmgr_client *pc, const char *drm_file_path, const char *decrypted_file_path);

/**
 * @brief	Add a package to blacklist
 *
 * This API adds a package to blacklist.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	pkgid	package id
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 */
int pkgmgr_client_add_blacklist(pkgmgr_client *pc, const char *pkgid);
int pkgmgr_client_usr_add_blacklist(pkgmgr_client *pc, const char *pkgid, uid_t uid);

/**
 * @brief	Remove a package to blacklist
 *
 * This API removes a package to blacklist.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	pkgid	package id
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 */
int pkgmgr_client_remove_blacklist(pkgmgr_client *pc, const char *pkgid);
int pkgmgr_client_usr_remove_blacklist(pkgmgr_client *pc, const char *pkgid, uid_t uid);

/**
 * @brief	Check whether a package is blacklisted
 *
 * This API checks whether the given package is blacklisted.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	pkgid	package id
 * @param[out]	blacklist	whether blacklisted or not
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 */
int pkgmgr_client_check_blacklist(pkgmgr_client *pc, const char *pkgid, bool *blacklist);
int pkgmgr_client_usr_check_blacklist(pkgmgr_client *pc, const char *pkgid, bool *blacklist, uid_t uid);

/**
 * @brief	This API is enabled the splash screen
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK		success
 * @retval	PKGMGR_R_EINVAL		invalid argument
 * @retval	PKGMGR_R_ECOMM		communication error
 * @retval	PKGMGR_R_ENOMEM		out of memory
 */
int pkgmgr_client_enable_splash_screen(pkgmgr_client *pc, const char *appid);
int pkgmgr_client_usr_enable_splash_screen(pkgmgr_client *pc, const char *appid, uid_t uid);

/**
 * @brief	This API is disabled the splash screen
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK		success
 * @retval	PKGMGR_R_EINVAL		invalid argument
 * @retval	PKGMGR_R_ECOMM		communication error
 * @retval	PKGMGR_R_ENOMEM		out of memory
 */
int pkgmgr_client_disable_splash_screen(pkgmgr_client *pc, const char *appid);
int pkgmgr_client_usr_disable_splash_screen(pkgmgr_client *pc, const char *appid, uid_t uid);

/** @} */


#ifdef __cplusplus
}
#endif
#endif				/* __PKG_MANAGER_H__ */
/**
 * @}
 * @}
 */

