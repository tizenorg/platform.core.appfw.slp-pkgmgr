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


#include <sys/types.h>

#ifndef __PKGMGR_INSTALLER_H__
#define __PKGMGR_INSTALLER_H__

/**
 * @file pkgmgr_installer.h
 * @author Youmin Ha <youmin.ha@samsung.com>
 * @version 0.1
 * @brief    This file declares API of pkgmgr_installer
 */

#ifdef __cplusplus
extern "C" {
#endif


/**
 * pkgmgr_installer is an opaque type for an object
 */
typedef struct pkgmgr_installer pkgmgr_installer;
typedef void* pkgmgr_instcertinfo_h;

/**
 * @brief listening event type in pkgmgr.
 */
#define PKGMGR_INSTALLER_START_KEY_STR           "start"
#define PKGMGR_INSTALLER_END_KEY_STR             "end"
#define PKGMGR_INSTALLER_ERROR_KEY_STR           "error"
#define PKGMGR_INSTALLER_APPID_KEY_STR           "appid"
#define PKGMGR_INSTALLER_INSTALL_PERCENT_KEY_STR "install_percent"
#define PKGMGR_INSTALLER_GET_SIZE_KEY_STR        "get_size"

#define PKGMGR_INSTALLER_INSTALL_EVENT_STR       "install"
#define PKGMGR_INSTALLER_UNINSTALL_EVENT_STR     "uninstall"
#define PKGMGR_INSTALLER_MOVE_EVENT_STR          "move"
#define PKGMGR_INSTALLER_UPGRADE_EVENT_STR       "update"
#define PKGMGR_INSTALLER_OK_EVENT_STR            "ok"
#define PKGMGR_INSTALLER_FAIL_EVENT_STR          "fail"




/**
 * Request type.
 */
enum {
	PKGMGR_REQ_PERM = -1,
	PKGMGR_REQ_INVALID = 0,
	PKGMGR_REQ_INSTALL = 1,
	PKGMGR_REQ_UNINSTALL = 2,
	PKGMGR_REQ_CLEAR = 3,
	PKGMGR_REQ_MOVE = 4,
	PKGMGR_REQ_RECOVER = 5,
	PKGMGR_REQ_REINSTALL = 6,
	PKGMGR_REQ_GETSIZE = 7,
	PKGMGR_REQ_UPGRADE = 8,
	PKGMGR_REQ_SMACK = 9,
#if 0//#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	/*TODO(jungh.yeon): for TEP only installation. This will be added later*/
	PKGMGR_REQ_INSTALL_TEP,
#endif

};

enum {
	PKGMGR_INSTALLER_EINVAL = -2,		/**< Invalid argument */
	PKGMGR_INSTALLER_ERROR = -1,		/**< General error */
	PKGMGR_INSTALLER_EOK = 0			/**< General success */
};


typedef enum {
	PM_SET_AUTHOR_ROOT_CERT = 0,
	PM_SET_AUTHOR_INTERMEDIATE_CERT = 1,
	PM_SET_AUTHOR_SIGNER_CERT = 2,
	PM_SET_DISTRIBUTOR_ROOT_CERT = 3,
	PM_SET_DISTRIBUTOR_INTERMEDIATE_CERT = 4,
	PM_SET_DISTRIBUTOR_SIGNER_CERT = 5,
	PM_SET_DISTRIBUTOR2_ROOT_CERT = 6,
	PM_SET_DISTRIBUTOR2_INTERMEDIATE_CERT = 7,
	PM_SET_DISTRIBUTOR2_SIGNER_CERT = 8,
}pkgmgr_instcert_type;


/**
 * @brief	Create a pkgmgr_installer object.
 * @pre		None
 * @post	pkgmgr_installer object must be freed.
 * @see		pkgmgr_installer_free
 * @return	pkgmgr_installer object
 * @retval	NULL	on failure creating an object
 * @remark	None
@code
#include <pkgmgr_installer.h>
pkgmgr_installer *pi = pkgmgr_installer_new();
pkgmgr_installer_free(pi);
@endcode
 */
pkgmgr_installer *pkgmgr_installer_new(void);

/**
	@brief		Free a pkgmgr_installer object
	@pre		pi must be a valid object.
	@post		None
	@see		pkgmgr_installer_new
	@param[in]	pi	A pkgmgr_installer object
	@return		Operation result
	@retval		0	on success
	@retval		-errno	on error
	@remark		None
	@code
#include <pkgmgr_installer.h>
pkgmgr_installer *pi = pkgmgr_installer_new();
pkgmgr_installer_free(pi);
	@endcode
 */
int pkgmgr_installer_free(pkgmgr_installer *pi);

/**
	@brief		Receive a request from argv
	@pre		None
	@post		pkgmgr_installer_get_*(), pkgmgr_installer_is_quiet() can be called.
	@see		pkgmgr_installer_get_request_type, pkgmgr_installer_get_request_info, pkgmgr_installer_get_session_id, pkgmgr_installer_is_quiet
	@param[in]	pi	a pkgmgr_installer object
	@param[in]	argc	argc from system
	@param[in]	argv	argv from system
	@return		Operation result
	@retval		0 on success
	@retval		-errno on failure
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r;

	pi = pkgmgr_installer_new();
	int r = pkgmgr_installer_receive_request(pi, argc, argv);
	pkgmgr_installer_free(pi);

	return 0;
}
	@endcode
 */
int pkgmgr_installer_receive_request(pkgmgr_installer *pi,
				     const int argc, char **argv);

/**
	@brief		Get request type
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Request type (One of PKGMGR_REQ_* enum values)
	@remark		None
	@code
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}

	switch(pkgmgr_installer_get_request_type(pi)) {
		case PKGMGR_REQ_PERM:
			// Do error processing
			break;
		case PKGMGR_REQ_INVALID:
			// Do error processing
			r = -1;
			break;
		case PKGMGR_REQ_INSTALL:
			// Do install processing
			break;
		case PKGMGR_REQ_UNINSTALL:
			// Do uninstall processing
			break;
		case PKGMGR_REQ_RECOVER:
			// Do recovere processing
			break;
		case PKGMGR_REQ_REINSTALL:
			// Do reinstall processing
			break;
		default:
			goto CLEANUP_END;
	}
CLEANUP_END:
	pkgmgr_installer_free(pi);

	return r;
}
	@endcode
 */
int pkgmgr_installer_get_request_type(pkgmgr_installer *pi);

/**
	@brief		Get request info
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Request info. When PKGMGR_REQ_INSTALL, this is a package file path to be installed. When PKGMGR_REQ_UNINSTALL, this is a package name to be uninstalled.
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *req_info = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	req_info = (char *) pkgmgr_installer_get_request_info(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
const char *pkgmgr_installer_get_request_info(pkgmgr_installer *pi);

/**
	@brief		Get TEP path
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		TEP path if exists
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *tep_path = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	tep_path = (char *) pkgmgr_installer_get_tep_path(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
@endcode
 */
const char *pkgmgr_installer_get_tep_path(pkgmgr_installer *pi);

/**
	@brief		Get TEP move type
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		integer value indicates tep move type(0: copy TEP file / 1: move TEP file)
	@retval		0	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int tep_move_type = -1;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	tep_move_type = pkgmgr_installer_get_tep_move_type(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
@endcode
 */
int pkgmgr_installer_get_tep_move_type(pkgmgr_installer *pi);

/**
	@brief		Get session ID for a certain session
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		A session ID
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *session_id = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	session_id = (char *) pkgmgr_installer_get_session_id(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
@endcode
 */
const char *pkgmgr_installer_get_session_id(pkgmgr_installer *pi);

/**
	@brief		Get a license path
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		license path
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *license_path = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	session_id = (char *) pkgmgr_installer_get_license_path(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
@endcode
 */
const char *pkgmgr_installer_get_license_path(pkgmgr_installer *pi);

/**
	@brief		Get a optional data
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		optional data
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *optional_data = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	optional_data = (char *) pkgmgr_installer_get_optional_data(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
@endcode
 */
const char *pkgmgr_installer_get_optional_data(pkgmgr_installer *pi);

/**
	@brief		Get if a request is with quite mode or not
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		0 if a request is not quiet mode
	@retval		1 if a request is quiet mode
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	if(pkgmgr_installer_is_quiet(pi)) {
		// Do quiet mode work...
	} else {
		// Do normal mode work...
	}

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_is_quiet(pkgmgr_installer *pi);

/**
	@brief		Get move type
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		enum value of move type
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	move_type = pkgmgr_installer_get_move_type(pi);

	//Do Something

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_get_move_type(pkgmgr_installer *pi);

/**
	@brief		Get caller package id
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		enum value of move type
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *pkgid = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	pkgid = (char *) pkgmgr_installer_get_caller_pkgid(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
const char *pkgmgr_installer_get_caller_pkgid(pkgmgr_installer *pi);

/**
	@brief		Send a process status signal
	@pre		None
	@post		None
	@see		None
	@param[in]	pi	pkgmgr_installer object
	@param[in]	pkg_type	package type: "deb", "jar", "wgt", ...
	@param[in]	pkgid	package id
	@param[in]	key			Signal key
	@param[in]	val			Signal value
	@return		Operation result
	@retval		0 on success
	@retval		-errno on failure
	@remark		If pkgmgr_installer_receive_request() is not called, the session ID will be null string (=="/0").
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *session_id = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}

	// Do something...
	pkgmgr_installer_send_signal(pi,
	 "deb", "org.tizen.foo", "install_percent", "100");
	// A sample signal

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_send_signal(pkgmgr_installer *pi,
				 const char *pkg_type,
				 const char *pkgid, const char *key,
				 const char *val);

/**
	@brief		Send a signal which indicates application is being uninstalled
	@pre		None
	@post		None
	@see		None
	@param[in]	pi	pkgmgr_installer object
	@param[in]	pkg_type	package type: "deb", "jar", "wgt", ...
	@param[in]	pkgid	package id
	@param[in]	key			Signal key
	@param[in]	val			Signal value
	@return		Operation result
	@retval		0 on success
	@retval		-errno on failure
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *session_id = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}

	// Do something...
	pkgmgr_installer_send_app_uninstall_signal(pi,
	 "tpk", "org.tizen.foo");
	// A sample signal

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_send_app_uninstall_signal(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *val);


/**
 * @brief	This API creates the certinfo handle.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[out]	handle				pointer to cert info handle
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_create_certinfo_set_handle(pkgmgr_instcertinfo_h *handle);

/**
 * @brief	This API sets cert value for corresponding cert type.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to cert info handle
 * @param[in]	cert_type			enum value for certificate type
 * @param[in]	cert_value			certificate value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_set_cert_value(pkgmgr_instcertinfo_h handle, pkgmgr_instcert_type cert_type, char *cert_value);

/**
 * @brief	This API saves cert info in DB.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	pkgid				package ID
 * @param[in]	handle				pointer to cert info handle
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_save_certinfo(const char *pkgid, pkgmgr_instcertinfo_h handle, uid_t uid);

/**
 * @brief	This API destroys cert info handle freeing all resources.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to cert info handle
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_destroy_certinfo_set_handle(pkgmgr_instcertinfo_h handle);

/**
 * @brief	This API deletes cert info from DB. To be used to cleanup info upon pkg uninstallation
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	pkgid				package ID
 * @return	0 if success, error code(<0) if fail\n
*/
 int pkgmgr_installer_delete_certinfo(const char *pkgid);

#ifdef __cplusplus
}
#endif

#endif				/* __PKGMGR_INSTALLER_H__ */

