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
 * @file		pkgmgr_parser_db.h
 * @author	Shobhit Srivastava <shobhit.s@samsung.com>
 * @version	0.1
 * @brief		This file declares API to store/retrieve manifest data in DB
 *
 * @addtogroup APPLICATION_FRAMEWORK
 * @{
 *
  * @defgroup	PackageManager
 * @section	Header to use them:
 * @code
 * #include "pkgmgr_parser_db.h"
 * @endcode
 *
 * @addtogroup PackageManager
 * @{
 */

#ifndef __PKGMGR_PARSER_DB_H__
#define __PKGMGR_PARSER_DB_H__

#ifdef __cplusplus
extern "C" {
#endif
#include "pkgmgr_parser.h"

/**
 * @brief				This API insert the parsed manifest info in db.
 *
 * @param[in]	mfx		pointer to manifest info.
 * @return			0 if success, error code(<0) if fail\n
*/
int pkgmgr_parser_insert_manifest_info_in_db(manifest_x *mfx);

/**
 * @brief				This API update the parsed manifest info in db.
 *
 * @param[in]	mfx		pointer to manifest info.
 * @return			0 if success, error code(<0) if fail\n
*/
int pkgmgr_parser_update_manifest_info_in_db(manifest_x *mfx);

/**
 * @brief				This API delete the parsed manifest info from db.
 *
 * @param[in]	mfx		pointer to manifest info.
 * @return			0 if success, error code(<0) if fail\n
*/
int pkgmgr_parser_delete_manifest_info_from_db(manifest_x *mfx);
/** @} */

int pkgmgr_parser_check_and_create_db();
int pkgmgr_parser_initialize_db();

#ifdef __cplusplus
}
#endif
#endif				/* __PKGMGR_PARSER_DB_H__ */
/**
 * @}
 * @}
 */
