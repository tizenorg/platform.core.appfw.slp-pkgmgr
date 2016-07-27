/*
 * slp-pkgmgr
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
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


#ifndef __PKGMGR_INSTALLER_INFO_H__
#define __PKGMGR_INSTALLER_INFO_H__

/**
 * @file	pkgmgr_installer_info.h
 * @brief	This file declares API for getting information of pkgmgr_installer
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	Get target_uid for pkg to be installed path
 * @pre		None
 * @post	None
 * @param[out]	uid	user id
 * @return	0 if success, else retrun < 0
 * @code
	#include <pkgmgr_installer_info.h>
	int main()
	{
		uid_t uid;
		if (pkgmgr_installer_info_get_target_uid(&uid) < 0) {
			printf("failed to get target uid\n");
		}
		printf("uid = %d\n", uid);
	}
 * @endcode
 */
int pkgmgr_installer_info_get_target_uid(uid_t *uid);

#ifdef __cplusplus
}
#endif

#endif	/* __PKGMGR_INSTALLER_INFO_H__ */

