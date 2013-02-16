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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <vconf.h>
#include <pkgmgr_parser.h>
#include <pkgmgr-info.h>
#include "package-manager.h"
#include "package-manager-types.h"
#include "pkgmgr-dbinfo.h"
#include "pkgmgr_installer.h"


static void __print_usage();
static int __get_pkg_info(char *pkgid);
static int __get_app_info(char *appid);
static int __get_app_list(char *pkgid);
static int __get_app_category_list(char *appid);
static int __get_app_control_list(char *appid);
static int __get_pkg_list(void);
static int __get_installed_app_list();
static int __add_app_filter(void);
static int __add_pkg_filter(void);
static int __insert_manifest_in_db(char *manifest);
static int __remove_manifest_from_db(char *manifest);
static int __set_pkginfo_in_db(char *pkgid);
static int __set_certinfo_in_db(char *pkgid);
static int __get_certinfo_from_db(char *pkgid);
static int __del_certinfo_from_db(char *pkgid);
static int __get_integer_input_data(void);
char *__get_string_input_data(void);
static int __pkg_list_cb (const pkgmgr_pkginfo_h handle, void *user_data);
static int __app_category_list_cb(const char *category_name, void *user_data);
static int __app_control_list_cb(pkgmgrinfo_appcontrol_h handle, void *user_data);
int app_func(const pkgmgr_appinfo_h handle, void *user_data);

static int __get_integer_input_data(void)
{
	char input_str[32] = { 0, };
	int data = 0;
	fflush(stdin);

	if (fgets(input_str, sizeof(input_str), stdin) == NULL) {
		printf("fgets() failed....\n");
		return -1;
	}

	if (sscanf(input_str, "%d", &data) != 1) {
		printf("Input only integer option....\n");
		return -1;
	}

	return data;
}


char *__get_string_input_data(void)
{
	char *data = (char *)malloc(1024);
	if (data == NULL) {
		printf("Malloc Failed\n");
		return NULL;
	}
	if (fgets(data,1024,stdin) == NULL){
		printf("Buffer overflow!!! try again\n");
		exit(-1);
	}
	data[strlen(data) - 1] = '\0';
	return data;
}

static void __print_usage()
{
	printf("For Getting package|App Info\n");
	printf("\tpkginfo --[pkg|app] <pkgid|appid>\n\n");
	printf("For Getting list of installed packages\n");
	printf("\tpkginfo --listpkg \n\n");
	printf("For Getting list of installed applications\n");
	printf("\tpkginfo --listapp \n\n");
	printf("For Getting app list for a particular package\n");
	printf("\tpkginfo --list <pkgid>\n\n");
	printf("For Getting app category list for a particular application\n");
	printf("\tpkginfo --category <appid>\n\n");
	printf("For Getting app control list for a particular application\n");
	printf("\tpkginfo --appcontrol <appid>\n\n");
	printf("To insert|remove manifest info in DB\n");
	printf("\tpkginfo --[imd|rmd] <manifest file name>\n\n");
	printf("To set pkginfo in DB\n");
	printf("\tpkginfo --setdb <pkgid>\n\n");
	printf("To set manifest validation\n");
	printf("\tpkginfo --check <manifest file name>\n\n");
	printf("To set cert info in DB\n");
	printf("\tpkginfo --setcert <pkgid>\n\n");
	printf("To get cert info from DB\n");
	printf("\tpkginfo --getcert <pkgid>\n\n");
	printf("To delete all cert info from DB\n");
	printf("\tpkginfo --delcert <pkgid>\n\n");
	printf("To add application filter values [Multiple values can be added]\n");
	printf("\tpkginfo --app-flt\n\n");
	printf("To add package filter values [Multiple values can be added]\n");
	printf("\tpkginfo --pkg-flt\n\n");
}

static int __add_app_filter()
{
	int ret = 0;
	int choice = -1;
	char *value = NULL;
	int val = -1;
	int count = 0;
	pkgmgrinfo_appinfo_filter_h handle;
	ret = pkgmgrinfo_appinfo_filter_create(&handle);
	if (ret > 0) {
		printf("appinfo filter handle create failed\n");
		return -1;
	}
	while (choice != 0 && choice != 1)
	{
		printf("Enter Choice\n");
		printf("0  --> Finalize filter and get count of apps\n");
		printf("1  --> Finalize filter and get list of apps\n");
		printf("2  --> filter by app ID\n");
		printf("3  --> filter by app component\n");
		printf("4  --> filter by app exec\n");
		printf("5  --> filter by app icon\n");
		printf("6  --> filter by app type\n");
		printf("7  --> filter by app operation\n");
		printf("8  --> filter by app uri\n");
		printf("9  --> filter by app mime\n");
		printf("10 --> filter by app category\n");
		printf("11 --> filter by app nodisplay [0|1]\n");
		printf("12 --> filter by app multiple [0|1]\n");
		printf("13 --> filter by app onboot [0|1]\n");
		printf("14 --> filter by app autorestart [0|1]\n");
		printf("15 --> filter by app taskmanage [0|1]\n");
		printf("16 --> filter by app hwacceleration\n");
		choice = __get_integer_input_data();
		switch (choice) {
		case 0:
			ret = pkgmgrinfo_appinfo_filter_count(handle, &count);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_count() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				return -1;
			}
			printf("App count = %d\n", count);
			return 0;
		case 1:
			ret = pkgmgrinfo_appinfo_filter_foreach_appinfo(handle, app_func, NULL);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_foreach_appinfo() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				return -1;
			}
			return 0;
		case 2:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_ID, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			break;
		case 3:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_COMPONENT, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			break;
		case 4:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_EXEC, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			break;
		case 5:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_ICON, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			break;
		case 6:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_TYPE, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			break;
		case 7:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_OPERATION, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			break;
		case 8:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_URI, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			break;
		case 9:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_MIME, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			break;
		case 10:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_CATEGORY, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			break;
		case 11:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
				PMINFO_APPINFO_PROP_APP_NODISPLAY, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				return -1;
			}
			break;
		case 12:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
				PMINFO_APPINFO_PROP_APP_MULTIPLE, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				return -1;
			}
			break;
		case 13:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
				PMINFO_APPINFO_PROP_APP_ONBOOT, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				return -1;
			}
			break;
		case 14:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
				PMINFO_APPINFO_PROP_APP_AUTORESTART, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				return -1;
			}
			break;
		case 15:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
				PMINFO_APPINFO_PROP_APP_TASKMANAGE, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				return -1;
			}
			break;
		case 16:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_HWACCELERATION, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			break;
		default:
			printf("Invalid filter property\n");
				pkgmgrinfo_appinfo_filter_destroy(handle);
			return -1;
		}
	}
	pkgmgrinfo_appinfo_filter_destroy(handle);
	ret = 0;
err:
	if (value) {
		free(value);
		value = NULL;
	}
	return ret;
}

static int __add_pkg_filter()
{
	int ret = 0;
	int choice = -1;
	char *value = NULL;
	int val = -1;
	int count = 0;
	pkgmgrinfo_pkginfo_filter_h handle;
	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	if (ret > 0) {
		printf("pkginfo filter handle create failed\n");
		return -1;
	}
	while (choice != 0 && choice !=1)
	{
		printf("Enter Choice\n");
		printf("0  --> Finalize filter and get count of packages\n");
		printf("1  --> Finalize filter and get list of packages\n");
		printf("2  --> filter by package ID\n");
		printf("3  --> filter by package version\n");
		printf("4  --> filter by package type\n");
		printf("5  --> filter by package install location\n");
		printf("6  --> filter by author name\n");
		printf("7  --> filter by author email\n");
		printf("8  --> filter by author href\n");
		printf("9  --> filter by package removable [0|1]\n");
		printf("10 --> filter by package readonly [0|1]\n");
		printf("11 --> filter by package preload [0|1]\n");
		printf("12 --> filter by package size\n");
		choice = __get_integer_input_data();
		switch (choice) {
		case 0:
			ret = pkgmgrinfo_pkginfo_filter_count(handle, &count);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_count() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				return -1;
			}
			printf("Package count = %d\n", count);
			return 0;
		case 1:
			ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __pkg_list_cb, NULL);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_foreach_pkginfo() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				return -1;
			}
			return 0;
		case 2:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_ID, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 3:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_VERSION, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 4:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_TYPE, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 5:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_INSTALL_LOCATION, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 6:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_NAME, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 7:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_EMAIL, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 8:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 9:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_bool(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE, val);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				return -1;
			}
			break;
		case 10:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_bool(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_READONLY, val);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				return -1;
			}
			break;
		case 11:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_bool(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD, val);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				return -1;
			}
			break;
		case 12:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_int(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_SIZE, val);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_int() failed\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				return -1;
			}
			break;
		default:
			printf("Invalid filter property\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
			return -1;
		}
	}
	pkgmgrinfo_pkginfo_filter_destroy(handle);
	ret = 0;
err:
	if (value) {
		free(value);
		value = NULL;
	}
	return ret;
}

static int __del_certinfo_from_db(char *pkgid)
{
	int ret = 0;
	if (pkgid == NULL) {
		printf("pkgid is NULL\n");
		return -1;
	}
	ret = pkgmgr_installer_delete_certinfo(pkgid);
	if (ret < 0) {
		printf("pkgmgr_installer_delete_certinfo failed\n");
		return -1;
	}
	return 0;
}

static int __get_certinfo_from_db(char *pkgid)
{
	if (pkgid == NULL) {
		printf("pkgid is NULL\n");
		return -1;
	}
	int ret = 0;
	int choice = -1;
	int i = 0;
	char *value = NULL;
	pkgmgr_certinfo_h handle = NULL;
	ret = pkgmgr_pkginfo_create_certinfo(&handle);
	if (ret < 0) {
		printf("pkgmgr_pkginfo_create_certinfo failed\n");
		return -1;
	}
	ret = pkgmgr_pkginfo_load_certinfo(pkgid, handle);
	if (ret < 0) {
		printf("pkgmgr_pkginfo_load_certinfo failed\n");
		return -1;
	}
	while (choice != 10)
	{
		printf("Enter the choice to get\n");
		printf("0 --> to get all cert values\n");
		printf("1 --> author root certificate\n");
		printf("2 --> author intermediate certificate\n");
		printf("3 --> author signer certificate\n");
		printf("4 --> distributor root certificate\n");
		printf("5 --> distributor intermediate certificate\n");
		printf("6 --> distributor signer certificate\n");
		printf("7 --> distributor2 root certificate\n");
		printf("8 --> distributor2 intermediate certificate\n");
		printf("9 --> distributor2 signer certificate\n");
		printf("10 --> exit\n");
		choice = __get_integer_input_data();
		switch (choice) {
		case 0:
			for (i = 0; i < 9; i++)
			{
				pkgmgr_pkginfo_get_cert_value(handle, i, &value);
				if (value)
					printf("cert type[%d] value = %s\n", i, value);
			}
			ret = pkgmgr_pkginfo_destroy_certinfo(handle);
			if (ret < 0) {
				printf("pkgmgr_pkginfo_destroy_certinfo failed\n");
				return -1;
			}
			return 0;
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
			ret = pkgmgr_pkginfo_get_cert_value(handle, choice - 1, &value);
			if (value)
				printf("cert type[%d] value = %s\n", choice - 1, value);
			break;
		case 10:
			ret = pkgmgr_pkginfo_destroy_certinfo(handle);
			if (ret < 0) {
				printf("pkgmgr_pkginfo_destroy_certinfo failed\n");
				return -1;
			}
			return 0;
		default:
			printf("Invalid choice entered\n");
			return -1;
		}
	}
	return 0;
}

static int __set_certinfo_in_db(char *pkgid)
{
	if (pkgid == NULL) {
		printf("pkgid is NULL\n");
		return -1;
	}
	int ret = 0;
	int choice = -1;
	char *value = NULL;
	pkgmgr_instcertinfo_h handle = NULL;
	ret = pkgmgr_installer_create_certinfo_set_handle(&handle);
	if (ret < 0) {
		printf("pkgmgr_installer_create_certinfo_set_handle failed\n");
		return -1;
	}
	while (choice != 0)
	{
		printf("Enter the choice you want to set\n");
		printf("0 --> to set data in DB\n");
		printf("1 --> author root certificate\n");
		printf("2 --> author intermediate certificate\n");
		printf("3 --> author signer certificate\n");
		printf("4 --> distributor root certificate\n");
		printf("5 --> distributor intermediate certificate\n");
		printf("6 --> distributor signer certificate\n");
		printf("7 --> distributor2 root certificate\n");
		printf("8 --> distributor2 intermediate certificate\n");
		printf("9 --> distributor2 signer certificate\n");
		choice = __get_integer_input_data();
		switch (choice) {
		case 0:
			ret = pkgmgr_installer_save_certinfo(pkgid, handle);
			if (ret < 0) {
				printf("pkgmgr_installer_save_certinfo failed\n");
				return -1;
			}
			ret = pkgmgr_installer_destroy_certinfo_set_handle(handle);
			if (ret < 0) {
				printf("pkgmgr_installer_destroy_certinfo_set_handle failed\n");
				return -1;
			}
			return 0;
		case 1:
			printf("Enter Author Root Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 0, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				pkgmgr_installer_destroy_certinfo_set_handle(handle);
				return -1;
			}
			break;
		case 2:
			printf("Enter Author Intermediate Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 1, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				pkgmgr_installer_destroy_certinfo_set_handle(handle);
				return -1;
			}
			break;
		case 3:
			printf("Enter Author Signer Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 2, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				pkgmgr_installer_destroy_certinfo_set_handle(handle);
				return -1;
			}
			break;
		case 4:
			printf("Enter Distributor Root Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 3, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				pkgmgr_installer_destroy_certinfo_set_handle(handle);
				return -1;
			}
			break;
		case 5:
			printf("Enter Distributor Intermediate Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 4, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				pkgmgr_installer_destroy_certinfo_set_handle(handle);
				return -1;
			}
			break;
		case 6:
			printf("Enter Distributor Signer Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 5, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				pkgmgr_installer_destroy_certinfo_set_handle(handle);
				return -1;
			}
			break;
		case 7:
			printf("Enter Distributor2 Root Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 6, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				pkgmgr_installer_destroy_certinfo_set_handle(handle);
				return -1;
			}
			break;
		case 8:
			printf("Enter Distributor2 Intermediate Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 7, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				pkgmgr_installer_destroy_certinfo_set_handle(handle);
				return -1;
			}
			break;
		case 9:
			printf("Enter Distributor2 Signer Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 8, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				pkgmgr_installer_destroy_certinfo_set_handle(handle);
				return -1;
			}
			break;
		default:
			printf("Invalid Number Entered\n");
			choice = 0;
			ret = pkgmgr_installer_destroy_certinfo_set_handle(handle);
			if (ret < 0) {
				printf("pkgmgr_installer_destroy_certinfo_set_handle failed\n");
				return -1;
			}
			break;
		}
	}
	return -1;
}

static int __set_pkginfo_in_db(char *pkgid)
{
	if (pkgid == NULL) {
		printf("pkgid is NULL\n");
		return -1;
	}
	int ret = 0;
	int choice = -1;
	int preload = -1;
	int removable = -1;
	int location = -1;
	char *locale = NULL;
	pkgmgr_pkgdbinfo_h handle = NULL;
	ret = pkgmgr_create_pkgdbinfo(pkgid, &handle);
	if (ret < 0) {
		printf("pkgmgr_create_pkgdbinfo failed\n");
		return -1;
	}
	while (choice != 0)
	{
		printf("Enter the choice you want to set\n");
		printf("0 --> to set data in DB\n");
		printf("1 --> pkg type\n");
		printf("2 --> pkg version\n");
		printf("3 --> pkg instal location\n");
		printf("4 --> pkg label\n");
		printf("5 --> pkg icon\n");
		printf("6 --> pkg description\n");
		printf("7 --> pkg author\n");
		printf("8 --> pkg removable\n");
		printf("9 --> pkg preload\n");
		printf("10 --> pkg size\n");
		choice = __get_integer_input_data();
		switch (choice) {
		case 0:
			ret = pkgmgr_save_pkgdbinfo(handle);
			if (ret < 0) {
				printf("pkgmgr_save_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				return -1;
			}
			ret = pkgmgr_destroy_pkgdbinfo(handle);
			if (ret < 0) {
				printf("pkgmgr_destroy_pkgdbinfo failed\n");
				return -1;
			}
			break;
		case 1:
			printf("Enter type: \n");
			char *type = __get_string_input_data();
			ret = pkgmgr_set_type_to_pkgdbinfo(handle, type);
			if (ret < 0) {
				printf("pkgmgr_set_type_to_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				return -1;
			}
			break;
		case 2:
			printf("Enter version: \n");
			char *version = __get_string_input_data();
			ret = pkgmgr_set_version_to_pkgdbinfo(handle, version);
			if (ret < 0) {
				printf("pkgmgr_set_version_to_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				return -1;
			}
			break;
		case 3:
			printf("Enter install location [0:internal | 1:external]: \n");
			location = __get_integer_input_data();
			ret = pkgmgr_set_install_location_to_pkgdbinfo(handle, location);
			if (ret < 0) {
				printf("pkgmgr_set_install_location_to_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				return -1;
			}
			break;
		case 4:
			printf("Enter label :\n");
			char *label = __get_string_input_data();
			printf("Enter locale ['def' for default]: \n");
			locale = __get_string_input_data();
			if (strcmp(locale, "def") == 0)
				ret = pkgmgr_set_label_to_pkgdbinfo(handle, label, NULL);
			else
				ret = pkgmgr_set_label_to_pkgdbinfo(handle, label, locale);
			if (ret < 0) {
				printf("pkgmgr_set_label_to_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				free(locale);
				return -1;
			}
			free(locale);
			break;
		case 5:
			printf("Enter icon: \n");
			char *icon = __get_string_input_data();
			printf("Enter locale ['def' for default]: \n");
			locale = __get_string_input_data();
			if (strcmp(locale, "def") == 0)
				ret = pkgmgr_set_icon_to_pkgdbinfo(handle, icon, NULL);
			else
				ret = pkgmgr_set_icon_to_pkgdbinfo(handle, icon, locale);
			if (ret < 0) {
				printf("pkgmgr_set_icon_to_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				free(locale);
				return -1;
			}
			free(locale);
			break;
		case 6:
			printf("Enter description: \n");
			char *description = __get_string_input_data();
			printf("Enter locale ['def' for default]: \n");
			locale = __get_string_input_data();
			if (strcmp(locale, "def") == 0)
				ret = pkgmgr_set_description_to_pkgdbinfo(handle, description, NULL);
			else
				ret = pkgmgr_set_description_to_pkgdbinfo(handle, description, locale);
			if (ret < 0) {
				printf("pkgmgr_set_description_to_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				free(locale);
				return -1;
			}
			free(locale);
			break;
		case 7:
			printf("Enter author name: \n");
			char *author_name = __get_string_input_data();
			printf("Enter locale ['def' for default]: \n");
			locale = __get_string_input_data();
			printf("Enter author email: \n");
			char *author_email = __get_string_input_data();
			printf("Enter author href: \n");
			char *author_href = __get_string_input_data();
			if (strcmp(locale, "def") == 0)
				ret = pkgmgr_set_author_to_pkgdbinfo(handle, author_name, author_email, author_href, NULL);
			else
				ret = pkgmgr_set_author_to_pkgdbinfo(handle, author_name, author_email, author_href, locale);
			if (ret < 0) {
				printf("pkgmgr_set_author_to_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				free(locale);
				return -1;
			}
			free(locale);
			break;
		case 8:
			printf("Enter removable [0:false | 1:true]: \n");
			removable = __get_integer_input_data();
			ret = pkgmgr_set_removable_to_pkgdbinfo(handle, removable);
			if (ret < 0) {
				printf("pkgmgr_set_removable_to_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				return -1;
			}
			break;
		case 9:
			printf("Enter preload [0:false | 1:true]: \n");
			preload = __get_integer_input_data();
			ret = pkgmgr_set_preload_to_pkgdbinfo(handle, preload);
			if (ret < 0) {
				printf("pkgmgr_set_preload_to_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				return -1;
			}
			break;
		case 10:
			printf("Enter size in MB \n");
			char *size = __get_string_input_data();
			ret = pkgmgr_set_size_to_pkgdbinfo(handle, size);
			if (ret < 0) {
				printf("pkgmgr_set_size_to_pkgdbinfo failed\n");
				pkgmgr_destroy_pkgdbinfo(handle);
				return -1;
			}
			break;
		default:
			printf("Invalid number entered\n");
			continue;
		}
	}
	return 0;
}

static int __insert_manifest_in_db(char *manifest)
{
	int ret = 0;
	if (manifest == NULL) {
		printf("Manifest file is NULL\n");
		return -1;
	}
	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
	if (ret < 0) {
		printf("insert in db failed\n");
		return -1;
	}
	return 0;
}

static int __remove_manifest_from_db(char *manifest)
{
	int ret = 0;
	if (manifest == NULL) {
		printf("Manifest file is NULL\n");
		return -1;
	}
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
	if (ret < 0) {
		printf("remove from db failed\n");
		return -1;
	}
	return 0;
}

int app_func(const pkgmgr_appinfo_h handle, void *user_data)
{
	char *appid;
	char *data = NULL;
	if (user_data) {
		data = (char *)user_data;
	}
	int ret = -1;
	char *exec = NULL;
	char *icon = NULL;
	char *label = NULL;
	pkgmgr_app_component component = 0;
	char *apptype = NULL;
	bool nodisplay = 0;
	bool multiple = 0;
	bool taskmanage = 0;
	int hwacceleration = 0;
	bool onboot = 0;
	bool autorestart = 0;
	char *package = NULL;

	ret = pkgmgr_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		printf("Failed to get appid\n");
	}
	if (appid)
		printf("Appid: %s\n", appid);

	ret = pkgmgr_appinfo_get_pkgid(handle, &package);
	if (ret < 0) {
		printf("Failed to get package\n");
	}
	if (package)
		printf("Package: %s\n", package);

	ret = pkgmgr_appinfo_get_exec(handle, &exec);
	if (ret < 0) {
		printf("Failed to get exec\n");
	}
	if (exec)
		printf("Exec: %s\n", exec);

	ret = pkgmgr_appinfo_get_icon(handle, &icon);
	if (ret < 0) {
		printf("Failed to get icon\n");
	}
	if (icon)
		printf("Icon: %s\n", icon);

	ret = pkgmgr_appinfo_get_label(handle, &label);
	if (ret < 0) {
		printf("Failed to get label\n");
	}
	if (label)
		printf("Label: %s\n", label);

	ret = pkgmgr_appinfo_get_component(handle, &component);
	if (ret < 0) {
		printf("Failed to get component\n");
	}

	ret = pkgmgr_appinfo_get_apptype(handle, &apptype);
	if (ret < 0) {
		printf("Failed to get apptype\n");
	}
	if (apptype)
		printf("Apptype: %s\n", apptype);

	if (component == PM_UI_APP) {
		printf("component: uiapp\n");
		ret = pkgmgr_appinfo_is_multiple(handle, &multiple);
		if (ret < 0) {
			printf("Failed to get multiple\n");
		} else {
			printf("Multiple: %d\n", multiple);
		}

		ret = pkgmgr_appinfo_is_nodisplay(handle, &nodisplay);
		if (ret < 0) {
			printf("Failed to get nodisplay\n");
		} else {
			printf("Nodisplay: %d \n", nodisplay);
		}

		ret = pkgmgr_appinfo_is_taskmanage(handle, &taskmanage);
		if (ret < 0) {
			printf("Failed to get taskmanage\n");
		} else {
			printf("Taskmanage: %d\n", taskmanage);
		}

		ret = pkgmgr_appinfo_get_hwacceleration(handle, &hwacceleration);
		if (ret < 0) {
			printf("Failed to get hwacceleration\n");
		} else {
			printf("hw-acceleration: %d\n", hwacceleration);
		}

	}
	if (component == PM_SVC_APP) {
		printf("component: svcapp\n");
		ret = pkgmgr_appinfo_is_onboot(handle, &onboot);
		if (ret < 0) {
			printf("Failed to get onboot\n");
		} else {
			printf("Onboot: %d\n", onboot);
		}

		ret = pkgmgr_appinfo_is_autorestart(handle, &autorestart);
		if (ret < 0) {
			printf("Failed to get autorestart\n");
		} else {
			printf("Autorestart: %d \n", autorestart);
		}
	}


	printf("\n", data);
	return 0;
}


static int __pkg_list_cb (const pkgmgr_pkginfo_h handle, void *user_data)
{
	char *test_data = "test data";
	int ret = -1;
	char *pkgid;
	char *pkg_type;
	char *pkg_version;
	ret = pkgmgr_pkginfo_get_pkgid(handle, &pkgid);
	if(ret < 0) {
		printf("pkgmgr_pkginfo_get_pkgid() failed\n");
	}
	ret = pkgmgr_pkginfo_get_type(handle, &pkg_type);
	if(ret < 0) {
		printf("pkgmgr_pkginfo_get_type() failed\n");
	}
	ret = pkgmgr_pkginfo_get_version(handle, &pkg_version);
	if(ret < 0) {
		printf("pkgmgr_pkginfo_get_version() failed\n");
	}
	printf("---------------------------------------\n");
	printf("pkg_type [%s]\tpkgid [%s]\tversion [%s]\n", pkg_type,
	       pkgid, pkg_version);

	printf("**List of Ui-Apps**\n");
	ret = pkgmgr_appinfo_get_list(handle, PM_UI_APP, app_func, (void *)test_data);
	if (ret < 0) {
		printf("pkgmgr_get_info_app() failed\n");
	}
	printf("**List of Svc-Apps**\n");
	ret = pkgmgr_appinfo_get_list(handle, PM_SVC_APP, app_func, (void *)test_data);
	if (ret < 0) {
		printf("pkgmgr_get_info_app() failed\n");
	}

	printf("---------------------------------------\n");

	return 0;
}

static int __get_pkg_list()
{
	int ret = -1;
	ret = pkgmgr_pkginfo_get_list(__pkg_list_cb, NULL);
	if (ret < 0) {
		printf("pkgmgr_pkginfo_get_list() failed\n");
		return -1;
	}
	return 0;
}

static int __get_installed_app_list()
{
	int ret = -1;
	ret = pkgmgrinfo_appinfo_get_installed_list(app_func, NULL);
	if (ret < 0) {
		printf("pkgmgrinfo_appinfo_get_installed_list() failed\n");
		return -1;
	}
	return 0;
}


static int __app_category_list_cb(const char *category_name, void *user_data)
{
	if (category_name)
		printf("Category: %s\n", category_name);
	return 0;
}

static int __app_control_list_cb(pkgmgrinfo_appcontrol_h handle, void *user_data)
{
	printf("-------------------------------------------------------\n");
	int i = 0;
	int ret = 0;
	int oc = 0;
	int mc = 0;
	int uc = 0;
	char **operation = NULL;
	char **uri = NULL;
	char **mime = NULL;
	ret = pkgmgrinfo_appinfo_get_operation(handle, &oc, &operation);
	if (ret < 0) {
		printf("Get Operation Failed\n");
		return -1;
	}
	ret = pkgmgrinfo_appinfo_get_uri(handle, &uc, &uri);
	if (ret < 0) {
		printf("Get Uri Failed\n");
		return -1;
	}
	ret = pkgmgrinfo_appinfo_get_mime(handle, &mc, &mime);
	if (ret < 0) {
		printf("Get Mime Failed\n");
		return -1;
	}
	for (i = 0; i < oc; i++) {
		if (operation && operation[i])
			printf("Operation: %s\n", operation[i]);
	}
	for (i = 0; i < uc; i++) {
		if (uri && uri[i])
			printf("Uri: %s\n", uri[i]);
	}
	for (i = 0; i < mc; i++) {
		if (mime && mime[i])
			printf("Mime: %s\n", mime[i]);
	}
	printf("-------------------------------------------------------\n\n");
	return 0;
}


static int __get_app_category_list(char *appid)
{
	int ret = -1;
	pkgmgr_appinfo_h handle;
	ret = pkgmgr_appinfo_get_appinfo(appid, &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}
	ret = pkgmgr_appinfo_foreach_category(handle, __app_category_list_cb, NULL);
	if (ret < 0) {
		printf("pkgmgr_appinfo_foreach_category() failed\n");
		pkgmgr_appinfo_destroy_appinfo(handle);
		return -1;
	}
	pkgmgr_appinfo_destroy_appinfo(handle);
	return 0;
}

static int __get_app_control_list(char *appid)
{
	int ret = -1;
	pkgmgr_appinfo_h handle;
	ret = pkgmgr_appinfo_get_appinfo(appid, &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}
	ret = pkgmgrinfo_appinfo_foreach_appcontrol(handle, __app_control_list_cb, NULL);
	if (ret < 0) {
		printf("pkgmgrinfo_appinfo_foreach_appcontrol() failed\n");
		pkgmgr_appinfo_destroy_appinfo(handle);
		return -1;
	}
	pkgmgr_appinfo_destroy_appinfo(handle);
	return 0;
}

static int __get_app_list(char *pkgid)
{
	pkgmgr_pkginfo_h handle;
	int ret = -1;
	char *test_data = "test data";
	ret = pkgmgr_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}
	printf("List of Ui-Apps\n\n");
	ret = pkgmgr_appinfo_get_list(handle, PM_UI_APP, app_func, (void *)test_data);
	if (ret < 0) {
		printf("pkgmgr_appinfo_get_list() failed\n");
	}
	printf("List of Svc-Apps\n\n");
	ret = pkgmgr_appinfo_get_list(handle, PM_SVC_APP, app_func, (void *)test_data);
	if (ret < 0) {
		printf("pkgmgr_appinfo_get_list() failed\n");
	}
	pkgmgr_pkginfo_destroy_pkginfo(handle);
	return 0;
}

static int __get_pkg_info(char *pkgid)
{
	pkgmgr_pkginfo_h handle;
	int ret = -1;
	char *type = NULL;
	char *version = NULL;
	char *author_name = NULL;
	char *author_email = NULL;
	char *author_href = NULL;
	pkgmgr_install_location location = 0;
	char *icon = NULL;
	char *label = NULL;
	char *desc = NULL;
	bool removable = 0;
	bool preload = 0;
	bool readonly = 0;
	int size = -1;
	int installed_time = -1;

	printf("Get Pkg Info Called [%s]\n", pkgid);
	ret = pkgmgr_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}

	ret = pkgmgr_pkginfo_get_type(handle, &type);
	if (ret < 0) {
		printf("Failed to get pkg type\n");
	}
	if (type)
		printf("Type: %s\n", type);

	ret = pkgmgr_pkginfo_get_version(handle, &version);
	if (ret < 0) {
		printf("Failed to get version\n");
	}
	if (version)
		printf("Version: %s\n", version);

	ret = pkgmgr_pkginfo_get_install_location(handle, &location);
	if (ret < 0) {
		printf("Failed to get install location\n");
	}
	printf("Install Location: %d\n", location);

	ret = pkgmgr_pkginfo_get_package_size(handle, &size);
	if (ret < 0) {
		printf("Failed to get package size \n");
	}
	printf("Package Size: %d\n", size);

	ret = pkgmgr_pkginfo_get_icon(handle, &icon);
	if (ret < 0) {
		printf("Failed to get icon\n");
	}
	if (icon)
		printf("Icon: %s\n", icon);

	ret = pkgmgr_pkginfo_get_label(handle, &label);
	if (ret < 0) {
		printf("Failed to get label\n");
	}
	if (label)
		printf("Label: %s\n", label);

	ret = pkgmgr_pkginfo_get_description(handle, &desc);
	if (ret < 0) {
		printf("Failed to get description\n");
	}
	if (desc)
		printf("Description: %s\n", desc);

	ret = pkgmgr_pkginfo_get_author_name(handle, &author_name);
	if (ret < 0) {
		printf("Failed to get author name\n");
	}
	if (author_name)
		printf("Author Name: %s\n", author_name);

	ret = pkgmgr_pkginfo_get_author_email(handle, &author_email);
	if (ret < 0) {
		printf("Failed to get author email\n");
	}
	if (author_email)
		printf("Author Email: %s\n", author_email);

	ret = pkgmgr_pkginfo_get_author_href(handle, &author_href);
	if (ret < 0) {
		printf("Failed to get author href\n");
	}
	if (author_href)
		printf("Author Href: %s\n", author_href);

	ret = pkgmgr_pkginfo_is_removable(handle, &removable);
	if (ret < 0) {
		printf("Failed to get removable\n");
	}
	else
		printf("Removable: %d\n", removable);

	ret = pkgmgr_pkginfo_is_preload(handle, &preload);
	if (ret < 0) {
		printf("Failed to get preload\n");
	}
	else
		printf("Preload: %d\n", preload);

	ret = pkgmgr_pkginfo_is_readonly(handle, &readonly);
	if (ret < 0) {
		printf("Failed to get readonly\n");
	}
	else
		printf("Readonly: %d\n", readonly);

	ret = pkgmgr_pkginfo_get_installed_time(handle, &installed_time);
	if (ret < 0) {
		printf("Failed to get install time\n");
	}
	printf("Install time: %d\n", installed_time);

	pkgmgr_pkginfo_destroy_pkginfo(handle);
	return 0;
}

static int __get_app_info(char *appid)
{
	printf("Get App Info Called [%s]\n", appid);
	char *exec = NULL;
	char *app_id = NULL;
	char *apptype = NULL;
	char *icon = NULL;
	char *label = NULL;
	char *package = NULL;
	pkgmgr_app_component component = 0;
	bool nodisplay = 0;
	bool multiple = 0;
	bool taskmanage = 0;
	int hwacceleration = 0;
	bool onboot = 0;
	bool autorestart = 0;
	pkgmgr_appinfo_h handle;
	int ret = -1;

	ret = pkgmgr_appinfo_get_appinfo(appid, &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}

	ret = pkgmgr_appinfo_get_pkgid(handle, &package);
	if (ret < 0) {
		printf("Failed to get package\n");
	}

	ret = pkgmgr_appinfo_get_appid(handle, &app_id);
	if (ret < 0) {
		printf("Failed to get exec\n");
	}

	ret = pkgmgr_appinfo_get_label(handle, &label);
	if (ret < 0) {
		printf("Failed to get label\n");
	}
	ret = pkgmgr_appinfo_get_icon(handle, &icon);
	if (ret < 0) {
		printf("Failed to get icon\n");
	}

	ret = pkgmgr_appinfo_get_exec(handle, &exec);
	if (ret < 0) {
		printf("Failed to get exec\n");
	}
	ret = pkgmgr_appinfo_get_component(handle, &component);
	if (ret < 0) {
		printf("Failed to get component\n");
	}
	ret = pkgmgr_appinfo_get_apptype(handle, &apptype);
	if (ret < 0) {
		printf("Failed to get apptype\n");
	}
	ret = pkgmgr_appinfo_is_nodisplay(handle, &nodisplay);
	if (ret < 0) {
		printf("Failed to get nodisplay\n");
	}
	ret = pkgmgr_appinfo_is_multiple(handle, &multiple);
	if (ret < 0) {
		printf("Failed to get multiple\n");
	}
	ret = pkgmgr_appinfo_is_taskmanage(handle, &taskmanage);
	if (ret < 0) {
		printf("Failed to get taskmanage\n");
	}
	ret = pkgmgr_appinfo_get_hwacceleration(handle, &hwacceleration);
	if (ret < 0) {
		printf("Failed to get hwacceleration\n");
	}
	ret = pkgmgr_appinfo_is_onboot(handle, &onboot);
	if (ret < 0) {
		printf("Failed to get onboot\n");
	}
	ret = pkgmgr_appinfo_is_autorestart(handle, &autorestart);
	if (ret < 0) {
		printf("Failed to get autorestart\n");
	}

	if (app_id)
		printf("Appid: %s\n", app_id);

	if (package)
		printf("Package: %s\n", package);

	if (exec)
		printf("Exec: %s\n", exec);
	if (apptype)
		printf("Apptype: %s\n", apptype);

	if (component == PM_UI_APP) {
		printf("component: uiapp\n");

		if (icon)
			printf("Icon: %s\n", icon);
		if (label)
			printf("Label: %s\n", label);

		printf("Nodisplay: %d\n", nodisplay);
		printf("Multiple: %d\n", multiple);
		printf("Taskmanage: %d\n", taskmanage);
		printf("Hw-Acceleration: %d\n", hwacceleration);
	} else if (component == PM_SVC_APP) {
		printf("component: svcapp\n");

		if (icon)
			printf("Icon: %s\n", icon);
		if (label)
			printf("Label: %s\n", label);

		printf("Autorestart: %d\n", autorestart);
		printf("Onboot: %d\n", onboot);
	} else {
		printf("Invalid Component Type\n");
	}

	pkgmgr_appinfo_destroy_appinfo(handle);
	return 0;

}

static int __check_manifest_validation(char *manifest)
{
	int ret = 0;
	if (manifest == NULL) {
		printf("Manifest file is NULL\n");
		return -1;
	}
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if (ret < 0) {
		printf("check manifest validation failed\n");
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = -1;
	char *locale = NULL;
	locale = vconf_get_str(VCONFKEY_LANGSET);
	if (locale == NULL) {
		printf("locale is NULL\n");
		return -1;
	}
	else
		printf("Locale is %s\n", locale);
	free(locale);
	locale = NULL;
	if (argc == 2) {
		if (strcmp(argv[1], "--listpkg") == 0) {
			ret = __get_pkg_list();
			if (ret == -1) {
				printf("get pkg list failed\n");
				return -1;
			} else {
				return 0;
			}
		} else if (strcmp(argv[1], "--app-flt") == 0) {
			ret = __add_app_filter();
			if (ret == -1) {
				printf("Adding app filter failed\n");
				return -1;
			} else {
				return 0;
			}
		} else if (strcmp(argv[1], "--pkg-flt") == 0) {
			ret = __add_pkg_filter();
			if (ret == -1) {
				printf("Adding pkg filter failed\n");
				return -1;
			} else {
				return 0;
			}
		} else if (strcmp(argv[1], "--listapp") == 0) {
			ret = __get_installed_app_list();
			if (ret == -1) {
				printf("get installed app list failed\n");
				return -1;
			} else {
				return 0;
			}
		} else {
			__print_usage();
			return -1;
		}
	}
	if (argc != 3) {
		__print_usage();
		return -1;
	}
	if (!argv[1] || !argv[2]) {
			__print_usage();
			return -1;
	}

	if (strcmp(argv[1], "--pkg") == 0) {
		ret = __get_pkg_info(argv[2]);
		if (ret == -1) {
			printf("get pkg info failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--app") == 0) {
		ret = __get_app_info(argv[2]);
		if (ret == -1) {
			printf("get app info failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--list") == 0) {
		ret = __get_app_list(argv[2]);
		if (ret == -1) {
			printf("get app list failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--imd") == 0) {
		ret = __insert_manifest_in_db(argv[2]);
		if (ret == -1) {
			printf("insert in db failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--rmd") == 0) {
		ret = __remove_manifest_from_db(argv[2]);
		if (ret == -1) {
			printf("remove from db failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--setdb") == 0) {
		ret = __set_pkginfo_in_db(argv[2]);
		if (ret == -1) {
			printf("set pkginfo in db failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--setcert") == 0) {
		ret = __set_certinfo_in_db(argv[2]);
		if (ret == -1) {
			printf("set certinfo in db failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--getcert") == 0) {
		ret = __get_certinfo_from_db(argv[2]);
		if (ret == -1) {
			printf("get certinfo from db failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--delcert") == 0) {
		ret = __del_certinfo_from_db(argv[2]);
		if (ret == -1) {
			printf("del certinfo from db failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--check") == 0) {
		ret = __check_manifest_validation(argv[2]);
		if (ret == -1) {
			printf("check manifest failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--category") == 0) {
		ret = __get_app_category_list(argv[2]);
		if (ret == -1) {
			printf("get app category list failed\n");
			return -1;
		}
	} else if (strcmp(argv[1], "--appcontrol") == 0) {
		ret = __get_app_control_list(argv[2]);
		if (ret == -1) {
			printf("get app control list failed\n");
			return -1;
		}
	} else
		__print_usage();

	return 0;
}