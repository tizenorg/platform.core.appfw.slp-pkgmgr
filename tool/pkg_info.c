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
#include "package-manager.h"
#include "package-manager-types.h"
#include "pkgmgr_parser.h"
#include "pkgmgr-dbinfo.h"


static void __print_usage();
static int __get_pkg_info(char *pkgname);
static int __get_app_info(char *appid);
static int __get_app_list(char *pkgname);
static int __get_pkg_list(void);
static int __insert_manifest_in_db(char *manifest);
static int __remove_manifest_from_db(char *manifest);
static int __set_pkginfo_in_db(char *pkgname);
static int __get_integer_input_data(void);
char *__get_string_input_data(void);
static int __iter_fn(const char *pkg_type, const char *pkg_name,
		     const char *version, void *data);

static int __get_integer_input_data(void)
{
	char input_str[32] = { 0, };
	int data = 0;
	fflush(stdin);

	if (fgets(input_str, 1024, stdin) == NULL) {
		printf("Input buffer overflow....\n");
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
		return -1;
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
	printf("\tpkginfo --[pkg|app] <pkgname|appid>\n\n");
	printf("For Getting list of installed packages\n");
	printf("\tpkginfo --list \n\n");
	printf("For Getting app list for a particular package\n");
	printf("\tpkginfo --list <pkgname>\n\n");
	printf("To insert|remove manifest info in DB\n");
	printf("\tpkginfo --[imd|rmd] <manifest file name>\n\n");
	printf("To set pkginfo in DB\n");
	printf("\tpkginfo --setdb <pkgname>\n\n");
	printf("To set manifest validation\n");
	printf("\tpkginfo --check <manifest file name>\n\n");
}

static int __set_pkginfo_in_db(char *pkgname)
{
	if (pkgname == NULL) {
		printf("pkgname is NULL\n");
		return -1;
	}
	int ret = 0;
	int choice = -1;
	int preload = -1;
	int removable = -1;
	int location = -1;
	char *locale = NULL;
	pkgmgr_pkgdbinfo_h handle = NULL;
	ret = pkgmgr_create_pkgdbinfo(pkgname, &handle);
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
		choice = __get_integer_input_data();
		switch(choice) {
		case 0:
			ret = pkgmgr_save_pkgdbinfo(handle);
			if (ret < 0) {
				printf("pkgmgr_save_pkgdbinfo failed\n");
				return -1;
			}
			ret = pkgmgr_destroy_pkgdbinfo(handle);
			if (ret < 0) {
				printf("pkgmgr_destroy_pkgdbinfo failed\n");
				return -1;
			}
			return 0;
		case 1:
			printf("Enter type: \n");
			char *type = __get_string_input_data();
			ret = pkgmgr_set_type_to_pkgdbinfo(handle, type);
			if (ret < 0) {
				printf("pkgmgr_set_type_to_pkgdbinfo failed\n");
				return -1;
			}
			break;
		case 2:
			printf("Enter version: \n");
			char *version = __get_string_input_data();
			ret = pkgmgr_set_version_to_pkgdbinfo(handle, version);
			if (ret < 0) {
				printf("pkgmgr_set_version_to_pkgdbinfo failed\n");
				return -1;
			}
			break;
		case 3:
			printf("Enter install location [0:internal | 1:external]: \n");
			location = __get_integer_input_data();
			ret = pkgmgr_set_install_location_to_pkgdbinfo(handle, location);
			if (ret < 0) {
				printf("pkgmgr_set_install_location_to_pkgdbinfo failed\n");
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
				return -1;
			}
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
				return -1;
			}
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
				return -1;
			}
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
				return -1;
			}
			break;
		case 8:
			printf("Enter removable [0:false | 1:true]: \n");
			removable = __get_integer_input_data();
			ret = pkgmgr_set_removable_to_pkgdbinfo(handle, removable);
			if (ret < 0) {
				printf("pkgmgr_set_removable_to_pkgdbinfo failed\n");
				return -1;
			}
			break;
		case 9:
			printf("Enter preload [0:false | 1:true]: \n");
			preload = __get_integer_input_data();
			ret = pkgmgr_set_preload_to_pkgdbinfo(handle, preload);
			if (ret < 0) {
				printf("pkgmgr_set_preload_to_pkgdbinfo failed\n");
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

int app_func(const pkgmgr_appinfo_h handle, const char *appid, void *user_data)
{
	char *data = NULL;
	if (user_data) {
		data = (char *)user_data;
	}
	int ret = -1;
	char *exec = NULL;
	char *component = NULL;
	char *apptype = NULL;
	bool nodisplay = 0;
	bool multiple = 0;
	bool taskmanage = 0;
	bool onboot = 0;
	bool autorestart = 0;
	if (appid)
		printf("Appid: %s\n", appid);

	ret = pkgmgr_get_pkginfo_exec(handle, &exec);
	if (ret < 0) {
		printf("Failed to get exec\n");
	}
	if (exec)
		printf("Exec: %s\n", exec);

	ret = pkgmgr_get_pkginfo_component(handle, &component);
	if (ret < 0) {
		printf("Failed to get component\n");
	}
	if (component)
		printf("Component: %s\n", component);

	ret = pkgmgr_get_pkginfo_apptype(handle, &apptype);
	if (ret < 0) {
		printf("Failed to get apptype\n");
	}
	if (apptype)
		printf("Apptype: %s\n", apptype);

	if (component) {
		if (strcasecmp(component, "uiapp") == 0) {
			ret = pkgmgr_get_pkginfo_multiple(handle, &multiple);
			if (ret < 0) {
				printf("Failed to get multiple\n");
			} else {
				printf("Multiple: %d\n", multiple);
			}

			ret = pkgmgr_get_pkginfo_nodisplay(handle, &nodisplay);
			if (ret < 0) {
				printf("Failed to get nodisplay\n");
			} else {
				printf("Nodisplay: %d \n", nodisplay);
			}

			ret = pkgmgr_get_pkginfo_taskmanage(handle, &taskmanage);
			if (ret < 0) {
				printf("Failed to get taskmanage\n");
			} else {
				printf("Taskmanage: %d\n", taskmanage);
			}
		}
		if (strcasecmp(component, "svcapp") == 0) {
			ret = pkgmgr_get_pkginfo_onboot(handle, &onboot);
			if (ret < 0) {
				printf("Failed to get onboot\n");
			} else {
				printf("Onboot: %d\n", onboot);
			}

			ret = pkgmgr_get_pkginfo_autorestart(handle, &autorestart);
			if (ret < 0) {
				printf("Failed to get autorestart\n");
			} else {
				printf("Autorestart: %d \n", autorestart);
			}
		}
	}

	printf("Userdata: %s\n\n\n", data);
	return 0;
}

static int __iter_fn(const char *pkg_type, const char *pkg_name,
		     const char *version, void *data)
{
	printf("pkg_type [%s]\tpkg_name [%s]\tversion [%s]\n", pkg_type,
	       pkg_name, version);
	return 0;
}

static int __get_pkg_list()
{
	int ret = -1;
	ret = pkgmgr_get_info_list(__iter_fn, NULL);
	if (ret < 0) {
		printf("pkgmgr_get_info_list() failed\n");
		return -1;
	}
	return 0;
}
static int __get_app_list(char *pkgname)
{
	pkgmgr_pkginfo_h handle;
	int ret = -1;
	char *test_data = "test data";
	ret = pkgmgr_get_pkginfo(pkgname, &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}
	printf("List of Ui-Apps\n\n");
	ret = pkgmgr_get_info_app(handle, PM_UI_APP, app_func, (void *)test_data);
	if (ret < 0) {
		printf("pkgmgr_get_info_app() failed\n");
	}
	printf("List of Svc-Apps\n\n");
	ret = pkgmgr_get_info_app(handle, PM_SVC_APP, app_func, (void *)test_data);
	if (ret < 0) {
		printf("pkgmgr_get_info_app() failed\n");
	}
	pkgmgr_destroy_pkginfo(handle);
	return 0;
}

static int __get_pkg_info(char *pkgname)
{
	pkgmgr_pkginfo_h handle;
	int ret = -1;
	char *type = NULL;
	char *version = NULL;
	char *author_name = NULL;
	char *author_email = NULL;
	char *author_href = NULL;
	pkgmgr_install_location location = 1;
	char *icon = NULL;
	char *label = NULL;
	char *desc = NULL;
	bool removable = 0;
	bool preload = 0;
	bool readonly = 0;

	printf("Get Pkg Info Called [%s]\n", pkgname);
	ret = pkgmgr_get_pkginfo(pkgname, &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}

	ret = pkgmgr_get_pkginfo_version(handle, &version);
	if (ret < 0) {
		printf("Failed to get version\n");
	}
	if (version)
		printf("Version: %s\n", version);

	ret = pkgmgr_get_pkginfo_install_location(handle, &location);
	if (ret < 0) {
		printf("Failed to get install location\n");
	}
	printf("Install Location: %d\n", location);

	ret = pkgmgr_get_pkginfo_label(handle, &label);
	if (ret < 0) {
		printf("Failed to get label\n");
	}
	if (label)
		printf("Label: %s\n", label);

	ret = pkgmgr_get_pkginfo_icon(handle, &icon);
	if (ret < 0) {
		printf("Failed to get icon\n");
	}
	if (icon)
		printf("Icon: %s\n", icon);

	ret = pkgmgr_get_pkginfo_description(handle, &desc);
	if (ret < 0) {
		printf("Failed to get description\n");
	}
	if (desc)
		printf("Description: %s\n", desc);

	ret = pkgmgr_get_pkginfo_type(handle, &type);
	if (ret < 0) {
		printf("Failed to get pkg type\n");
	}
	if (type)
		printf("Type: %s\n", type);

	ret = pkgmgr_get_pkginfo_author_name(handle, &author_name);
	if (ret < 0) {
		printf("Failed to get author name\n");
	}
	if (author_name)
		printf("Author Name: %s\n", author_name);

	ret = pkgmgr_get_pkginfo_author_email(handle, &author_email);
	if (ret < 0) {
		printf("Failed to get author email\n");
	}
	if (author_email)
		printf("Author Email: %s\n", author_email);

	ret = pkgmgr_get_pkginfo_author_href(handle, &author_href);
	if (ret < 0) {
		printf("Failed to get author href\n");
	}
	if (author_href)
		printf("Author Href: %s\n", author_href);

	ret = pkgmgr_get_pkginfo_removable(handle, &removable);
	if (ret < 0) {
		printf("Failed to get removable\n");
	}
	else
		printf("Removable: %d\n", removable);

	ret = pkgmgr_get_pkginfo_preload(handle, &preload);
	if (ret < 0) {
		printf("Failed to get preload\n");
	}
	else
		printf("Preload: %d\n", preload);

	ret = pkgmgr_get_pkginfo_readonly(handle, &readonly);
	if (ret < 0) {
		printf("Failed to get readonly\n");
	}
	else
		printf("Readonly: %d\n", readonly);

	pkgmgr_destroy_pkginfo(handle);
	return 0;
}

static int __get_app_info(char *appid)
{
	printf("Get App Info Called [%s]\n", appid);
	char *exec = NULL;
	char *apptype = NULL;
	char *component = NULL;
	bool nodisplay = 0;
	bool multiple = 0;
	bool taskmanage = 0;
	bool onboot = 0;
	bool autorestart = 0;
	pkgmgr_appinfo_h handle;
	int ret = -1;

	ret = pkgmgr_get_appinfo(appid, &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}
	ret = pkgmgr_get_pkginfo_exec(handle, &exec);
	if (ret < 0) {
		printf("Failed to get exec\n");
	}
	ret = pkgmgr_get_pkginfo_component(handle, &component);
	if (ret < 0) {
		printf("Failed to get component\n");
	}
	ret = pkgmgr_get_pkginfo_apptype(handle, &apptype);
	if (ret < 0) {
		printf("Failed to get apptype\n");
	}
	ret = pkgmgr_get_pkginfo_multiple(handle, &multiple);
	if (ret < 0) {
		printf("Failed to get multiple\n");
	}
	ret = pkgmgr_get_pkginfo_nodisplay(handle, &nodisplay);
	if (ret < 0) {
		printf("Failed to get nodisplay\n");
	}
	ret = pkgmgr_get_pkginfo_taskmanage(handle, &taskmanage);
	if (ret < 0) {
		printf("Failed to get taskmanage\n");
	}
	ret = pkgmgr_get_pkginfo_onboot(handle, &onboot);
	if (ret < 0) {
		printf("Failed to get onboot\n");
	}
	ret = pkgmgr_get_pkginfo_autorestart(handle, &autorestart);
	if (ret < 0) {
		printf("Failed to get autorestart\n");
	}

	if (exec)
		printf("Exec: %s\n", exec);
	if (apptype)
		printf("Apptype: %s\n", apptype);
	if (component)
		printf("Component: %s\n", component);
	if (component) {
		if (strcasecmp(component, "uiapp") == 0) {
			printf("Nodisplay: %d\n", nodisplay);
			printf("Multiple: %d\n", multiple);
			printf("Taskmanage: %d\n", taskmanage);
		} else if (strcasecmp(component, "svcapp") == 0) {
			printf("Autorestart: %d\n", autorestart);
			printf("Onboot: %d\n", onboot);
		} else {
			printf("Invalid Component Type\n");
		}
	}
	pkgmgr_destroy_appinfo(handle);
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
		if (strcmp(argv[1], "--list") == 0) {
			ret = __get_pkg_list();
			if (ret == -1) {
				printf("get pkg list failed\n");
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
	} else if (strcmp(argv[1], "--check") == 0) {
		ret = __check_manifest_validation(argv[2]);
		if (ret == -1) {
			printf("check manifest failed\n");
			return -1;
		}
	} else
		__print_usage();

	return 0;
}
