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
#include <getopt.h>
#include <sys/types.h>
#include <glib.h>
#include <ail.h>
#include <glib-object.h>
#include "package-manager.h"
#include "package-manager-types.h"

#define PKG_TOOL_VERSION	"0.1"

static int __process_request();
static void __print_usage();
static int __is_authorized();
static int __is_app_installed(char *pkgname);
static void __print_pkg_info(pkgmgr_info * pkg_info);
static int __iter_fn(const char *pkg_type, const char *pkg_name,
		     const char *version, void *data);
static int __return_cb(int req_id, const char *pkg_type, const char *pkg_name,
		       const char *key, const char *val, const void *pmsg,
		       void *data);
static int __convert_to_absolute_path(char *path);

/* Supported options */
const char *short_options = "iucADlsd:p:t:n:qh";
const struct option long_options[] = {
	{"install", 0, NULL, 'i'},
	{"uninstall", 0, NULL, 'u'},
	{"clear", 0, NULL, 'c'},
	{"activate", 0, NULL, 'A'},
	{"deactivate", 0, NULL, 'D'},
	{"list", 0, NULL, 'l'},
	{"show", 0, NULL, 's'},
	{"descriptor", 1, NULL, 'd'},
	{"package-path", 1, NULL, 'p'},
	{"package-type", 1, NULL, 't'},
	{"package-name", 1, NULL, 'n'},
	{"quiet", 0, NULL, 'q'},
	{"help", 0, NULL, 'h'},
	{0, 0, 0, 0}		/* sentinel */
};

enum pm_tool_request_e {
	INSTALL_REQ = 1,
	UNINSTALL_REQ,
	CLEAR_REQ,
	ACTIVATE_REQ,
	DEACTIVATE_REQ,
	LIST_REQ,
	SHOW_REQ,
	HELP_REQ
};
typedef enum pm_tool_request_e req_type;

struct pm_tool_args_t {
	req_type request;
	char pkg_path[PKG_NAME_STRING_LEN_MAX];
	char pkg_type[PKG_TYPE_STRING_LEN_MAX];
	char pkg_name[PKG_NAME_STRING_LEN_MAX];
	char des_path[PKG_NAME_STRING_LEN_MAX];
	int quiet;
	int result;
};
typedef struct pm_tool_args_t pm_tool_args;
pm_tool_args data;

static GMainLoop *main_loop = NULL;

static int __iter_fn(const char *pkg_type, const char *pkg_name,
		     const char *version, void *data)
{
	printf("pkg_type [%s]\tpkg_name [%s]\tversion [%s]\n", pkg_type,
	       pkg_name, version);
	return 0;
}

static int __return_cb(int req_id, const char *pkg_type,
		       const char *pkg_name, const char *key, const char *val,
		       const void *pmsg, void *priv_data)
{
	printf("__return_cb req_id[%d] pkg_type[%s] "
	       "pkg_name[%s] key[%s] val[%s]\n",
	       req_id, pkg_type, pkg_name, key, val);

	if (strncmp(key, "end", strlen("end")) == 0) {
		if (strncasecmp(val, "ok", strlen("ok")) != 0)
			data.result = EXIT_FAILURE;	//error_code

		g_main_loop_quit(main_loop);
	}

	return 0;
}

static int __convert_to_absolute_path(char *path)
{
	char abs[PKG_NAME_STRING_LEN_MAX] = {'\0'};
	char temp[PKG_NAME_STRING_LEN_MAX] = {'\0'};
	char *ptr = NULL;
	if (path == NULL) {
		printf("path is NULL\n");
		return -1;
	}
	strncpy(temp, path, PKG_NAME_STRING_LEN_MAX - 1);
	if (strchr(path, '/') == NULL) {
		getcwd(abs, PKG_NAME_STRING_LEN_MAX - 1);
		if (abs == NULL) {
			printf("getcwd() failed\n");
			return -1;
		}
		memset(data.pkg_path, '\0', PKG_NAME_STRING_LEN_MAX);
		snprintf(data.pkg_path, PKG_NAME_STRING_LEN_MAX - 1, "%s/%s", abs, temp);
		return 0;
	}
	if (strncmp(path, "./", 2) == 0) {
		ptr = temp;
		getcwd(abs, PKG_NAME_STRING_LEN_MAX - 1);
		if (abs == NULL) {
			printf("getcwd() failed\n");
			return -1;
		}
		ptr = ptr + 2;
		memset(data.pkg_path, '\0', PKG_NAME_STRING_LEN_MAX);
		snprintf(data.pkg_path, PKG_NAME_STRING_LEN_MAX - 1, "%s/%s", abs, ptr);
		return 0;
	}
	return 0;
}

static int __is_app_installed(char *pkgname)
{
	ail_appinfo_h handle;
	ail_error_e ret;
	char *str = NULL;
	ret = ail_package_get_appinfo(pkgname, &handle);
	if (ret != AIL_ERROR_OK) {
		return -1;
	}
	ret = ail_appinfo_get_str(handle, AIL_PROP_NAME_STR, &str);
	if (ret != AIL_ERROR_OK) {
		return -1;
	}
	ret = ail_package_destroy_appinfo(handle);
	if (ret != AIL_ERROR_OK) {
		return -1;
	}

	return 0;
}

static void __print_usage()
{
	printf("\nPackage Manager Tool Version: %s\n\n", PKG_TOOL_VERSION);
	printf("-i, --install		install the package\n");
	printf("-u, --uninstall		uninstall the package\n");
	printf("-c, --clear		clear user data\n");
	printf("-l, --list		display list of installed packages\n");
	printf("-s, --show		show detail package info\n");
	printf("-d, --descriptor	provide descriptor path\n");
	printf("-p, --package-path	provide package path\n");
	printf("-n, --package-name	provide package name\n");
	printf("-t, --package-type	provide package type\n");
	printf("-q, --quiet		quiet mode operation\n");
	printf("-h, --help		print this help\n\n");
	printf("Usage: pkgcmd [options] (--quiet)\n");
	printf
	    ("pkgcmd -i -t <pkg type> (-d <descriptor path>) -p <pkg path> (-q)\n");
	printf("pkgcmd -u -t <pkg type> -n <pkg name> (-q)\n");
	printf("pkgcmd -l \n");
	printf("pkgcmd -s -t <pkg type> -p <pkg path> (-q)\n");
	printf("pkgcmd -s -t <pkg type> -n <pkg name> (-q)\n\n");
	printf("Example:\n");
	printf("pkgcmd -u -t deb -n org.tizen.calculator\n");
	printf
	    ("pkgcmd -i -t deb -p /mnt/nfs/org.tizen.calculator_0.1.2-95_armel.deb\n");
	printf("pkgcmd -c -t deb -n org.tizen.hello\n");
	exit(0);

}

static void __print_pkg_info(pkgmgr_info *pkg_info)
{
	char *temp = NULL;

	temp = pkgmgr_info_get_string(pkg_info, "pkg_type");
	if (temp) {
		printf("pkg_type : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "pkg_name");
	if (temp) {
		printf("pkg_name : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "version");
	if (temp) {
		printf("version : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "pkg_vendor");
	if (temp) {
		printf("pkg_vendor : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "pkg_description");
	if (temp) {
		printf("pkg_description : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "pkg_mimetype");
	if (temp) {
		printf("pkg_mimetype : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "pkg_installed_path_package");
	if (temp) {
		printf("pkg_installed_path_package : %s\n", temp);
		free(temp);
	}

	temp =
	    pkgmgr_info_get_string(pkg_info, "pkg_installed_path_descriptor");
	if (temp) {
		printf("pkg_installed_path_descriptor : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "category");
	if (temp) {
		printf("category : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "min_platform_version");
	if (temp) {
		printf("min_platform_version : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "visible");
	if (temp) {
		printf("visible : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "removable");
	if (temp) {
		printf("removable : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "installed_size");
	if (temp) {
		printf("installed_size : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "installed_time");
	if (temp) {
		printf("installed_time : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "data_size");
	if (temp) {
		printf("data_size : %s\n", temp);
		free(temp);
	}

	temp = pkgmgr_info_get_string(pkg_info, "optional_id");
	if (temp) {
		printf("optional_id : %s\n", temp);
		free(temp);
	}
}

static int __process_request()
{
	int ret = -1;
	int mode = PM_DEFAULT;
	pkgmgr_client *pc = NULL;
	switch (data.request) {
	case INSTALL_REQ:
		if (data.pkg_type[0] == '\0' || data.pkg_path[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}
		g_type_init();
		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			ret = -1;
			break;
		}
		if (data.quiet == 0)
			mode = PM_DEFAULT;
		else
			mode = PM_QUIET;
		if (data.des_path[0] == '\0')
			ret =
			    pkgmgr_client_install(pc, data.pkg_type, NULL,
						  data.pkg_path, NULL, mode,
						  __return_cb, pc);
		else
			ret =
			    pkgmgr_client_install(pc, data.pkg_type,
						  data.des_path, data.pkg_path,
						  NULL, mode, __return_cb, pc);
		if (ret < 0)
			break;
		g_main_loop_run(main_loop);
		ret = data.result;
		break;

	case UNINSTALL_REQ:
		if (data.pkg_type[0] == '\0' || data.pkg_name[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}
		g_type_init();
		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			ret = -1;
			break;
		}
		if (data.quiet == 0)
			mode = PM_DEFAULT;
		else
			mode = PM_QUIET;
#if 0
		ret = __is_app_installed(data.pkg_name);
		if (ret == -1) {
			printf("package is not installed\n");
			break;
		}
#else
		pkgmgr_pkginfo_h handle;
		ret = pkgmgr_get_pkginfo(data.pkg_name, &handle);
		if(ret < 0) {
			printf("package is not in pkgmgr_info DB\n");
		} else
			pkgmgr_destroy_pkginfo(handle);
#endif
		ret =
		    pkgmgr_client_uninstall(pc, data.pkg_type, data.pkg_name,
					    mode, __return_cb, NULL);
		if (ret < 0)
			break;
		g_main_loop_run(main_loop);
		ret = data.result;
		break;

	case CLEAR_REQ:
		if (data.pkg_type[0] == '\0' || data.pkg_name[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			ret = -1;
			break;
		}
		if (data.quiet == 0)
			mode = PM_DEFAULT;
		else
			mode = PM_QUIET;
		ret = __is_app_installed(data.pkg_name);
		if (ret == -1) {
			printf("package is not installed\n");
			break;
		}
		ret = pkgmgr_client_clear_user_data(pc, data.pkg_type,
						    data.pkg_name, mode);
		if (ret < 0)
			break;
		ret = data.result;
		break;

	case ACTIVATE_REQ:
		if (data.pkg_type[0] == '\0' || data.pkg_name[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			ret = -1;
			break;
		}

		ret = pkgmgr_client_activate(pc, data.pkg_type, data.pkg_name);
		if (ret < 0)
			break;
		ret = data.result;

		break;


	case DEACTIVATE_REQ:
		if (data.pkg_type[0] == '\0' || data.pkg_name[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			ret = -1;
			break;
		}

		ret = pkgmgr_client_deactivate(pc, data.pkg_type, data.pkg_name);
		if (ret < 0)
			break;
		ret = data.result;

		break;

	case LIST_REQ:
		ret = pkgmgr_get_pkg_list(__iter_fn, NULL);
		break;

	case SHOW_REQ:
		if (data.pkg_name[0] != '\0') {
			pkgmgr_info *pkg_info =
			    pkgmgr_info_new(data.pkg_type, data.pkg_name);
			if (pkg_info == NULL) {
				printf("Failed to get pkginfo handle\n");
				ret = -1;
				break;
			}
			__print_pkg_info(pkg_info);
			ret = pkgmgr_info_free(pkg_info);
			break;
		}
		if (data.pkg_path[0] != '\0') {
			pkgmgr_info *pkg_info =
			    pkgmgr_info_new_from_file(data.pkg_type,
						      data.pkg_path);
			if (pkg_info == NULL) {
				printf("Failed to get pkginfo handle\n");
				ret = -1;
				break;
			}
			__print_pkg_info(pkg_info);
			ret = pkgmgr_info_free(pkg_info);
			break;
		}
		printf("Either pkgname or pkgpath should be supplied\n");
		ret = -1;
		break;

	case HELP_REQ:
		__print_usage();
		ret = 0;
		break;

	default:
		printf("Wrong Request\n");
		ret = -1;
		break;
	}

	if (pc) {
		pkgmgr_client_free(pc);
		pc = NULL;
	}
	return ret;
}

static int __is_authorized()
{
	/* pkgcmd needs root or developer privileges.
	   If launched via fork/exec, the launching program 
	   must be running as root */

	uid_t uid = getuid();
	if ((uid_t) 0 == uid || (uid_t) 5100 == uid)
		return 1;
	else
		return 0;
}

int main(int argc, char *argv[])
{
	optind = 1;
	int opt_idx = 0;
	int c = -1;
	int ret = -1;

	if (!__is_authorized()) {
		printf("You are not an authorized user!\n");
		return -1;
	}

	if (argc == 1)
		__print_usage();

	data.request = -1;
	memset(data.des_path, '\0', PKG_NAME_STRING_LEN_MAX);
	memset(data.pkg_path, '\0', PKG_NAME_STRING_LEN_MAX);
	memset(data.pkg_name, '\0', PKG_NAME_STRING_LEN_MAX);
	memset(data.pkg_type, '\0', PKG_TYPE_STRING_LEN_MAX);
	data.quiet = 0;
	data.result = 0;
	while (1) {
		c = getopt_long(argc, argv, short_options, long_options,
				&opt_idx);
		if (c == -1)
			break;	/* Parse end */
		switch (c) {
		case 'i':	/* install */
			data.request = INSTALL_REQ;
			break;

		case 'u':	/* uninstall */
			data.request = UNINSTALL_REQ;
			break;

		case 'c':	/* clear */
			data.request = CLEAR_REQ;
			break;

		case 'A':	/* activate */
			data.request = ACTIVATE_REQ;
			break;

		case 'D':	/* deactivate */
			data.request = DEACTIVATE_REQ;
			break;

		case 'l':	/* list */
			data.request = LIST_REQ;
			break;

		case 's':	/* show */
			data.request = SHOW_REQ;
			break;

		case 'p':	/* package path */
			if (optarg)
				strncpy(data.pkg_path, optarg,
					PKG_NAME_STRING_LEN_MAX);
			ret = __convert_to_absolute_path(data.pkg_path);
			if (ret == -1) {
				printf("conversion of relative path to absolute path failed\n");
				return -1;
			}
			printf("package path is %s\n", data.pkg_path);
			break;

		case 'd':	/* descriptor path */
			if (optarg)
				strncpy(data.des_path, optarg,
					PKG_NAME_STRING_LEN_MAX);
			break;

		case 'n':	/* package name */
			if (optarg)
				strncpy(data.pkg_name, optarg,
					PKG_NAME_STRING_LEN_MAX);
			break;

		case 't':	/* package type */
			if (optarg)
				strncpy(data.pkg_type, optarg,
					PKG_TYPE_STRING_LEN_MAX);
			break;

		case 'h':	/* help */
			data.request = HELP_REQ;
			break;

		case 'q':	/* quiet mode */
			data.quiet = 1;
			break;

			/* Otherwise */
		case '?':	/* Not an option */
			__print_usage();
			break;

		case ':':	/* */
			break;

		default:
			break;

		}
	}
	ret = __process_request();
	if (ret != 0) {
		printf("processing request %d failed\n", data.request);
	}
	return ret;
}
