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

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <sys/stat.h>

#include <pkgmgr-info.h>

static int __pkg_list_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data);


#ifdef _E
#undef _E
#endif
#define _E(fmt, arg...) fprintf(stderr, "[PKG_SMACK][E][%s,%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);

#ifdef _D
#undef _D
#endif
#define _D(fmt, arg...) fprintf(stderr, "[PKG_SMACK][D][%s,%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);

#define LIB_PRIVILEGE_CONTROL		"libprivilege-control.so.0"
#define LIB_SMACK					"libsmack.so.1"

#define BUFF_SIZE			256
#define APP_OWNER_ID		5000
#define APP_GROUP_ID		5000

enum rpm_path_type {
	RPM_PATH_PRIVATE,
	RPM_PATH_GROUP_RW,
	RPM_PATH_PUBLIC_RO,
	RPM_PATH_SETTINGS_RW,
	RPM_PATH_ANY_LABEL
};

static int __is_dir(char *dirname)
{
	struct stat stFileInfo;
	stat(dirname, &stFileInfo);
	if (S_ISDIR(stFileInfo.st_mode)) {
		return 1;
	}
	return 0;
}

int __pkg_smack_register_package(const char *pkgid)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_install)(const char*) = NULL;

	if (pkgid == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_E( "register package: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_install = dlsym(handle, "app_install");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_install == NULL)) {
		_E( "register package: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	_E( "[smack] app_install(%s)", pkgid);
	ret = app_install(pkgid);
	_E( "[smack] app_install(%s), result = [%d]", pkgid, ret);

	dlclose(handle);
	return ret;
}

int __pkg_smack_unregister_package(const char *pkgid)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_uninstall)(const char*) = NULL;

	if (pkgid == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_E( "unregister package: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_uninstall = dlsym(handle, "app_uninstall");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_uninstall == NULL)) {
		_E( "unregister package: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	_E( "[smack] app_uninstall(%s)", pkgid);
	ret = app_uninstall(pkgid);
	_E( "[smack] app_uninstall(%s), result = [%d]", pkgid, ret);

	dlclose(handle);
	return ret;
}

int __pkg_smack_revoke_permissions(const char *pkgid)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_revoke_permissions)(const char*) = NULL;

	if (pkgid == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_E( "revoke permissions: dlopen() failed. [%s][%s]", pkgid, dlerror());
		return -1;
	}

	app_revoke_permissions = dlsym(handle, "app_revoke_permissions");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_revoke_permissions == NULL)) {
		_E( "revoke permissions(): dlsym() failed. [%s][%s]", pkgid, errmsg);
		dlclose(handle);
		return -1;
	}

	_E( "[smack] app_revoke_permissions(%s)", pkgid);
	ret = app_revoke_permissions(pkgid);
	_E( "[smack] app_revoke_permissions(%s), result = [%d]", pkgid, ret);

	dlclose(handle);
	return ret;
}

int __pkg_smack_enable_permissions(const char *pkgid, int apptype,
						const char **perms, int persistent)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_enable_permissions)(const char*, int, const char**, bool) = NULL;

	if (pkgid == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_E( "enable permissions(): dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_enable_permissions = dlsym(handle, "app_enable_permissions");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_enable_permissions == NULL)) {
		_E( "enable permissions(): dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	_E( "[smack] app_enable_permissions(%s, %d)", pkgid, apptype);
	ret = app_enable_permissions(pkgid, apptype, perms, persistent);
	_E( "[smack] app_enable_permissions(%s, %d), result = [%d]", pkgid, apptype, ret);

	dlclose(handle);
	return ret;
}

int __pkg_smack_setup_path(const char *pkgid, const char *dirpath,
						int apppathtype, const char *groupid)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_setup_path)(const char*, const char*, int, ...) = NULL;

	if (pkgid == NULL || dirpath == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_E( "setup path: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_setup_path = dlsym(handle, "app_setup_path");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_setup_path == NULL)) {
		_E( "setup path: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	if (groupid == NULL) {
		_E( "[smack] app_setup_path(%s, %s, %d)", pkgid, dirpath, apppathtype);
		ret = app_setup_path(pkgid, dirpath, apppathtype);
		_E( "[smack] app_setup_path(), result = [%d]", ret);
	} else {
		_E( "[smack] app_setup_path(%s, %s, %d, %s)", pkgid, dirpath, apppathtype, groupid);
		ret = app_setup_path(pkgid, dirpath, apppathtype, groupid);
		_E( "[smack] app_setup_path(), result = [%d]", ret);
	}

	dlclose(handle);
	return ret;
}

int __pkg_smack_add_friend(const char *pkgid1, const char *pkgid2)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_add_friend)(const char*, const char*) = NULL;

	if (pkgid1 == NULL || pkgid2 == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_E( "add friend: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_add_friend = dlsym(handle, "app_add_friend");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_add_friend == NULL)) {
		_E( "add friend: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	_E( "[smack] app_add_friend(%s, %s)", pkgid1, pkgid2);
	ret = app_add_friend(pkgid1, pkgid2);
	_E( "[smack] app_add_friend(%s, %s), result = [%d]", pkgid1, pkgid2, ret);

	dlclose(handle);
	return ret;
}

int __pkg_smack_change_smack_label(const char *path, const char *label,
						int label_type)
{
	if (path == NULL || label == NULL)
		return -1;
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*smack_lsetlabel)(const char*, const char*, int) = NULL;

	handle = dlopen(LIB_SMACK, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_E( "change smack label: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	smack_lsetlabel = dlsym(handle, "smack_lsetlabel");
	errmsg = dlerror();
	if ((errmsg != NULL) || (smack_lsetlabel == NULL)) {
		_E( "change smack label: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	_E( "[smack] smack_lsetlabel(%s, %s, %d)", path, label, label_type);
	ret = smack_lsetlabel(path, label, label_type);
	_E( "[smack] smack_lsetlabel(%s, %s, %d), result = [%d]", path, label, label_type, ret);

	dlclose(handle);
	return ret;
}

static void __apply_shared_privileges(char *pkgname, int flag)
{
	char dirpath[BUFF_SIZE] = {'\0'};
	/*execute privilege APIs. The APIs should not fail*/
	__pkg_smack_register_package(pkgname);

#if 1
	/*home dir. Dont setup path but change smack access to "_" */
	snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s", pkgname);
	if (__is_dir(dirpath))
		__pkg_smack_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUFF_SIZE);
	snprintf(dirpath, BUFF_SIZE, "/opt/usr/apps/%s", pkgname);
	if (__is_dir(dirpath))
		__pkg_smack_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUFF_SIZE);

	/*/shared dir. Dont setup path but change smack access to "_" */
	snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s/shared", pkgname);
	if (__is_dir(dirpath))
		__pkg_smack_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUFF_SIZE);
	snprintf(dirpath, BUFF_SIZE, "/opt/usr/apps/%s/shared", pkgname);
	if (__is_dir(dirpath))
		__pkg_smack_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUFF_SIZE);

	/*/shared/res dir. setup path */
	if (flag == 0)
		snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s/shared/res", pkgname);
	else
		snprintf(dirpath, BUFF_SIZE, "/opt/usr/apps/%s/shared/res", pkgname);
	if (__is_dir(dirpath))
		__pkg_smack_setup_path(pkgname, dirpath, RPM_PATH_PUBLIC_RO, NULL);
	memset(dirpath, '\0', BUFF_SIZE);

	/*/shared/data dir. setup path and change group to 'app'*/
	if (flag == 0)
		snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s/shared/data", pkgname);
	else
		snprintf(dirpath, BUFF_SIZE, "/opt/usr/apps/%s/shared/data", pkgname);
	if (__is_dir(dirpath)) {
		chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
		__pkg_smack_setup_path(pkgname, dirpath, RPM_PATH_PUBLIC_RO, NULL);
	} else {
		memset(dirpath, '\0', BUFF_SIZE);
		if (flag == 0)
			snprintf(dirpath, BUFF_SIZE, "/opt/usr/apps/%s/shared/data", pkgname);
		else
			snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s/shared/data", pkgname);
		if (__is_dir(dirpath))
			chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
			__pkg_smack_setup_path(pkgname, dirpath, RPM_PATH_PUBLIC_RO, NULL);
	}
#endif
}

static int __is_authorized()
{
	/* pkg_init db should be called by as root privilege. */

	uid_t uid = getuid();
	if ((uid_t) 0 == uid)
		return 1;
	else
		return 0;
}

static int __pkg_list_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if(ret < 0) {
		printf("pkgmgrinfo_pkginfo_get_pkgid() failed\n");
	}

	__apply_shared_privileges(pkgid, 0);

	return 0;
}

static int __additional_rpm_for_smack()
{
	char *pkgid = "ui-gadget::client";
	char *perm[] = {"http://tizen.org/privilege/appsetting", NULL};

	__apply_shared_privileges(pkgid, 0);
	__pkg_smack_enable_permissions(pkgid, 1, perm, 1);
	return 0;
}

static int __find_rpm_for_smack()
{
	int ret = 0;
	pkgmgrinfo_pkginfo_filter_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	if (ret > 0) {
		printf("pkginfo filter handle create failed\n");
		return -1;
	}

	ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
		PMINFO_PKGINFO_PROP_PACKAGE_TYPE, "rpm");
	if (ret < 0) {
		printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
		ret = -1;
	}

	ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __pkg_list_cb, NULL);
	if (ret < 0) {
		printf("pkgmgrinfo_pkginfo_filter_foreach_pkginfo() failed\n");
		ret = -1;
	}

	pkgmgrinfo_pkginfo_filter_destroy(handle);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	if (!__is_authorized()) {
		_E("You are not an authorized user!\n");
		return -1;
	}

	ret = __find_rpm_for_smack();
	if (ret < 0)
		printf("__find_rpm_for_smack() failed\n");

	ret = __additional_rpm_for_smack();
	if (ret < 0)
		printf("__additional_rpm_for_smack() failed\n");

	return 0;
}


