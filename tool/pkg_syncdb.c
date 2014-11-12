/*
 * slp-pkgmgr
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Sabera Djelti <sabera.djelti@open.eurogiciel.org>,
 * Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include <pkgmgr_parser.h>
#include <pkgmgr-info.h>

#include <sys/smack.h>
/* For multi-user support */
#include <tzplatform_config.h>

#define OWNER_ROOT 0
#define BUFSZE 1024
#define SYS_MANIFEST_DIRECTORY tzplatform_getenv(TZ_SYS_RW_PACKAGES)
#define PACKAGE_INFO_DB_FILE tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_parser.db")
#define PACKAGE_INFO_DB_FILE_JOURNAL tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_parser.db-journal")


#define PKG_CERT_DB_FILE tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_cert.db")
#define PKG_CERT_DB_FILE_JOURNAL tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_cert.db-journal")
#define PKG_INFO_DB_LABEL "*"
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)


#ifdef _E
#undef _E
#endif
#define _E(fmt, arg...) fprintf(stderr, "[PKG_SYNCDB][E][%s,%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);

#ifdef _D
#undef _D
#endif
#define _D(fmt, arg...) fprintf(stderr, "[PKG_SYNCDB][D][%s,%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);

#define SET_DEFAULT_LABEL(x) \
	if(smack_setlabel((x), "*", SMACK_LABEL_ACCESS)) _E("failed chsmack -a \"*\" %s", x) \
    else  _D("chsmack -a \"*\" %s", x)
	  
static int syncdb_count_package(void)
{
	int total = 0;

	return total;
}

char* _manifest_to_package(const char* manifest)
{
	char *package;

	if(manifest == NULL)
		return NULL;

	package = strdup(manifest);
	if(package == NULL)
		return NULL;


	if (!strstr(package, ".xml")) {
		_E("%s is not a manifest file", manifest);
		free(package);
		return NULL;
	}

	return package;
}



int syncdb_load_directory(const char *directory)
{
	DIR *dir;
	struct dirent entry, *result;
	int ret;
	char buf[BUFSZE];

	// desktop file
	dir = opendir(directory);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			_E("Failed to access the [%s] because %s\n", directory, buf);
		return -1;
	}

	_D("Loading manifest files from %s\n", directory);

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {
		char *manifest;

		if (entry.d_name[0] == '.') continue;

		manifest = _manifest_to_package(entry.d_name);
		if (!manifest) {
			_E("Failed to convert file to package[%s]\n", entry.d_name);
			continue;
		}

		snprintf(buf, sizeof(buf), "%s/%s", directory, manifest);

		fprintf(stderr, "pkg_initdb : manifest file %s\n", buf);

		ret = pkgmgr_parser_check_manifest_validation(buf);
		if (ret < 0) {
			_E("check manifest validation failed code[%d] %s\n", ret, buf);
			fprintf(stderr, "check manifest validation failed code[%d] %s\n", ret, buf);
			free(manifest);
			continue;
		}


		/*temporarily fixed due to glib abort */
		// pkgmgr_parser_parse_manifest_for_installation(buf, NULL);

		char buf2[BUFSZE];
		snprintf(buf2, sizeof(buf2), "/usr/bin/pkginfo --imd %s", buf);
		system(buf2);

		free(manifest);
	}

	closedir(dir);

	return 0;
}


static int __is_authorized()
{
	/* pkg_init db should be called by as root privilege. */

	uid_t uid = getuid();
	uid_t euid = geteuid();
	//euid need to be root to allow smack label changes during initialization
	if ((uid_t) OWNER_ROOT == uid)
		return 1;
	else
		return 0;
}


int main(int argc, char *argv[])
{
	int ret;

	if (!__is_authorized()) {
		_E("You are not an authorized user!\n");
		return -1;
	}

	setresuid(GLOBAL_USER, GLOBAL_USER, OWNER_ROOT);
	/* This is for AIL initializing */
	ret = setenv("INITDB", "1", 1);
	_D("INITDB : %d", ret);

	ret = syncdb_count_package();
	if (ret > 0) {
		_D("Some Packages in the Package Info DB.");
		return 0;
	}
	ret = syncdb_load_directory(SYS_MANIFEST_DIRECTORY);
	if (ret == -1) {
		_E("cannot load opt manifest directory.");
	}

	return 0;
}
