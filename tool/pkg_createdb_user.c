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
#include <sqlite3.h>

#include <pkgmgr_parser.h>
#include <pkgmgr-info.h>

#include <sys/smack.h>
/* For multi-user support */
#include <tzplatform_config.h>

#define OWNER_ROOT 0

#define QUERY_CREATE_TABLE_PARSER "create table if not exists package_info " \
						"(package text primary key not null, " \
						"package_type text DEFAULT 'rpm', " \
						"package_version text, " \
						"install_location text, " \
						"package_size text, " \
						"package_removable text DEFAULT 'true', " \
						"package_preload text DEFAULT 'false', " \
						"package_readonly text DEFAULT 'false', " \
						"package_update text DEFAULT 'false', " \
						"package_appsetting text DEFAULT 'false', " \
						"package_nodisplay text DEFAULT 'false', " \
						"package_system text DEFAULT 'false', " \
						"author_name text, " \
						"author_email text, " \
						"author_href text," \
						"installed_time text," \
						"installed_storage text," \
						"storeclient_id text," \
						"mainapp_id text," \
						"package_url text," \
						"root_path text," \
						"csc_path text );" \
						"create table if not exists package_localized_info " \
						"(package text not null, " \
						"package_locale text DEFAULT 'No Locale', " \
						"package_label text, " \
						"package_icon text, " \
						"package_description text, " \
						"package_license text, " \
						"package_author, " \
						"PRIMARY KEY(package, package_locale), " \
						"FOREIGN KEY(package) " \
						"REFERENCES package_info(package) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_privilege_info " \
						"(package text not null, " \
						"privilege text not null, " \
						"PRIMARY KEY(package, privilege) " \
						"FOREIGN KEY(package) " \
						"REFERENCES package_info(package) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_info " \
						"(app_id text primary key not null, " \
						"app_component text, " \
						"app_exec text, " \
						"app_nodisplay text DEFAULT 'false', " \
						"app_type text, " \
						"app_onboot text DEFAULT 'false', " \
						"app_multiple text DEFAULT 'false', " \
						"app_autorestart text DEFAULT 'false', " \
						"app_taskmanage text DEFAULT 'false', " \
						"app_enabled text DEFAULT 'true', " \
						"app_hwacceleration text DEFAULT 'use-system-setting', " \
						"app_screenreader text DEFAULT 'use-system-setting', " \
						"app_mainapp text, " \
						"app_recentimage text, " \
						"app_launchcondition text, " \
						"app_indicatordisplay text DEFAULT 'true', " \
						"app_portraitimg text, " \
						"app_landscapeimg text, " \
						"app_guestmodevisibility text DEFAULT 'true', " \
						"app_permissiontype text DEFAULT 'normal', " \
						"app_preload text DEFAULT 'false', " \
						"app_submode text DEFAULT 'false', " \
						"app_submode_mainid text, " \
						"component_type text, " \
						"package text not null, " \
						"FOREIGN KEY(package) " \
						"REFERENCES package_info(package) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_localized_info " \
						"(app_id text not null, " \
						"app_locale text DEFAULT 'No Locale', " \
						"app_label text, " \
						"app_icon text, " \
						"PRIMARY KEY(app_id,app_locale) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_icon_section_info " \
						"(app_id text not null, " \
						"app_icon text, " \
						"app_icon_section text, " \
						"app_icon_resolution text, " \
						"PRIMARY KEY(app_id,app_icon_section,app_icon_resolution) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_image_info " \
						"(app_id text not null, " \
						"app_locale text DEFAULT 'No Locale', " \
						"app_image_section text, " \
						"app_image text, " \
						"PRIMARY KEY(app_id,app_image_section) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_app_control " \
						"(app_id text not null, " \
						"operation text not null, " \
						"uri_scheme text, " \
						"mime_type text, " \
						"subapp_name text, " \
						"PRIMARY KEY(app_id,operation,uri_scheme,mime_type,subapp_name) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_app_svc " \
						"(app_id text not null, " \
						"operation text not null, " \
						"uri_scheme text, " \
						"mime_type text, " \
						"subapp_name text, " \
						"PRIMARY KEY(app_id,operation,uri_scheme,mime_type,subapp_name) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_app_category " \
						"(app_id text not null, " \
						"category text not null, " \
						"PRIMARY KEY(app_id,category) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_app_metadata " \
						"(app_id text not null, " \
						"md_key text not null, " \
						"md_value text not null, " \
						"PRIMARY KEY(app_id, md_key, md_value) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_app_permission " \
						"(app_id text not null, " \
						"pm_type text not null, " \
						"pm_value text not null, " \
						"PRIMARY KEY(app_id, pm_type, pm_value) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_share_allowed " \
						"(app_id text not null, " \
						"data_share_path text not null, " \
						"data_share_allowed text not null, " \
						"PRIMARY KEY(app_id,data_share_path,data_share_allowed) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE);" \
						"create table if not exists package_app_share_request " \
						"(app_id text not null, " \
						"data_share_request text not null, " \
						"PRIMARY KEY(app_id,data_share_request) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_CERT "create table if not exists package_cert_index_info " \
						"(cert_info text not null, " \
						"cert_id integer, " \
						"cert_ref_count integer, " \
						"PRIMARY KEY(cert_id)); " \
						"create table if not exists package_cert_info " \
						"(package text not null, " \
						"author_root_cert integer, " \
						"author_im_cert integer, " \
						"author_signer_cert integer, " \
						"dist_root_cert integer, " \
						"dist_im_cert integer, " \
						"dist_signer_cert integer, " \
						"dist2_root_cert integer, " \
						"dist2_im_cert integer, " \
						"dist2_signer_cert integer, " \
						"PRIMARY KEY(package)) "

#ifdef _E
#undef _E
#endif
#define _E(fmt, arg...) fprintf(stderr, "[PKG_CREATEDB][E][%s,%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);

#ifdef _D
#undef _D
#endif
#define _D(fmt, arg...) fprintf(stderr, "[PKG_CREATEDB][D][%s,%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);

sqlite3 *parser_db;
sqlite3 *cert_db;

static int __is_authorized()
{
	/* pkg_init db should be called by as root privilege. */

	uid_t uid = getuid();
	if ((uid_t) OWNER_ROOT != uid)
		return 1;
	else
		return 0;
}

static int __createdb_user_tables(sqlite3 **db_handle, const char *db_path, char *db_query)
{
	int ret = -1;

	ret =
			db_util_open_with_options(db_path, &db_handle,
				 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);

	if (ret != SQLITE_OK) {
		_D("connect db [%s] failed!\n", db_path);
		sqlite3_close(db_handle);
		return -1;
	} else {
			char *error_message = NULL;
			if (SQLITE_OK !=
				sqlite3_exec(db_handle, db_query,
					NULL, NULL, &error_message)) {
					_D("Don't execute query = %s error message = %s\n",
						db_query, error_message);
				sqlite3_free(error_message);
				return -1;
			}
			sqlite3_free(error_message);
		}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	char *journal = NULL;
	uid_t uid = getuid();

	if (!__is_authorized()) {
		_E("You are not an authorized user!\n");
		return -1;
	} else {
		if(remove(getUserPkgParserDBPathUID(uid)))
			_E(" %s is not removed", getUserPkgParserDBPathUID(uid));
		asprintf(&journal, "%s-journal", getUserPkgParserDBPathUID(uid));
		if(remove(journal))
			_E(" %s is not removed", journal);
		if(remove(getUserPkgCertDBPathUID(uid)))
			_E(" %s is not removed", getUserPkgCertDBPathUID(uid));
		asprintf(&journal, "%s-journal", getUserPkgCertDBPathUID(uid));
		if(remove(journal))
			_E(" %s is not removed", journal);
	}
	/* This is for AIL initializing */
	ret = setenv("INITDB", "1", 1);
	_D("INITDB : %d", ret);
	
	ret = __createdb_user_tables(&parser_db, getUserPkgParserDBPathUID(uid), QUERY_CREATE_TABLE_PARSER);
	_D("create DB  %s", getUserPkgParserDBPathUID(uid));
	if (ret) {
		_D("Parser DB creation Failed\n");
		return -1;
	}
	ret = __createdb_user_tables(&cert_db, getUserPkgCertDBPathUID(uid), QUERY_CREATE_TABLE_CERT);
	_D("create DB  %s", getUserPkgCertDBPathUID(uid));
	if (ret) {
		_D("Cert DB creation Failed\n");
		return -1;
	}

	return 0;
}
