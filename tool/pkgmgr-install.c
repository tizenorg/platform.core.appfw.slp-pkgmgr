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





#include "package-manager.h"

#include <bundle.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <appcore-efl.h>
#include <glib.h>


#define KEY_MIME_TYPE "__AUL_MIME_TYPE__"
#define KEY_MIME_CONTENT "__AUL_MIME_CONTENT__"

#define KEY_MIME_TYPE_NEW "__APP_SVC_MIME_TYPE__"
#define KEY_MIME_CONTENT_NEW "__APP_SVC_URI__"


#if !defined(PACKAGE)
#define PACKAGE "org.tizen.pkgmgr-install"
#endif


char *supported_mime_type_list[] = {
	NULL			/* sentinel */
};

struct appdata {
	char *file_path;
	char *extension;
};


static int __parse_argv(int argc, char **argv,
		char **mime_type, char **file_path);
static const char *__get_ext_from_file_path(const char *file_path);

static int __parse_argv(int argc, char **argv, 
		char **mime_type, char **file_path)
{
	static bundle *b = NULL;
	if (b)
		bundle_free(b);

	b = bundle_import_from_argv(argc, argv);
	if (b == NULL) {
		fprintf(stderr, "bundle for bundle_import_from_argv is NULL");
	}

	errno = 0;

	if(bundle_get_val(b, KEY_MIME_CONTENT_NEW)) {
	/*	*mime_type = (char *)bundle_get_val(b, KEY_MIME_TYPE_NEW); */
		*file_path = (char *)bundle_get_val(b, KEY_MIME_CONTENT_NEW);
	} else {
		*mime_type = (char *)bundle_get_val(b, KEY_MIME_TYPE);
		*file_path = (char *)bundle_get_val(b, KEY_MIME_CONTENT);
	}

	if (errno)
		return -1;

	return 0;
}

static const char *__get_ext_from_file_path(const char *file_path)
{
	return strrchr(file_path, '.') + 1;
}

gboolean __term(void *data)
{
	ecore_main_loop_quit();

	return FALSE;
}

int main(int argc, char **argv)
{
	struct appdata ad;
	struct appcore_ops ops = {
		.create = NULL,
		.terminate = NULL,
		.pause = NULL,
		.resume = NULL,
		.reset = NULL,
	};

	char *mime_type;
	char *file_path;
	const char *extension;

	if (__parse_argv(argc, argv, &mime_type, &file_path)) {
		fprintf(stderr, "Failed to parse argv!\n");
		return -1;
	}

	extension = __get_ext_from_file_path(file_path);

	memset(&ad, 0x0, sizeof(struct appdata));
	ops.data = &ad;
	ad.file_path = file_path;
	ad.extension = extension;


	int pid = fork();
	if (pid == 0) {
		pkgmgr_client *pc = pkgmgr_client_new(PC_REQUEST);
		pkgmgr_client_install(pc, extension, NULL, file_path, NULL,
							PM_DEFAULT, NULL, NULL);
		pkgmgr_client_free(pc);

		exit(0);
	}

	g_timeout_add(1000, __term, &ad);

//	sleep(2);
	/* Wait until AULD(launchpad) retrives info of this process.
	Its timeout is 1.2s. */

	return appcore_efl_main(PACKAGE, &argc, &argv, &ops);
}

