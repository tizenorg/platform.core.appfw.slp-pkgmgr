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

 *
 * @ingroup   SLP_PG
 * @defgroup   PackageManagerClient


@par package manager Programming Guide

<h1 class="pg"> Introduction</h1>
<h2 class="pg"> Purpose of this document</h2>
The purpose of this document is to describe how applications can usepackage manager APIs.\n
This document gives only programming guidelines to application engineers.

<h2 class="pg"> Scope</h2>
The scope of this document is limited to Samsung platform package manager API usage.

<h1 class="pg"> Architecture</h1>
<h2 class="pg"> Architecture overview</h2>
package manager is responsible for installing / uninstalling / activating application. It also support getting application list API \n

Dbus is used for communication between frontend and package-server / package-server and client library..\n
Each type of packages have been implemented and these are used for each type of operation.

@image html high-level.png "High-Level Architure"

<h2 class="pg"> SLP Features</h2>
package manager has the following features:\n

 - Install /Uninstall /Activate Application (Primitive APIs)
	- It can install/uninstall an application
	- It can activate/deactivate application.

 - Application List
	- It provides the list of applications that are installed.
	- It provides the API to free the list.

 - Listen / Broadcast status
 	- It can listen the status broadcasted by other application.
 	- It can broadcast the status to other application.

<h1 class="pg"> package manager API descriptions</h1>
<b> SEE API manual </b>

<h1 class="pg"> package manager features with sample code</h1>
<h2 class="pg"> Install /Uninstall /Activate an application</h2>

Client application
- Install request with return callback function

@code
// the package path is "/opt/apps/org.tizen.hello.deb"
#include <package-manager.h>

int static return_cb(pkg_request_id req_id, const char *pkg_type, const char *pkg_name, const char *key, const char *val, const void *pmsg, void *data)
{
	pkgmgr_client *pc = (pkgmgr_client *)data;
	
	if( strcmp(key, "end") == 0) {
		pkgmgr_client_free(pc);
		exit(0);
	}
}

void install_func()
{	
	int result = 0;
	pkgmgr_client *pc = NULL;

	pc = pkgmgr_client_new(PC_REQUEST);
	if(pc == NULL) {
		printf("pc is NULL\n");
		return -1;
	}
	
	result = pkgmgr_client_install(pc, NULL, des, "/opt/apps/org.tizen.hello.deb", NULL, PM_DEFAULT, return_cb, pc);
	if(result < 0) {
		fprintf(stderr, "Install failed! %d\n", result);
		return -1;
	}

}
@endcode


- Uninstall request with return callback function

@code
// the package type is "deb", package name is "org.tizen.hello"
#include <package-manager.h>

int static return_cb(pkg_request_id req_id, const char *pkg_type, const char *pkg_name, const char *key, const char *val, const void *pmsg, void *data)
{	
	pkgmgr_client *pc = (pkgmgr_client *)data;
	
	if( strcmp(key, "end") == 0) {
		pkgmgr_client_free(pc);
		exit(0);
	}
}

void uninstall_func()
{	
	int result = 0;
	pkgmgr_client *pc = NULL;

	pc = pkgmgr_client_new(PC_REQUEST);
	if(pc == NULL) {
		printf("pc is NULL\n");
		return -1;
	}
	
	result = pkgmgr_client_uninstall(pc, "deb", des, "org.tizen.hello", PM_DEFAULT, return_cb, pc);
	if(result < 0) {
		fprintf(stderr, "Uninstall failed! %d\n", result);
		return -1;
	}

}
@endcode


- Activate request with return callback function

@code
// the package type is "deb", package name is "org.tizen.hello"
#include <package-manager.h>


void activate_func()
{
	int result = 0;
	pkgmgr_client *pc = NULL;

	pc = pkgmgr_client_new(PC_REQUEST);
	if(pc == NULL) {
		printf("pc is NULL\n");
		return -1;
	}
	
	result = pkgmgr_client_activate(pc, "deb", "org.tizen.hello");
	if(result < 0) {
		fprintf(stderr, "Activation failed! %d\n", result);
		return -1;
	}

	pkgmgr_client_free(pc);

}
@endcode



<h2 class="pg"> Get Installed Application List </h2>

- Get/free application list
- This package manager function is used to get the list of all installed applications which can be removed.

@code
#include <package-manager.h>

static int __iter_fn(const char* pkg_type, const char* pkg_name, const char* version, void *data)
{
        printf("pkg_type %s, pkg_name %s, version %s\n", pkg_type, pkg_name, version);

        return 0;
}

void getlist_func()
{	
	pkgmgr_get_pkg_list(__iter_fn, NULL);
}
@endcode



<h2 class="pg"> Listen and broadcast the status </h2>

- Listen / broadcast the status
- This package manager function is used to listen the status broadcasted by other application.

@code
#include <package-manager.h>

int static return_cb(pkg_request_id req_id, const char *pkg_type, const char *pkg_name, const char *key, const char *val, const void *pmsg, void *data)
{	
	pkgmgr_client *pc = (pkgmgr_client *)data;
	
	if( strcmp(key, "end") == 0) {
		pkgmgr_client_free(pc);
		exit(0);
	}
}

void listen_func()
{	
	int result = 0;
	pkgmgr_client *pc = NULL;

	pc = pkgmgr_client_new(PC_LISTENING);
	if(pc == NULL) {
		printf("pc is NULL\n");
		return -1;
	}
	
	result = pkgmgr_client_listen_status(pc, return_cb, pc);
	if(result < 0)
	{
		fprintf(stderr, "status listen failed!\n");
		return -1;
	}
}
@endcode


- This package manager function is used to listen the status broadcasted by other application.

@code
// the package type is "deb", package name is "org.tizen.hello", key is "key_string", val is "val_string"
#include <package-manager.h>

void broadcast_func()
{	
	int result = 0;
	pkgmgr_client *pc = NULL;

	pc= pkgmgr_client_new(PC_BROADCAST);
	if(pc == NULL) {
		printf("pc is NULL\n");
		return -1;
	}
	
	int result = pkgmgr_client_broadcast_status(pc, "deb", "org.tizen.hello", "key_string", "val_string");
	if(result < 0) {
		fprintf(stderr, "status broadcast failed!\n");
		return -1;
	}
		
	pkgmgr_client_free(pc);
}
@endcode


*/

/**
@}
*/


