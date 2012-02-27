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
 * @ingroup SLP_PG
 * @defgroup pacakge_manager_PG PackageManagerStructure
 * @brief A programming guide for deelopers who want to make a frontend/backend pair for a package type.
 * @{

<h1 class="pg">Introduction</h1>
	<h2 class="pg">Terms of use</h2>
	<ul>
		<li><b>frontend</b> an installer frontend process</li>
		<li><b>backend</b> an installer backend process</li>
		<li><b>backendlib</b> a library of backend plugin</li>
		<li><b>PMS</b> Package manager server</li>
	</ul>

	<h2 class="pg">Structure overview</h2>

 When a command to install/update/delete a package to package-manager system, a frontend process receives request, and pass it to the package manager server. Package manager server will queue all requests, and runs backend one by one.<br>
For example, <br>
  <center>SamsungApps --(install foo.deb)--> frontend --(install foo.deb)--> PMS --(Run dpkg backend to install foo.deb)--> backend</center><br>

When 'install' command is given, the package file to be installed is already downloaded by user's application (SamsungApps, ...), and these frontend/PMS/backend are only responsible for installing it.<br>
Requests between frontend and PMS, and signal broadcasting between backend and frontend/apps are implemented by dbus.<br>
<h2></h2><br>

 To get the package information, backend plugin library is used. Each backend library provides the predefined functions, and package manager client library uses it.<br>
  <center>SamsungApps ~~> package-manager client library ~~> backend end plugin library </center>
  <center>(link and API call)                     (dynamic loading and symbol binding)  </center><br>
 

Detailed informations for each process are explained below.

	<h2 class="pg">Frontend</h2>

  A frontend is a program which shows UI to users(if needed), requests install/update/delete/recover to PMS, and shows installing status(if needed). frontend/backend programs must be exist per one package type. Again, each package type must have one frontend/backend pair.<br>

  A frontend process runs with <b>user provilege</b>, executed by package-manager client API, in include/package-manager.h;
<ul>
	<li>package_manager_install_application()</li>
	<li>package_manager_uninstall_application()</li>
</ul>

  Frontend process does following things;
<ul>
	<li>Gets arguments from argv, with one of following options;
		<ul>
			<li>-i <filepath> : Install package</li>
			<li>-u <filepath> : Update package</li>
			<li>-r : Recover package system</li>
			<li>-d <package_name> : Delete package</li>
		</ul>
	</li>
	<li>Gets cookie from security server.</li>
	<li>Sends request to PMS, with various arguments and cookie.</li>
	<li>Waits backend's status signals.</li>
	<li>Updates UI accroding to backend's status signal, if necessary.</li>
	<li>Finishes process when 'end' signal from backend comes.</li>
</ul>

A frontend has UI, so it runs in event-loop (usually ecore_loop, sometimes g_main_loop). We provide an object 'comm_client', which is integrated with g_main_loop. So, you have to program event-loop based code. Luckily the ecore_loop in SLP is integrated with g_main_loop, so you don't need to worry about using comm_client API in ecore_loop.

		<h3 class="pg">Rules</h3>
A frontend must have following features;
<ul>
	<li>Must be able to parse -i, -u, -r, -d, -q options.</li>
	<li>Must be able to parse -k <req_id> option. This string is passed to backend, as a request id.
	<li>Must have UI(at least a OK/Cancel dialog), which can be ignored by -q option.</li>
	<li>Must be able to use g_main_loop based functions.</li>
</ul>



	<h2 class="pg">Package manager server</h2>
Package Manager Server(PMS) is a <b>root</b> privilege process, which queues all requests from lots of frontends, and runs backends accrding to each requests. <br>
PMS has a queue internally, which stores each request and runs one by one. <br>
When no PMS is running yet, first frontend's request will execute PMS.

  PMS process does following things;
<ul>
	<li>Receives requests from a frontend via dbus.</li>
	<li>If the request has a wrong cookie, discard it.</li>
	<li>Puts the request into the queue.</li>
	<li>Pops a request from the queue, and sends it to corresponding backend.</li>
	<li>When the backend finishes, run next request in the queue.</li>
</ul>

PMS is already made and installed in your system.

	<h2 class="pg">Backend</h2>

for a certain package type, a backend is a <b>root</b> privilege process invoked by PMS, which is doing following things;
<ul>
	<li>Parses input values</li>
	<li>Checks signing of the package file, and verifies its validity (if necessary)
	<li>Does install/update/delete a pacakge, or recovers package system, or </li>
	<li>activate/deactivate a package</li>
	<li>Broadcasts current status</li>
</ul>

		<h3 class="pg">Rules</h3>
A backend must have following features;
<ul>
	<li>Must parse args string from frontend.</li>
	<li>Must install/update/delete a package.</li>
	<li>Must be able to recover package system, when it is corrupted.</li>
	<li>Must broadcast current install/status</li>
</ul>

	<h2 class="pg">Backend library</h2>

for a certain package type, a backend library  is just a <b>library</b> client process uses this library.
Backend library does following things;
<ul>
	<li>Checks whether package is installed or not</li>
	<li>Gets the list of installed package</li>
	<li>Gets the information of installed package</li>
	<li>Gets the information from package file</li>
</ul>

		<h3 class="pg">Rules</h3>
A backend must have following features;
<ul>
	<li>Must check whether package is installed or not.</li>
	<li>Must get the list of installed package.</li>
	<li>Must get the information of installed package.</li>
	<li>Must gets the information from package file</li>
</ul>


<h1 class="pg">Programming guide</h1>

	<h2 class="pg">Requied dev package</h2>
libpkgmgr-installer-dev package is provided to develop installer frontend/backend. <br>
@code
$ apt-get install libpkgmgr-installer-dev
@endcode

libpkgmgr-types-dev package is provided to develop installer backendlib. <br>
@code
$ apt-get install libpkgmgr-types-dev
@endcode

Three package-config files are installed; pkgmgr-installer-client.pc and pkgmgr-installer-status-broadcast-server.pc and pkgmgr-types.pc 
The first one is for frontend, the second one is for backend, and last one if for backendlib <br>


	<h2 class="pg">Installer frontend's programming guide</h2>

comm_client module is provided for frontend programming, which can do comminucations with PMS and backend process.<br>

Example code is in packages/test/frontend.c. <br>

<B>NOTE:</b> This example code uses g_main_loop. If you use ecore_loop, you don't need to run g_main_loop_*() functions. <br>

Every installer frontend's command arguments are like this; <br>
@code
$ <frontend> <cmd_opt> [<opt_val>] -k <req_id>
@endcode
<ul>
	<li>frontend : An installer frontend executable file.  </li>
	<li>cmd_opt : One of -i(install package), -u(update package), -d(delete package), -r(recover package system), -a(activate package)</li>
	<li>opt_val : Means package file path (with -i/-u), package name (with -d, -a). When cmd_opt is -r, no opt_val is required.  </li>
	<li>req_id : A request id, which is passed from frontend (with -k option) to backend. </li>
</ul>



		<h3 class="pg">Get a cookie from security-server</h3>
To authenticate this frontend process, firstly you have to get a cookie from security server.<br>
security-server.h from security-server package has cookie APIs. For more information, see security-server.h file.<br>
@code

#include <security-server.h>

/* ...... */

char *cookie;
int cookie_size;
int cookie_ret;

cookie_size = security_server_get_cookie_size();
/* If security server is down or some other error occured, raise failure */
if(0 >= cookie_size) {
	/* TODO: raise error */
} else {
	cookie = calloc(cookie_size, sizeof(char));
	cookie_ret = security_server_request_cookie(cookie, cookie_size);
	/* TODO: Check cookie_ret... (See security-server.h to check return code) */
}

@endcode
This cookie string will be passed to PMS later.

		<h3 class="pg">Parse argv options</h3>
All frontends must support at least 5 options; -i, -u, -d, -r, -k, and -q. Parse each options, and do requested job. <br>
Only one of following options must be taken. <br>
		<ul>
			<li>-i <filepath> : Install package</li>
			<li>-u <filepath> : Update package</li>
			<li>-r : Recover package system</li>
			<li>-d <package_name> : Delete package</li>
		</ul>
Following options must be able to taken. <br>
		<ul>
			<li>-k <request_id> : An <b>unique string</b> to identify this request. This key will be included in status broadcast signals from backend.</li>
			<li>-q : Quiet option. Do now show UI.</li>
		</ul>


The sample code uses getopt() function in unistd.h to parse argv options.<br>

@code
#include <unistd.h>
#define BUFSIZE 256

/* ...... */

const char *opts_str = "i:u:d:rqk:";	
int s = 0;
int quite = 0;
int mode = 0;
char buf[BUFSIZE];
char req_id[BUFSIZE];


while(-1 != (s = getopt(argc, argv, opts_str))) {
	switch(s) {
		case 'i':
			if(mode) break;
			mode = MODE_INSTALL;
			strncpy(buf, optarg, BUFSIZE);
			break;
		case 'u':
			if(mode) break;
			mode = MODE_UPDATE;
			strncpy(buf, optarg, BUFSIZE);
			break;
		case 'd':
			if(mode) break;
			mode = MODE_DELETE;
			strncpy(buf, optarg, BUFSIZE);
			break;
		case 'r':
			if(mode) break;
			mode = MODE_RECOVER;
			break;
		case 'q':
			quite = 1;
			break;
		case 'k':
			strncpy(req_id, optarg, BUFSIZE);

		default:
			usage();	/* Show usage, and exit */
	}
}

@endcode

		<h3 class="pg">Do send a request to install,update,delete or recover</h3>
After parsing argv options, now your frontend knows what command will be request to your backend. For this work, we provide APIs.

		<h3 class="pg"></h3>
		<h3 class="pg"></h3>
		<h3 class="pg"></h3>

	<h2 class="pg">Installer backend's programming guide</h2>

Example code is in packages/test/backend.c. <br>

	<h3 class="pg">Parse command args</h3>
Every installer backend's command arguments are like this; <br>
@code
$ <backend> <req_id> <pkg_name> [<arg1> <arg2> <arg3> ...]
@endcode
<ul>
	<li>backend : An installer backend executable file.  </li>
	<li>req_id : A request id, which is passed from frontend (with -k option). This is broadcasted with all signals from this backend. </li>
	<li>pkg_name : package name</li>
	<li>arg1, arg2, ... : Separated arguments from frontend. You can use anything. This is a rule just between frontend and backend. </li>
</ul>

Those options must be parsed and processed properly. <br>

	<h3 class="pg">Broadcast installing status</h3>
Backend must broadcast its installing status. You can broadcast your status by using following API.
@code
#include "comm_status_broadcast_server.h"

/* ... */

DBusConnection *conn;
conn = comm_status_broadcast_server_connect();

comm_status_broadcast_server_send_signal(conn, req_id, pkg_type, pkg_name, "start", "0");
/* ... */
comm_status_broadcast_server_send_signal(conn, req_id, pkg_type, pkg_name, "install_percent", "60");
/* ... */
comm_status_broadcast_server_send_signal(conn, req_id, pkg_type, pkg_name, "end", "0");

/* ... */
@endcode

Last two values are key/value pair. Following values are mandatory;
<table>
	<tr>
		<th>key</th>
		<th>value</th>
		<th>Comment</th>
	</tr>
	<tr>
		<td>start</td>
		<td>download|install|uninstall|update|recover</td>
		<td>Start backend process. <br>NOTE: 'download' is used only by downloader.</td>
	</tr>
	<tr>
		<td>install_percent</td>
		<td>[number between 0~100]</td>
		<td>Install progress</td>
	</tr>
	<tr>
		<td>error</td>
		<td>[string]</td>
		<td>Error message</td>
	</tr>
	<tr>
		<td>end</td>
		<td>ok|fail</td>
		<td>End backend (Process termination)</td>
	</tr>
</table>

Following values are required also. If you need any of them in downloader or installer backend, send it. <br>
<table>
	<tr>
		<th>key</th>
		<th>value</th>
		<th>Comment</th>
	</tr>
	<tr>
		<td>icon_path</td>
		<td>path of icon file</td>
		<td>Before icon and *.desktop files are installed, menu-screen must have temporary icon file. This option indicates temporary icon file's path.<br>If no icon_path is provided, menu-screen will use general temporary icon.</td>
	</tr>
	<tr>
		<td>download_percent</td>
		<td>[number between 0~100]</td>
		<td>Download progress<br>NOTE: This key is used by downloader only. Installer backends don't use this.</td>
</table>

You can send any other key/val pair by this API, to send any information to your frontend or donwloader app. Any keys except above will be ignored by PMS.<br>



	<h2 class="pg">Installer backendlib's programming guide</h2>
Example code is in packages/installers/sample/sample_backendlib.c. <br>

	<h3 class="pg">Plugin implementation</h3>
Backendlib should implemented according to following Rule.
<ul>
	<li>Exported API : pkg_plugin_onload() is a exported symbol. This symbol is found when after loading the library. </li>
	<li>function pointer : _pkg_plugin_set defines the structor of function pointer. Each functions are implemented. </li>
	<li>function mapping : defined each functions are connected to function pointer when pkg_plugin_onload() is called. </li>
</ul>

@code
#include "package-manager-plugin.h"


static void pkg_native_plugin_unload (void)
{
	//ToDo
}

static int pkg_plugin_app_is_installed(const char *pkg_name)
{
	//ToDo
	
	return 0;
}

static int pkg_plugin_get_installed_apps_list(package_manager_pkg_info_t **list, int *count)
{
	//ToDo
	
	return 0;
}

static int pkg_plugin_get_app_detail_info(const char *pkg_name, package_manager_pkg_detail_info_t* pkg_detail_info)
{
	//ToDo
	
	return 0;
}

static int pkg_plugin_get_app_detail_info_from_package(const char *pkg_path, package_manager_pkg_detail_info_t* pkg_detail_info)
{
	//ToDo
	
	return 0;
}


int pkg_plugin_onload (pkg_plugin_set * set)
{
	if(set == NULL)
	{
		return -1;
	}
	
	memset(set, 0x00, sizeof(pkg_plugin_set));

	set->plugin_unload = pkg_native_plugin_unload;
	set->pkg_is_installed = pkg_plugin_app_is_installed;
	set->get_installed_pkg_list = pkg_plugin_get_installed_apps_list;
	set->get_pkg_detail_info = pkg_plugin_get_app_detail_info;
	set->get_pkg_detail_info_from_package = pkg_plugin_get_app_detail_info_from_package;

	return 0;
}
@endcode



	<h2 class="pg">Install frontend/backend</h2>
Your frontend/backend binary executables have to be installed. Usually they are installed into @PREFIX@/bin/. <br>

One thing you must do is that your backend binary's owner must be <b>root</b>, permission must be <b>700</b>.
In case of backendlib, it's permission is <b>644</b>.


	<h2 class="pg">Create symlinks for your frontend/backend binaries and backendlib library</h2>
After installing your frontend/backend, You have to create symlinks pointing your frontend/backend binaries. <br>
Those symlinks must be installed as following paths;
<ul>
	<li>frontend : @PREFIX@/etc/package-manager/frontend/<your package file's extension></li>
	<li>backend : @PREFIX@/etc/package-manager/backend/<your package file's extension></li>
	<li>backendlib : @PREFIX@/etc/package-manager/backendlib/lib[<your package file's extension>].so</li>
</ul>
For example, the debian package (*.deb) must have symlink @PREFIX@/etc/package-manager/frontend/deb, which is pointing actual frontend binary.<br>
Client API and PMS will find actual frontend/backend binaries from those paths. <br>

 * @}
 */
