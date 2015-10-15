#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/limits.h>

#include <tzplatform_config.h>
#include <security-manager.h>
#include <pkgmgr_parser.h>

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

static const char *_get_pkg_root_path(const char *pkgid, uid_t uid)
{
	const char *path;

	tzplatform_set_user(uid);
	path = tzplatform_mkpath((uid == OWNER_ROOT || uid == GLOBAL_USER) ?
			TZ_SYS_RO_APP : TZ_USER_APP, pkgid);
	tzplatform_reset_user();

	return path;
}

struct path_type {
	const char *path;
	enum app_install_path_type type;
};

struct path_type path_type_map[] = {
	{"/", SECURITY_MANAGER_PATH_PUBLIC_RO},
	{"/bin", SECURITY_MANAGER_PATH_RO},
	{"/data", SECURITY_MANAGER_PATH_RW},
	{"/cache", SECURITY_MANAGER_PATH_RW},
	{"/lib", SECURITY_MANAGER_PATH_RO},
	{"/res", SECURITY_MANAGER_PATH_RO},
	{"/shared", SECURITY_MANAGER_PATH_PUBLIC_RO},
	{NULL, SECURITY_MANAGER_ENUM_END}
};

static app_inst_req *_prepare_request(const char *pkgid, const char *appid,
		uid_t uid)
{
	int ret;
	app_inst_req *req;
	const char *root_path;
	char buf[PATH_MAX];
	int i;

	if (security_manager_app_inst_req_new(&req)) {
		printf("security_manager_app_inst_req_new failed\n");
		return NULL;
	}

	ret = security_manager_app_inst_req_set_pkg_id(req, pkgid);
	if (ret != SECURITY_MANAGER_SUCCESS) {
		printf("set pkgid failed: %d\n", ret);
		security_manager_app_inst_req_free(req);
		return NULL;
	}

	ret = security_manager_app_inst_req_set_app_id(req, appid);
	if (ret != SECURITY_MANAGER_SUCCESS) {
		printf("set appid failed: %d\n", ret);
		security_manager_app_inst_req_free(req);
		return NULL;
	}

	root_path = _get_pkg_root_path(pkgid, uid);
	/* TODO: should be fixed */
	if (access(root_path, F_OK) == -1) {
		printf("cannot find %s, but the smack rule for %s "
				"will be installed\n", root_path, appid);
		return req;
	}

	for (i = 0; path_type_map[i].path; i++) {
		snprintf(buf, sizeof(buf), "%s%s", root_path,
				path_type_map[i].path);
		if (access(buf, F_OK) == -1)
			continue;
		ret = security_manager_app_inst_req_add_path(req, buf,
				path_type_map[i].type);
		if (ret != SECURITY_MANAGER_SUCCESS) {
			printf("set path failed: %d\n", ret);
			security_manager_app_inst_req_free(req);
			return NULL;
		}
	}

	return req;
}

/* NOTE: We cannot use cert-svc api which checks signature level in this tool,
 * because cert-svc does not provide c apis in Tizen 3.0.
 * So we set default privilege as platform level temporarily.
 */
#define DEFAULT_PRIVILEGE "http://tizen.org/privilege/internal/default/platform"
static int _insert_privilege(char *manifest, uid_t uid)
{
	int ret;
	app_inst_req *req;
	manifest_x *mfx;
	privilege_x *priv;
	struct application_x *app;

	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	if (mfx == NULL) {
		printf("Parse manifest failed\n");
		return -1;
	}

	app = mfx->application;
	while (app) {
		req = _prepare_request(mfx->package, app->appid, uid);
		if (req == NULL) {
			pkgmgr_parser_free_manifest_xml(mfx);
			return -1;
		}
		if (mfx->privileges != NULL) {
			for (priv = mfx->privileges->privilege; priv;
					priv = priv->next)
				security_manager_app_inst_req_add_privilege(req,
						priv->text);
		}

		if (getuid() == OWNER_ROOT)
			security_manager_app_inst_req_add_privilege(req,
					DEFAULT_PRIVILEGE);

		ret = security_manager_app_install(req);
		if (ret != SECURITY_MANAGER_SUCCESS)
			printf("app install failed: %d\n", ret);
		security_manager_app_inst_req_free(req);
		app = app->next;
	}

	pkgmgr_parser_free_manifest_xml(mfx);

	return 0;
}

static int _remove_privilege(char *manifest, uid_t uid)
{
	int ret;
	app_inst_req *req;
	manifest_x *mfx;
	struct application_x *app;

	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	if (mfx == NULL) {
		printf("Parse manifest failed\n");
		return -1;
	}

	app = mfx->application;
	while (app) {
		req = _prepare_request(mfx->package, app->appid, uid);
		if (req == NULL) {
			pkgmgr_parser_free_manifest_xml(mfx);
			return -1;
		}

		ret = security_manager_app_uninstall(req);
		if (ret != SECURITY_MANAGER_SUCCESS)
			printf("app uninstall failed: %d\n", ret);

		security_manager_app_inst_req_free(req);
		app = app->next;
	}

	pkgmgr_parser_free_manifest_xml(mfx);

	return 0;
}

static void _print_usage(const char *cmd)
{
	printf("usage: %s <option> <manifest>\n"
	       "   -i \t\t install privilege\n"
	       "   -u \t\t uninstall privilege\n", cmd);
}

int main(int argc, char **argv)
{
	int ret;

	if (argc < 3) {
		_print_usage(argv[0]);
		return -1;
	}

	if (!strcmp(argv[1], "-i")) {
		ret = _insert_privilege(argv[2], getuid());
	} else if (!strcmp(argv[1], "-u")) {
		ret = _remove_privilege(argv[2], getuid());
	} else {
		_print_usage(argv[0]);
		ret = -1;
	}

	return ret;
}
