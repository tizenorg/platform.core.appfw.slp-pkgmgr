#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include <tzplatform_config.h>
#include <security-manager.h>
#include <pkgmgr_parser.h>

#define BUFSIZE 4096
#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

static char *__get_path(char *pkgid, uid_t uid)
{
	char buf[BUFSIZE];
	char *path;

	if (uid == OWNER_ROOT || uid == GLOBAL_USER)
		snprintf(buf, BUFSIZE - 1, "%s", pkgid, pkgid);
	else
		snprintf(buf, BUFSIZE - 1, "%s/%s", pkgid, pkgid);

	tzplatform_set_user(uid);
	path = tzplatform_mkpath((uid == OWNER_ROOT || uid == GLOBAL_USER) ?
			TZ_SYS_RO_APP : TZ_USER_APP, buf);
	tzplatform_reset_user();

	return path;
}

static int __insert_privilege(char *manifest, uid_t uid)
{
	int ret;
	manifest_x *mfx;
	struct uiapplication_x *uiapp;
	struct serviceapplication_x *svcapp;
	char *path;

	privilege_x *priv;
	app_inst_req *req;

	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	if (mfx == NULL) {
		printf("Parse manifest failed\n");
		return -1;
	}
	if (security_manager_app_inst_req_new(&req)) {
		printf("security_manager_app_inst_req_new failed\n");
		pkgmgr_parser_free_manifest_xml(mfx);
		return -1;
	}

	security_manager_app_inst_req_set_pkg_id(req, mfx->package);
	security_manager_app_inst_req_set_app_id(req,
			mfx->uiapplication->appid);
	path = __get_path(mfx->package, uid);
	security_manager_app_inst_req_add_path(req, path,
			SECURITY_MANAGER_PATH_PUBLIC_RO);
	if (mfx->privileges != NULL) {
		for (priv = mfx->privileges->privilege; priv; priv = priv->next)
			security_manager_app_inst_req_add_privilege(req,
					priv->text);
	}

	ret = security_manager_app_install(req);
	if (ret != SECURITY_MANAGER_SUCCESS)
		printf("security_manager_app_install failed: %d\n", ret);

	security_manager_app_inst_req_free(req);
	pkgmgr_parser_free_manifest_xml(mfx);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("missing operand\n");
		return -1;
	}

	return __insert_privilege(argv[1], getuid());
}
