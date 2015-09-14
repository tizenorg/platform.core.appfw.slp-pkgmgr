#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include <pkgmgr_parser.h>
#include <tzplatform_config.h>

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define UG_CLIENT tzplatform_mkpath(TZ_SYS_BIN, "ug-client")

static int _check_bin_directory(const char *pkgid)
{
	int ret;
	const char *path;
	char buf[PATH_MAX];

	path = tzplatform_mkpath(TZ_SYS_RO_APP, pkgid);
	snprintf(buf, sizeof(buf), "%s/bin", path);

	if (access(buf, F_OK) == -1) {
		if (mkdir(buf, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH)) {
			printf("create bin directory(%s) failed: %s\n", buf,
					strerror(errno));
			return -1;
		}
	}

	return 0;
}

static int _install_ug(char *manifest)
{
	manifest_x *mfx;
	uiapplication_x *tmp;
	int ret;

	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	if (mfx == NULL) {
		printf("Parse manifest failed\n");
		return -1;
	}

	for (tmp = mfx->uiapplication; tmp; tmp = tmp->next) {
		if (tmp->exec == NULL || tmp->ui_gadget == NULL ||
				strcasecmp(tmp->ui_gadget, "true") != 0)
			continue;

		if (_check_bin_directory(mfx->package))
			continue;

		ret = symlink(UG_CLIENT, tmp->exec);
		if (ret != 0)
			printf("failed to install ug %s: %s\n", tmp->exec,
					strerror(errno));
	}

	pkgmgr_parser_free_manifest_xml(mfx);

	return 0;
}

static void _print_usage(const char *cmd)
{
	printf("usage: %s <manifest>\n", cmd);
}

int main(int argc, char *argv[])
{
	int ret;

	if (getuid() != OWNER_ROOT && getuid() != GLOBAL_USER) {
		printf("Only root or tizenglobalapp user is allowed\n");
		return -1;
	}

	if (argc < 2) {
		_print_usage(argv[0]);
		return -1;
	}

	ret = _install_ug(argv[1]);

	return ret;
}
