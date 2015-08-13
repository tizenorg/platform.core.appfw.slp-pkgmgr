#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include <pkgmgr-info.h>
#include <pkgmgr_parser.h>
#include <tzplatform_config.h>

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define UG_CLIENT tzplatform_mkpath(TZ_SYS_BIN, "ug-client")

static int _install_ug(const char *manifest)
{
	manifest_x *mfx;
	uiapplication_x *tmp;
	const char *exec;
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
