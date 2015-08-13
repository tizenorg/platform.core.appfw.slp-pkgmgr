#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include <pkgmgr-info.h>
#include <tzplatform_config.h>

#define UG_CLIENT tzplatform_mkpath(TZ_SYS_BIN, "ug-client")

#ifdef _E
#undef _E
#endif
#define _E(fmt, arg...) fprintf(stderr, "[PKG_INSTALL_UG][E] "fmt"\n", ##arg);

#ifdef _D
#undef _D
#endif
#define _D(fmt, arg...) fprintf(stderr, "[PKG_INSTALL_UG][D] "fmt"\n", ##arg);

static int _install_ug(pkgmgrinfo_appinfo_h info, void *user_data)
{
	int ret;
	char *exec;

	ret = pkgmgrinfo_appinfo_get_exec(info, &exec);
	if (ret != PMINFO_R_OK) {
		_E("failed to get exec");
		return -1;
	}

	_D("installing: %s", exec);
	ret = symlink(UG_CLIENT, exec);
	if (ret != 0)
		_E("failed to install ug %s: %s", exec, strerror(errno));

	return 0;
}

static int _process(const char *appid)
{
	int ret;
	pkgmgrinfo_appinfo_h info;

	ret = pkgmgrinfo_appinfo_get_appinfo(appid, &info);
	if (ret != PMINFO_R_OK) {
		_D("failed to get appinfo");
		return -1;
	}

	ret = _install_ug(info, NULL);
	if (ret < 0) {
		pkgmgrinfo_appinfo_destroy_appinfo(info);
		return -1;
	}

	pkgmgrinfo_appinfo_destroy_appinfo(info);

	return 0;
}

static int _process_for_all(void)
{
	int ret;
	pkgmgrinfo_appinfo_filter_h filter;

	ret = pkgmgrinfo_appinfo_filter_create(&filter);
	if (ret != PMINFO_R_OK) {
		_E("failed to create filter");
		return -1;
	}

	ret = pkgmgrinfo_appinfo_filter_add_bool(filter,
			PMINFO_APPINFO_PROP_APP_UI_GADGET, true);
	if (ret != PMINFO_R_OK) {
		_E("failed to add filter property");
		pkgmgrinfo_appinfo_filter_destroy(filter);
		return -1;
	}

	ret = pkgmgrinfo_appinfo_filter_foreach_appinfo(filter, _install_ug,
			NULL);
	if (ret != PMINFO_R_OK) {
		_E("failed to filter foreach appinfo");
		pkgmgrinfo_appinfo_filter_destroy(filter);
		return -1;
	}

	pkgmgrinfo_appinfo_filter_destroy(filter);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (getuid()) {
		_E("ONLY ROOT USER IS ALLOWED");
		return -1;
	}

	_D("start installing ug");

	if (argc < 2)
		ret = _process_for_all();
	else
		ret = _process(argv[1]);

	_D("done, result: %s", ret ? "ERROR" : "OK");

	return ret;
}
