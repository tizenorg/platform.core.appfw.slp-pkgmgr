#define _GNU_SOURCE
#include <unistd.h>
int main(int argc, char **argv, char **env)
{
	setresuid(0,0,0);
	setresgid(0,0,0);
	return execve("/usr/bin/pkgcmd.wrapper",argv,env);
}
