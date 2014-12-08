/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2010, 2013 Piotr Roszatycki <dexter@debian.org>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
*/


#include <config.h>

#include <sys/types.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include "libfakechroot.h"

static int is_proc_exe(const char * path) {
    char *last_sep = strrchr(path, '/');
    return strncmp(path, "/proc/", 6) == 0 /* begins with /proc/ */
        && strchr(path+6, '/') == last_sep /* no / before /exe */
        && strcmp(last_sep, "/exe") == 0;  /* ends with /exe */
}


wrapper(readlink, READLINK_TYPE_RETURN, (const char * path, char * buf, READLINK_TYPE_ARG3(bufsiz)))
{
    int linksize, fd, bytes;
    char tmp[FAKECHROOT_PATH_MAX], *tmpptr,
         read_buf[FAKECHROOT_PATH_MAX];
    const char *fakechroot_base = getenv("FAKECHROOT_BASE");
    const char *fakechroot_elfloader = getenv("FAKECHROOT_ELFLOADER");

    debug("readlink(\"%s\", &buf, %zd)", path, bufsiz);
    expand_chroot_path(path);

    debug("nextcall(readlink)(\"%s\", tmp, %zd)", path, FAKECHROOT_PATH_MAX-1);
    if ((linksize = nextcall(readlink)(path, tmp, FAKECHROOT_PATH_MAX-1)) == -1) {
        return -1;
    }
    tmp[linksize] = '\0';

    if (fakechroot_base != NULL) {
        tmpptr = strstr(tmp, fakechroot_base);
        if (tmpptr != tmp) {
            tmpptr = tmp;
        }
        else if (tmp[strlen(fakechroot_base)] == '\0') {
            tmpptr = "/";
            linksize = strlen(tmpptr);
        }
        else if (tmp[strlen(fakechroot_base)] == '/') {
            tmpptr = tmp + strlen(fakechroot_base);
            linksize -= strlen(fakechroot_base);
        }
        else {
            tmpptr = tmp;
        }

        /* fix /proc/.../exe for ELFLOADER operation */
        if (fakechroot_elfloader && is_proc_exe(path)) {
            strcpy(read_buf, path);
            strcpy(strrchr(read_buf, '/'), "/cmdline");
            if ((fd = open(read_buf, O_RDONLY)) > 0) {
                bytes = read(fd, read_buf, strlen(fakechroot_elfloader)+1);
                if (strcmp(read_buf, fakechroot_elfloader) == 0) {
                    bytes = read(fd, read_buf, FAKECHROOT_PATH_MAX);
                    if (bytes > 0 && strlen(read_buf) > 0) {
                        tmpptr = read_buf;
                        linksize = strlen(tmpptr);
                    }
                }
                close(fd);
            }
        }
    }
    else {
        tmpptr = tmp;
    }

    if (strlen(tmpptr) > bufsiz) {
        linksize = bufsiz;
    }
    strncpy(buf, tmpptr, linksize);
    debug("readlink(\"%s\", \"%s\", %zd) = %zd", path, buf, bufsiz, linksize);
    return linksize;
}
