#ifndef __LINUX_FILEMON_DEFS_H
#define __LINUX_FILEMON_DEFS_H
#include <linux/time.h>
/*
 * include/linux/filemon_defs.h - dentry-based file event notifications
 *
 * WARNING! This patch has been designed as EXPERIMENTAL. Its usage
 * is DANGEROUS, because some filesystems could get exhausted by the
 * masses of ORPHAN INODES!
 *
 * Copyright (C) 2012 1&1 Internet AG - http://www.1und1.de
 *
 * Authors:
 * Stela Suciu <stela.suciu@1and1.ro>
 * Thomas Schoebel-Theuer <thomas.schoebel-theuer@1und1.de>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

enum filemon_type {
	FM_MOUNT,
	FM_UMOUNT,
	FM_NEW = 4,
	FM_CREATE,
	FM_LINK,
	FM_MKDIR,
	FM_DELETE,
	FM_MOVED_FROM,
	FM_MOVED_TO,
	FM_OPEN = 12,
	FM_CLOSE,
	FM_READ,
	FM_WRITE,
	FM_STAT,
	FM_READDIR,
	FM_MODIFY = 20,
	FM_ATTR,
	FM_XATTR,
	FM_FLOCK = 24,
	FM_PLOCK,
	// this must remain last
	FM_MAX
};

#define FILEMON_MOUNT                   0x0000001
#define FILEMON_UMOUNT                  0x0000002
#define FILEMON_NEW                     0x0000010
#define FILEMON_CREATE                  0x0000020
#define FILEMON_LINK                    0x0000040
#define FILEMON_MKDIR                   0x0000080
#define FILEMON_DELETE                  0x0000100
#define FILEMON_MOVED_FROM              0x0000200
#define FILEMON_MOVED_TO                0x0000400
#define FILEMON_OPEN                    0x0001000
#define FILEMON_CLOSE                   0x0002000
#define FILEMON_READ                    0x0004000
#define FILEMON_WRITE                   0x0008000
#define FILEMON_STAT                    0x0010000
#define FILEMON_READDIR                 0x0020000
#define FILEMON_MODIFY                  0x0100000
#define FILEMON_ATTR                    0x0200000
#define FILEMON_XATTR                   0x0400000
#define FILEMON_FLOCK                   0x1000000
#define FILEMON_PLOCK                   0x2000000

#define FILEMON_MAX 2

struct filemon_info {
        struct list_head fi_dirty;  /* membership in the corresponding dirty list */
	struct timespec  fi_ctime;  /* timestamp of last dirtifying */
	pid_t            fi_fpid;   /* pid of last dirtifying process */
	unsigned int     fi_fflags; /* filemon flags (see above defines) */
#ifdef CONFIG_FILEMON_COUNTERS
	int              fi_counter[FM_MAX];
#endif
};

struct filemon_base {
        struct list_head fb_dirty;  /* head of dirty list */
	int fb_dirty_count;         /* #entries in list */
};

#endif
