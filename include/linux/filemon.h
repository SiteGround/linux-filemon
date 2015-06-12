#ifndef __LINUX_FILEMON_H
#define __LINUX_FILEMON_H

/*
 * include/linux/filemon.h - dentry-based file event notifications
 *
 * WARNING! This patch has been designed as EXPERIMENTAL. Its usage
 * is DANGEROUS, because some filesystems could get exhausted by the
 * masses of ORPHAN INODES!
 *
 * Copyright (C) 2012 1&1 Internet AG - http://www.1und1.de
 *
 * Authors:
 * Stela Suciu <stela.suciu@gmail.com>, <stela.suciu@1and1.ro>
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

#include <linux/filemon_defs.h>

#ifdef __KERNEL__

#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>
#include <linux/mnt_namespace.h>
#include <linux/fs.h>
#include <linux/mm.h>

#ifdef CONFIG_FILEMON

extern struct semaphore filemon_mutex;   /* for atomicity of read() */
extern spinlock_t filemon_dirty_lock;    /* to protect the lists */
extern struct filemon_base filemon_dirty_list; /* dirty lists */
extern unsigned int filemon_mask;        /* event mask */

extern void filemon_killall_dirty(struct super_block *sb);
extern void __filemon_killall_dirty(struct super_block *sb);

extern void d_dirtify(struct dentry *dentry, int flag_bit);

static inline
bool __d_free_dirty(struct dentry * dentry)
{
	struct filemon_info *info = &dentry->d_filemon;
	bool ok = !list_empty(&info->fi_dirty);
	if (ok) {
		list_del_init(&info->fi_dirty);
		filemon_dirty_list.fb_dirty_count--;
	}
	return ok;
}

static inline
bool __d_reenter_dirty(struct dentry * dentry)
{
	struct filemon_info *info = &dentry->d_filemon;
	bool ok = !!list_empty(&info->fi_dirty);
	if (ok) {
		list_add(&info->fi_dirty, &filemon_dirty_list.fb_dirty);
		filemon_dirty_list.fb_dirty_count++;
	}
	return ok;
}

static inline
bool d_reenter_dirty(struct dentry * dentry, struct filemon_info *copy)
{
#ifdef CONFIG_FILEMON_COUNTERS
	int i;
#endif
	bool ok;

        spin_lock(&filemon_dirty_lock);
	dentry->d_filemon.fi_fflags |= copy->fi_fflags;
#ifdef CONFIG_FILEMON_COUNTERS
	for(i = 0; i < FM_MAX; i++)
		dentry->d_filemon.fi_counter[i] += copy->fi_counter[i];
#endif
	ok = __d_reenter_dirty(dentry);
        spin_unlock(&filemon_dirty_lock);
	return ok;
}

/*
 * Get the LRU-eldest dentry from one of the global dirty lists.
 * The caller must either dput() it later, or reenter it
 * via d_reenter_dirty().
 * This must not be called from interrupt context.
 */
static inline
struct dentry *d_get_dirty(struct filemon_info *copy)
{
	struct dentry * dentry;
	struct filemon_info *info;

        spin_lock(&filemon_dirty_lock);

	if(list_empty(&filemon_dirty_list.fb_dirty)) {
		spin_unlock(&filemon_dirty_lock);
		return NULL;
	}

	dentry = list_first_entry(&filemon_dirty_list.fb_dirty, struct dentry,
				  d_filemon.fi_dirty);

	__d_free_dirty(dentry);

	info = &dentry->d_filemon;
	memcpy(copy, info, sizeof(struct filemon_info));
	info->fi_fflags = 0;
#ifdef CONFIG_FILEMON_COUNTERS
	memset(info->fi_counter, 0, sizeof(info->fi_counter));
#endif

        spin_unlock(&filemon_dirty_lock);

	return dentry;
}

#else
#define d_dirtify(dentry,flags)         /*empty*/
#define d_get_dirty(copy)             NULL
#define d_free_dirty(dentry)      /*empty*/
#define filemon_killall_dirty(sb) /*empty*/
#endif

#endif /* __KERNEL__ */

#endif	/* __LINUX_FILEMON_H */
