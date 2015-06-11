/*
 * fs/filemon.c - dentry-based file event notifications
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

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/mount.h>
#include <linux/sysctl.h>
#include <linux/nsproxy.h>
#include <linux/fs_struct.h>
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/vfs.h>
#include <linux/filemon.h>
#include <linux/wait.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#include "../internal.h"
#include "../mount.h"

DEFINE_SEMAPHORE(filemon_mutex);
EXPORT_SYMBOL(filemon_mutex);

DEFINE_SPINLOCK(filemon_dirty_lock);
EXPORT_SYMBOL(filemon_dirty_lock);

DECLARE_WAIT_QUEUE_HEAD(filemon_wait);
EXPORT_SYMBOL(filemon_wait);

struct filemon_base filemon_base[FILEMON_MAX] = {
	{ LIST_HEAD_INIT(filemon_base[0].fb_dirty), 0},
	{ LIST_HEAD_INIT(filemon_base[1].fb_dirty), 0},
};
EXPORT_SYMBOL(filemon_base);

int filemon_max_count = 200000;
EXPORT_SYMBOL(filemon_max_count);

unsigned int filemon_mask = FILEMON_OPEN | FILEMON_CLOSE | FILEMON_READ | FILEMON_STAT | FILEMON_READDIR | FILEMON_FLOCK | FILEMON_PLOCK;
EXPORT_SYMBOL(filemon_mask);

int filemon_active = 0;
EXPORT_SYMBOL(filemon_active);

int filemon_overflow = 0;
EXPORT_SYMBOL(filemon_overflow);

int filemon_msleep = 0;
EXPORT_SYMBOL(filemon_msleep);

int filemon_version = 5;
EXPORT_SYMBOL(filemon_version);

static char str_scratch[PATH_MAX];
static bool filemon_enabled;
/*
 * Remember this dentry in the active dirty list and pin it via dget().
 * It remains there until you remove it by d_get_dirty()
 * and finally dput() it.
 */
void d_dirtify(struct dentry *dentry, int flag_bit)
{
	struct dentry * unpin = dentry;
	struct filemon_info *info;
	int wakeup = 0;

	if(flag_bit < 0 || flag_bit >= FM_MAX)
		BUG();

	if((1u << flag_bit) & filemon_mask)
		return;

	dget(dentry);

        spin_lock(&filemon_dirty_lock);

	// don't dirtify on inactive / currently umounting filesystems
        if(!(dentry->d_sb->s_flags & MS_ACTIVE)) {
		goto done;
        }

	// suppress special filesystems like /proc, but not nfs
        if(!(dentry->d_sb->s_type->fs_flags & FS_REQUIRES_DEV) && strcmp(dentry->d_sb->s_type->name, "nfs") && strcmp(dentry->d_sb->s_type->name, "nfs4")) {
		goto done;
        }

	// is the limit exceeded?
	if(filemon_base[0].fb_dirty_count + filemon_base[1].fb_dirty_count >= filemon_max_count) {
	        filemon_overflow = 1;
	}

	// is filemon overflow set?
	if(filemon_overflow) {
		if(filemon_base[0].fb_dirty_count + filemon_base[1].fb_dirty_count > 0 &&
		   !spin_is_locked(&dentry->d_lock)) {
			__filemon_killall_dirty(NULL);
			goto unpin;
		}
		goto done;
	}

	// now we remember what we want to know later...
	info = &dentry->d_filemon[filemon_active];
	info->fi_ctime = current_kernel_time();
	info->fi_fpid = current->pid;
	info->fi_fflags |= (1u << flag_bit);
#ifdef CONFIG_FILEMON_COUNTERS
	info->fi_counter[flag_bit]++;
#endif

	// has it alread been dirtified before? ensure correct bookkeeping.
	if(list_empty(&info->fi_dirty)) {
	        wakeup = !filemon_base[filemon_active].fb_dirty_count++;
		unpin = NULL;
	}

	// now do the real work...
	list_del(&info->fi_dirty);
	list_add_tail(&info->fi_dirty, &filemon_base[filemon_active].fb_dirty);

done:
        spin_unlock(&filemon_dirty_lock);
	if(wakeup) {
		wake_up(&filemon_wait);
	}

unpin:
	if(unpin)
		dput(dentry);

}
EXPORT_SYMBOL(d_dirtify);

static struct vfsmount *get_vfsmount(struct dentry *root_dentry)
{
       struct list_head *lhead;
       struct mount *mnt = NULL;
       struct mnt_namespace *ns = current->nsproxy->mnt_ns;

       if(ns) {
               get_mnt_ns(ns);
               list_for_each(lhead, &ns->list)
               {
                       mnt = list_entry(lhead, struct mount, mnt_list);
                       if (mnt->mnt.mnt_root == root_dentry)
                       {
                               mntget(&mnt->mnt);
			       put_mnt_ns(ns);
                               return &mnt->mnt;
                       }
               }
               put_mnt_ns(ns);
       }
       return NULL;
}

static ssize_t emit_first(struct dentry *dentry, struct filemon_info *info, char *rbuf, ssize_t bufsize, ssize_t namelen)
{
        ssize_t len;
	char str[96];
#ifdef CONFIG_FILEMON_COUNTERS
	int i;
	int add;
#endif
	len = snprintf(str, sizeof(str),
		"%012ld.%09ld %08x %024ld %010u %06d %04d ",
		(unsigned long)info->fi_ctime.tv_sec,
		info->fi_ctime.tv_nsec,
		info->fi_fflags,
		(dentry->d_inode ? dentry->d_inode->i_ino : 0l),
		(unsigned int)(dentry->d_inode ? dentry->d_inode->i_generation : 0),
		info->fi_fpid,
		(int)namelen);
	if(len > bufsize)
	        return -ENOMEM;
	if(len < 0)
		return -EFAULT;

	memcpy(rbuf-len, str, len);

#ifdef CONFIG_FILEMON_COUNTERS
	for(i = FM_MAX-1; i >=0; i--) {
		add = snprintf(str, sizeof(str), "%03d ", info->fi_counter[i]);
		len += add;
		if(len > bufsize)
			return -ENOMEM;
		memcpy(rbuf-len, str, add);
	}
#endif
	return len;
}

static ssize_t emit_element(struct dentry *dentry, char *rbuf, ssize_t bufsize)
{
        ssize_t len = dentry->d_name.len;
	if(len+1 > bufsize)
		return -ENOMEM;
	memcpy(rbuf-len, dentry->d_name.name, len);
	memcpy(rbuf-len-1, "/", 1);

	return len+1;
}

static ssize_t emit_last(struct dentry *dentry, char *rbuf, ssize_t bufsize)
{
	ssize_t len = 1;
	if(bufsize < len)
		return -ENOMEM;
	memcpy(rbuf-1, "\n", 1);
	return len;
}

	if (!*pos)
		seq_puts(s, "No. Modification time\tFlags\tFilename\n");


static ssize_t emit_path(struct dentry *dentry, struct dentry *root, struct vfsmount *rootmnt, struct filemon_info *info, char *rbuf, ssize_t bufsize)
{
        ssize_t pos, ipos;
	ssize_t status;
	struct dentry *original = dentry;
	struct mount *mnt = NULL;
	struct vfsmount *vfsmnt = NULL, *original_vfsmnt = NULL;
	char *path;

	ipos = emit_last(dentry, rbuf, bufsize);
	if(ipos < 0)
		return ipos;

	pos = ipos;

	path = dentry_path_raw(dentry, str_scratch, PATH_MAX);
	if (path < 0)
		return -EFAULT;
	pos += strlen(path) + 1;
	memcpy((rbuf-pos), path, strlen(path) + 1);

/*
	//try to find a vfsmount corresponding to the superblock dentry
	if((vfsmnt = get_vfsmount(dentry->d_sb->s_root)))
		original_vfsmnt = vfsmnt;

	while(dentry != root || vfsmnt != rootmnt) {
		if(IS_ROOT(dentry) || (vfsmnt && dentry == vfsmnt->mnt_root)) {
			// if initial match attempt did not succeed, try again
			// with the first encountered root dentry (works for nfs4)
			if(!vfsmnt) {
				if((vfsmnt = get_vfsmount(dentry)))
					original_vfsmnt = vfsmnt;
				else break;
			}

			br_read_lock(&vfsmount_lock);
			mnt = real_mount(vfsmnt);
			if(mnt->mnt_parent == mnt) {
				br_read_unlock(&vfsmount_lock);
				break;
			}
			dentry = mnt->mnt_mountpoint;
			mnt = mnt->mnt_parent;
			vfsmnt = &mnt->mnt;
			br_read_unlock(&vfsmount_lock);
		}

		status = emit_element(dentry, rbuf - pos, bufsize - pos);
		if(status < 0) {
			if(original_vfsmnt)
				mntput(original_vfsmnt);
			return status;
		}

		dentry = dentry->d_parent;
		pos += status;
	}

	if(original_vfsmnt)
		mntput(original_vfsmnt);

	//if our dentry was root, resolve the path to "/"
	if(pos == ipos) {
		status = emit_slash(dentry, rbuf - pos, bufsize - pos);
		if(status < 0)
			return status;
		pos += status;
	}
*/

	status = emit_first(original, info, rbuf - pos, bufsize - pos, strlen(path));
	if(status < 0)
	        return status;
	return pos + status;
}

static ssize_t do_entry(struct dentry *dentry, struct filemon_info *info, char *rbuf, ssize_t bufsize)
{
	struct dentry *root;
	struct vfsmount *rootmnt;
	ssize_t status;

	spin_lock(&current->fs->lock);
	root = dget(current->fs->root.dentry);
	rootmnt = mntget(current->fs->root.mnt);
	spin_unlock(&current->fs->lock);

	status = emit_path(dentry, root, rootmnt, info, rbuf, bufsize);

	mntput(rootmnt);
	dput(root);
	return status;
}

static ssize_t __sched do_filemon_read(char __user *buf, ssize_t bufsize, int active, int wait)
{
	struct dentry *dentry = NULL;
        ssize_t pos = 0;
	ssize_t status = 0;
	char *reverse_buffer;
	struct filemon_info info;

	seq_printf(s, "[%lld] %-2ld.%09ld %08x %-12s\n",
		iter->pos,
		(unsigned long)iter->metadata.fi_ctime.tv_sec,
		iter->metadata.fi_ctime.tv_nsec,
		iter->metadata.fi_fflags,
		path);
	return 0;
}

	down(&filemon_mutex);
        for(;;) {
		if(signal_pending(current)) {
			if(!pos)
				pos = -ERESTARTSYS;
			break;
		}

	        dentry = d_get_dirty(active, &info);

		if(!dentry) {
			if(!wait || pos > 0)
				break;

			up(&filemon_mutex);
			wait_event_interruptible(filemon_wait, filemon_base[active].fb_dirty_count > 0);
			if(filemon_msleep > 0)
				msleep(filemon_msleep);

			down(&filemon_mutex);
			continue;
		}

		status = do_entry(dentry, &info, reverse_buffer + PAGE_SIZE*2, min(bufsize - pos, (ssize_t)PAGE_SIZE*2));

		if(status < 0)
		        break;

		if(copy_to_user(buf + pos, reverse_buffer + PAGE_SIZE*2 - status, status)) {
			status = -EFAULT;
			break;
		}

		pos += status;
		dput(dentry);
		dentry = NULL;
	}
	/* sorry: it is over. we had to remove it (race avoidance),
	 * thus we have to reenter it now.
	 */
	if(dentry) {
		bool ok = d_reenter_dirty(dentry, &info, active);
		/* it might have been already entered in the meantime by d_dirtify(),
		 * thus we have to correct the d_count in this case...
		 */
		if(!ok)
			dput(dentry);
	}
	up(&filemon_mutex);

	kfree(reverse_buffer);

	// only report errors when nothing could be delivered
	if(!pos)
	        return status;
	return pos;
}

static int __filemon_sysctl_handler(void __user *buffer, size_t *length, loff_t *ppos, int transact, int wait)
{
        ssize_t res;
	int active;

	if (!*length) {
		return 0;
	}

	/* check if the overflow_flag is set, in which case
	 * we should kill all pinned dentries
	 */
	if(filemon_overflow) {
		down(&filemon_mutex);
		spin_lock(&filemon_dirty_lock);

		if (filemon_base[0].fb_dirty_count + filemon_base[1].fb_dirty_count > 0)
			__filemon_killall_dirty(NULL);
		else
			spin_unlock(&filemon_dirty_lock);
		up(&filemon_mutex);
	}

	// shall we switch the active list?
	if(transact && !*ppos) {
		spin_lock(&filemon_dirty_lock);
		if(list_empty(&filemon_base[filemon_active ^ 1].fb_dirty)) {
		        filemon_active ^= 1;
		}
		spin_unlock(&filemon_dirty_lock);
	}

	active = transact ? filemon_active ^ 1 : filemon_active;
	res = do_filemon_read(buffer, *length, active, wait);

	if(res >= 0) {
	        *ppos += res;
		*length = res;
		return 0;
	}

	*length = res;
	return res;
}

static int filemon_sysctl_handler(struct ctl_table *table, int write,
         void __user *buffer, size_t *length, loff_t *ppos)
{
        return __filemon_sysctl_handler(buffer, length, ppos, 0, 0);
}

static int filemon_sysctl_handler_transactional(struct ctl_table *table,
	int write, void __user *buffer, size_t *length, loff_t *ppos)
{
        return __filemon_sysctl_handler(buffer, length, ppos, 1, 0);
}

static int filemon_sysctl_handler_blocking(struct ctl_table *table, int write,
         void __user *buffer, size_t *length, loff_t *ppos)
{
        return __filemon_sysctl_handler(buffer, length, ppos, 0, 1);
}

static int filemon_sysctl_handler_transactional_blocking(struct ctl_table *table,
	int write, void __user *buffer, size_t *length, loff_t *ppos)
{
        return __filemon_sysctl_handler(buffer, length, ppos, 1, 1);
}

struct ctl_table filemon_table[] = {
	{
		.procname	= "version",
		.data		= &filemon_version,
		.maxlen		= sizeof(filemon_version),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec_minmax,
	},
	{
		.procname	= "filemon",
		.mode		= 0400,
		.proc_handler	= &filemon_sysctl_handler,
	},
	{
		.procname	= "filemon-transactional",
		.mode		= 0400,
		.proc_handler	= &filemon_sysctl_handler_transactional,
	},
	{
		.procname	= "filemon-blocking",
		.mode		= 0400,
		.proc_handler	= &filemon_sysctl_handler_blocking,
	},
	{
		.procname	= "filemon-transactional-blocking",
		.mode		= 0400,
		.proc_handler	= &filemon_sysctl_handler_transactional_blocking,
	},
	{
		.procname	= "dirty_count[0]",
		.data		= &filemon_base[0].fb_dirty_count,
		.maxlen		= sizeof(int),
		.mode		= 0400,
		.proc_handler	= &proc_dointvec_minmax,
	},
	{
		.procname	= "dirty_count[1]",
		.data		= &filemon_base[1].fb_dirty_count,
		.maxlen		= sizeof(int),
		.mode		= 0400,
		.proc_handler	= &proc_dointvec_minmax,
	},
	{
		.procname	= "mask",
		.data		= &filemon_mask,
		.maxlen		= sizeof(filemon_mask),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_minmax,
	},
	{
		.procname	= "max_count",
		.data		= &filemon_max_count,
		.maxlen		= sizeof(filemon_max_count),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_minmax,
	},
	{
		.procname	= "overflow",
		.data		= &filemon_overflow,
		.maxlen		= sizeof(filemon_overflow),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_minmax,
	},
	{
		.procname	= "msleep",
		.data		= &filemon_msleep,
		.maxlen		= sizeof(filemon_msleep),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_minmax,
	},
	{ }
};

/* Free all dentries from the given superblock.
 * If sb==NULL, globally free all (used on overflow).
 * Called with the filemon_dirty_lock taken; it releases it.
 */
void __filemon_killall_dirty(struct super_block *sb)
{
	struct list_head *tmp;
	struct dentry * dentry;
	struct list_head remember[FILEMON_MAX] = {
		LIST_HEAD_INIT(remember[0]),
#if FILEMON_MAX > 1
		LIST_HEAD_INIT(remember[1]),
#endif
#if FILEMON_MAX > 2
		LIST_HEAD_INIT(remember[2]),
#endif
	};
	int i;
	for(i = 0; i < FILEMON_MAX; i++) {
		while(!list_empty(&filemon_base[i].fb_dirty)) {
			tmp = filemon_base[i].fb_dirty.next;
			dentry = list_entry(tmp, struct dentry, d_filemon[i].fi_dirty);
			if(!sb || dentry->d_sb == sb) {
			        __d_free_dirty(dentry, i);
				spin_unlock(&filemon_dirty_lock);
				dput(dentry);
				spin_lock(&filemon_dirty_lock);
			} else {
				/* note: it does not matter when it is removed from remember
				 * during the next spin_unlock(). it just does the work
				 * of the later list_splice() in advance.
				 */
				list_move_tail(&dentry->d_filemon[i].fi_dirty, &remember[i]);
			}
		}
		list_splice_tail(&remember[i], &filemon_base[i].fb_dirty);
	}
	spin_unlock(&filemon_dirty_lock);
}
EXPORT_SYMBOL(__filemon_killall_dirty);

/* Free all dentries from the given superblock.
 * If sb==NULL, globally free all (used on overflow).
 */
void filemon_killall_dirty(struct super_block *sb)
{

	down(&filemon_mutex);
	spin_lock(&filemon_dirty_lock);
	__filemon_killall_dirty(sb);
	up(&filemon_mutex);
}
EXPORT_SYMBOL(filemon_killall_dirty);

static DEFINE_MUTEX(filemon_proc_mutex);


struct filemon_seq_info {
	struct dentry *dentry;
	struct filemon_info metadata;
	loff_t pos;
};

static void *filemon_seq_start(struct seq_file *s, loff_t *pos)
{
	struct filemon_iter_state *iter = s->private;

	pr_debug("=================[filemon_seq_start]==================\n");

	/* This is released from filemon_seq_stop */
	mutex_lock(&filemon_proc_mutex);

	if (filemon_listlimit && *pos >= filemon_listlimit - 1)
		return NULL;

	if (!*pos)
		seq_puts(s, "No. Modification time\tFlags\tFilename\n");

	/* If overflow is detected kill all pinned dentries */
	if (filemon_overflow) {
		spin_lock(&filemon_dirty_lock);
		if (filemon_base[0].fb_dirty_count + filemon_base[1].fb_dirty_count > 0) {
			pr_debug("[filemon] Overflow ocurred. Killed all nodes\n");
			__filemon_killall_dirty(NULL);
			filemon_overflow = 0;
			return NULL;
		} else
			spin_unlock(&filemon_dirty_lock);
	}

	/* Begin actual stuff */
	info = kmalloc(sizeof(*info), GFP_KERNEL | GFP_NOFS);
	if (!info)
		return ERR_PTR(-ENOMEM);

	/* For now we are always using filemon_active (should be 0) */
	info->dentry = d_get_dirty(filemon_active, &info->metadata);
	info->pos = *pos;
	if (!info->dentry) {
		pr_debug("Freeing in seq_start\n");
		kfree(info);
		return NULL;
	}

	return info;
}


static void *filemon_seq_next(struct seq_file *s, void *v, loff_t *pos)
{

	/* When we are here we need to free the current entry and then 
	 * get another one
	 */
	struct filemon_seq_info *info = v;
	pr_debug("[filemon_seq_next]\n");

	/* Handle the case where we have copied a very 
	 * long file name
	 */
	if (dname_external(info->dentry) && (info->metadata.fi_fflags & FILEMON_MOVED_FROM)) {
		char *path = dentry_path_raw(info->dentry, str_scratch, PATH_MAX);
		struct external_name *old_name = external_name(info->dentry);

		if (old_name && (atomic_dec_and_test(&old_name->u.count)))
			kfree_rcu(old_name, u.head);
	}

	/* Put the extra ref that we have taken when this
	 * dentry was put into the dirty list
	 */
	dput(info->dentry);

	info->dentry = d_get_dirty(filemon_active, &info->metadata);
	*pos += 1;
	info->pos = *pos;
	if (!info->dentry) {
		pr_debug("freeing allocated in seq_next\n");
		kfree(v);
		return NULL;
	}

	return info;
}

static void filemon_seq_stop(struct seq_file *s, void *v)
{
	filemon_enabled = false;
	mutex_unlock(&filemon_proc_mutex);
	if (v) {
		pr_debug("[fmon]Freeing allocated info\n");
		kfree(v);
	}

	pr_debug("==================[filemon_seq_stop]====================\n");
}

static int filemon_seq_show(struct seq_file *s, void *v)
{
	struct filemon_seq_info *info = v;
	char *path = dentry_path_raw(info->dentry, str_scratch, PATH_MAX);
	pr_debug("filemon_seq_show\n");
	if (path < 0)
		return -EFAULT;

	seq_printf(s, "[%lld] %-2ld.%09ld %08x %-12s\n",
                iter->pos,
                (unsigned long)iter->metadata.fi_ctime.tv_sec,
                iter->metadata.fi_ctime.tv_nsec,
                iter->metadata.fi_fflags,
                path);

	return 0;
}


static ssize_t filemon_enabled_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *pos)
{
	char tmp[4];
	unsigned long tmp_number;

	if (count > sizeof(tmp))
		count = sizeof(tmp);

	if (copy_from_user(tmp, buf, count))
	    return -EFAULT;

	if (kstrtoul(strstrip(tmp), 0, &tmp_number))
		return -EFAULT;

	filemon_enabled = tmp_number ? true : false;

	return count;
}

static int filemon_enabled_show(struct seq_file *m, void *v)
{
	return seq_printf(m, "%d\n", filemon_enabled);
}

static int filemon_enabled_open(struct inode *inode, struct file *file)
{
	return single_open(file, filemon_enabled_show, NULL);
}

static const struct file_operations proc_filemon_enabled_ops = {
	.open = filemon_enabled_open,
	.read = seq_read,
	.write = filemon_enabled_write,
	.llseek = seq_lseek,
	.release = single_release,
};


static const struct seq_operations filemon_seq_ops = {
	.start = filemon_seq_start,
	.next = filemon_seq_next,
	.stop = filemon_seq_stop,
	.show = filemon_seq_show,
};

static int filemon_buffer_open(struct inode* inode, struct file *file)
{
	if (filemon_enabled)
		return seq_open(file, &filemon_seq_ops);

	return -EPERM;
}

static const struct file_operations proc_filemon_buffer_ops = {
	.open = filemon_buffer_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};


static int proc_filemon_init(void)
{
	struct proc_dir_entry *filemon_dir = proc_mkdir("filemon", NULL);

	proc_create("buffer", 0, filemon_dir, &proc_filemon_buffer_ops);
	proc_create("enabled", 0, filemon_dir, &proc_filemon_enabled_ops);
	return 0;
}
late_initcall(proc_filemon_init);
