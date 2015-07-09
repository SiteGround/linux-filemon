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

#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/filemon.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/rculist.h>
#include <linux/mount.h>

/* Protects all procfs interactions */
static DEFINE_MUTEX(filemon_proc_mutex);
/* Protects filemon_dirty_list */
DEFINE_SPINLOCK(filemon_dirty_lock);

struct filemon_base filemon_dirty_list = {
	LIST_HEAD_INIT(filemon_dirty_list.fb_dirty), 0
};

/* This lock protects only the write-side critical section */
static DEFINE_SPINLOCK(filemon_dir_lock);
static LIST_HEAD(filemon_dir_list);
struct filemon_dir_entry {
	struct file *file;
	struct list_head entry;
};

//this is eclusion mask. 
unsigned int filemon_exclusion_mask = FILEMON_OPEN | FILEMON_CLOSE | FILEMON_READ | FILEMON_STAT | FILEMON_READDIR | FILEMON_FLOCK | FILEMON_PLOCK;

/* Access to this scratch space is also protected by filemon_proc_mutex */
static char str_scratch[PATH_MAX];
static bool filemon_enabled = false;
static unsigned long filemon_listlimit = 0;


static bool should_log(struct dentry *target, int flag_bit)
{
	struct filemon_dir_entry *member;
	bool ret = false;
	bool rename_lock_held = (flag_bit == FM_MOVED_FROM)
				|| (flag_bit == FM_MOVED_TO);
	rcu_read_lock();
	if (list_empty(&filemon_dir_list))
		ret = true;

	list_for_each_entry_rcu(member, &filemon_dir_list, entry) {
		if (rename_lock_held)
			ret = d_ancestor(member->file->f_path.dentry, target) != NULL;
		else
			ret = is_subdir(target, member->file->f_path.dentry);

		if (ret)
			break;
	}
	rcu_read_unlock();

	return ret;
}
/*
 * Remember this dentry in the active dirty list and pin it via dget().
 * It remains there until you remove it by d_get_dirty()
 * and finally dput() it.
 */
void d_dirtify(struct dentry *dentry, int flag_bit)
{
	struct dentry *unpin = dentry;
	struct filemon_info *info;
	if (flag_bit < 0 || flag_bit >= FM_MAX)
		BUG();

	if ((1u << flag_bit) & filemon_exclusion_mask)
		return;

	dget(dentry);

	if (!should_log(dentry, flag_bit))
		goto unpin;

	// don't dirtify on inactive / currently umounting filesystems
        if (!(dentry->d_sb->s_flags & MS_ACTIVE))
		goto unpin;

	// suppress special filesystems like /proc, but not nfs
        if (!(dentry->d_sb->s_type->fs_flags & FS_REQUIRES_DEV)
	    && strcmp(dentry->d_sb->s_type->name, "nfs")
	    && strcmp(dentry->d_sb->s_type->name, "nfs4"))
		goto unpin;


	/* Record what interests us */
	info = &dentry->d_filemon;
	info->fi_ctime = ktime_get_real_ns(); 
	info->fi_lastflag = (1 << flag_bit);
	info->fi_fflags |= (1u << flag_bit);
#ifdef CONFIG_FILEMON_COUNTERS
	info->fi_counter[flag_bit]++;
#endif

	// It is possible that an already dirtied dentry is
	// dirtied again, in this case what do is just re-enter it
	// into the list and drop the extra reference we've taken in
	// this function. If the entry is being dirtied for the first time
	// then do the correct accounting and make sure we don't drop the
	// reference.
	spin_lock(&filemon_dirty_lock);
	if (list_empty(&info->fi_dirty)) {
		filemon_dirty_list.fb_dirty_count++;
		unpin = NULL;
	} else
		list_del(&info->fi_dirty);

	list_add_tail(&info->fi_dirty, &filemon_dirty_list.fb_dirty);
	spin_unlock(&filemon_dirty_lock);

unpin:
	if (unpin)
		dput(dentry);
}
EXPORT_SYMBOL(d_dirtify);

/* Free all dentries from the given superblock.
 * If sb==NULL, globally free all (used on overflow).
 * Called with the filemon_dirty_lock taken; it releases it.
 */
void __filemon_killall_dirty(struct super_block *sb)
{
	struct dentry *dentry;
	struct list_head remember = LIST_HEAD_INIT(remember);
	while(!list_empty(&filemon_dirty_list.fb_dirty)) {
		dentry = list_first_entry(&filemon_dirty_list.fb_dirty,
					  struct dentry, d_filemon.fi_dirty);
		if (!sb || dentry->d_sb == sb) {
		        __d_free_dirty(dentry);
			spin_unlock(&filemon_dirty_lock);
			dput(dentry);
			spin_lock(&filemon_dirty_lock);
		} else {
			/* note: it does not matter when it is removed from remember
			 * during the next spin_unlock(). it just does the work
			 * of the later list_splice() in advance.
			 */
			list_move_tail(&dentry->d_filemon.fi_dirty, &remember);
		}
	}
	list_splice_tail(&remember, &filemon_dirty_list.fb_dirty);
	spin_unlock(&filemon_dirty_lock);
}
EXPORT_SYMBOL(__filemon_killall_dirty);

/* Free all dentries from the given superblock.
 * If sb==NULL, globally free all (used on overflow).
 */
void filemon_killall_dirty(struct super_block *sb)
{

	mutex_lock(&filemon_proc_mutex);
	spin_lock(&filemon_dirty_lock);
	__filemon_killall_dirty(sb);
	mutex_unlock(&filemon_proc_mutex);
}
EXPORT_SYMBOL(filemon_killall_dirty);


struct filemon_iter_state {
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

	iter->dentry = d_get_dirty(&iter->metadata);
	iter->pos = *pos;
	if (!iter->dentry)
		return NULL;

	return iter;
}


static void *filemon_seq_next(struct seq_file *s, void *v, loff_t *pos)
{

	/* When we are here we need to free the current entry and then 
	 * get another one
	 */
	struct filemon_iter_state *iter = v;
	pr_debug("[filemon_seq_next]\n");

	/* Handle the case where we have copied a very 
	 * long file name
	 */
	if (dname_external(iter->dentry) && (iter->metadata.fi_fflags & FILEMON_MOVED_FROM)) {
		struct external_name *old_name = external_name(iter->dentry);

		if (old_name && (atomic_dec_and_test(&old_name->u.count)))
			kfree_rcu(old_name, u.head);
	}

	/* Put the extra ref that we have taken when this
	 * dentry was put into the dirty list
	 */
	dput(iter->dentry);

	if (filemon_listlimit && iter->pos >= filemon_listlimit - 1) {
		pr_debug("%s: listlimit reached. idx = %lld\n", __func__, iter->pos);
		return NULL;
	}

	iter->dentry = d_get_dirty(&iter->metadata);
	*pos += 1;
	iter->pos = *pos;


	if (!iter->dentry)
		return NULL;

	return iter;
}

static void filemon_seq_stop(struct seq_file *s, void *v)
{
	filemon_enabled = false;
	mutex_unlock(&filemon_proc_mutex);
	pr_debug("==================[filemon_seq_stop]====================\n");
}


extern void path_for_dentry(struct dentry *dentry, struct path *path);

static int filemon_seq_show(struct seq_file *s, void *v)
{
	struct filemon_iter_state *iter= v;
	struct path path;
	char *path_buf;
	struct timespec time;
	int ret = -EFAULT;

	path_for_dentry(iter->dentry, &path);

	BUG_ON(path.dentry != iter->dentry);

	path_buf = d_absolute_path(&path, str_scratch, PATH_MAX);
	pr_debug("filemon_seq_show\n");
	if (IS_ERR(path_buf))
		goto out;

	time = ns_to_timespec((s64)iter->metadata.fi_ctime);
	seq_printf(s, "[%lld] %-2ld.%09ld %08x %-12s\n",
	        iter->pos,
	        (unsigned long)time.tv_sec,
	        time.tv_nsec,
	        iter->metadata.fi_lastflag,
	        path_buf);
	ret = 0;

out:
	path_put(&path);

	return ret;
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
		return -EINVAL;

	filemon_enabled = tmp_number ? true : false;

	return count;
}

static inline int filemon_enabled_show(struct seq_file *m, void *v)
{
	return seq_printf(m, "%d\n", filemon_enabled);
}

static inline int filemon_enabled_open(struct inode *inode, struct file *file)
{
	return single_open(file, filemon_enabled_show, NULL);
}

static ssize_t filemon_listlimit_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *pos)
{
	char tmp[4];
	unsigned long tmp_number;

	mutex_lock(&filemon_proc_mutex);
	if (count > sizeof(tmp))
		count = sizeof(tmp);

	if (copy_from_user(tmp, buf, count)) {
		count = -EFAULT;
		goto out;
	}

	if (kstrtoul(strstrip(tmp), 0, &tmp_number)) {
		count = -EINVAL;
		goto out;
	}

	filemon_listlimit = tmp_number;

out:
	mutex_unlock(&filemon_proc_mutex);
	return count;
}

static inline int filemon_listlimit_show(struct seq_file *m, void *v)
{
	int ret;
	mutex_lock(&filemon_proc_mutex);
	ret = seq_printf(m, "%lu\n", filemon_listlimit);
	mutex_unlock(&filemon_proc_mutex);

	return ret;
}

static inline int filemon_listlimit_open(struct inode *inode, struct file *file)
{
	return single_open(file, filemon_listlimit_show, NULL);
}

static inline int filemon_dirtycount_show(struct seq_file *m, void *v)
{
	int ret;
	mutex_lock(&filemon_proc_mutex);
	ret = seq_printf(m, "%lu\n", filemon_dirty_list.fb_dirty_count);
	mutex_unlock(&filemon_proc_mutex);

	return ret;
}

static inline int filemon_dirtycount_open(struct inode *inode, struct file *file)
{
	return single_open(file, filemon_dirtycount_show, NULL);
}

static ssize_t filemon_mask_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *pos)
{
	char tmp[4];
	unsigned long tmp_number;

	if (count > sizeof(tmp))
		count = sizeof(tmp);

	if (copy_from_user(tmp, buf, count))
		return -EFAULT;

	if (kstrtoul(strstrip(tmp), 0, &tmp_number))
		return -EINVAL;

	filemon_exclusion_mask = tmp_number;

	return count;
}

static inline int filemon_mask_show(struct seq_file *m, void *v)
{
	return seq_printf(m, "%x\n", filemon_exclusion_mask);
}

static inline int filemon_mask_open(struct inode *inode, struct file *file)
{
	return single_open(file, filemon_mask_show, NULL);
}

static ssize_t filemon_filter_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *pos)
{
	char *tmp, *new_line;
	struct filemon_dir_entry *dir;
	ssize_t ret = -EFAULT;

	mutex_lock(&filemon_proc_mutex);
	if (count >= PAGE_SIZE)
		count = PAGE_SIZE - 1;

	if (*pos != 0) {
		ret = -EINVAL;
		goto unlock;
	}

	tmp = (char*)__get_free_page(GFP_TEMPORARY);
	if (!tmp) {
		ret = -ENOMEM;
		goto unlock;
	}

	dir = kzalloc(sizeof(*dir), GFP_KERNEL);
	if (!dir) {
		ret = -ENOMEM;
		goto out_free_page;
	}

	if (copy_from_user(tmp, buf, count)) {
		ret = -EFAULT;
		goto out_free_mem;
	}

	new_line = memchr(tmp, '\n', count);
	if (new_line)
		tmp[(new_line - tmp)] = '\0';
	else
		tmp[count] = '\0';


	dir->file = filp_open(tmp, O_DIRECTORY, 0655);
	if (IS_ERR(dir->file)) {
		ret = PTR_ERR(dir->file);
		goto out_free_mem;
	}

	spin_lock(&filemon_dir_lock);
	list_add_tail_rcu(&dir->entry, &filemon_dir_list);
	spin_unlock(&filemon_dir_lock);

	free_page((unsigned long) tmp);

	mutex_unlock(&filemon_proc_mutex);

	return count;

out_free_mem:
	kfree(dir);
out_free_page:
	free_page((unsigned long) tmp);
unlock:
	mutex_unlock(&filemon_proc_mutex);
	return ret;
}

static inline int filemon_filter_show(struct seq_file *m, void *v)
{
	uint32_t i = 0;
	struct filemon_dir_entry *entry;

	mutex_lock(&filemon_proc_mutex);
	rcu_read_lock();
	list_for_each_entry_rcu(entry, &filemon_dir_list, entry) {
		char *path = d_absolute_path(&entry->file->f_path, str_scratch, PATH_MAX);
		seq_printf(m, "[%u]: %s\n", i, path);
		++i;

	}
	rcu_read_unlock();
	mutex_unlock(&filemon_proc_mutex);
	return 0;
}

static inline int filemon_filter_open(struct inode *inode, struct file *file)
{
	return single_open(file, filemon_filter_show, NULL);
}

static const struct file_operations proc_filemon_filter_ops = {
	.open = filemon_filter_open,
	.write = filemon_filter_write,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations proc_filemon_dirtycount_ops = {
	.open = filemon_dirtycount_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations proc_filemon_enabled_ops = {
	.open = filemon_enabled_open,
	.read = seq_read,
	.write = filemon_enabled_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations proc_filemon_mask_ops = {
	.open = filemon_mask_open,
	.read = seq_read,
	.write = filemon_mask_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations proc_filemon_listlimit_ops = {
	.open = filemon_listlimit_open,
	.read = seq_read,
	.write = filemon_listlimit_write,
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
		return seq_open_private(file, &filemon_seq_ops,
					sizeof(struct filemon_iter_state));

	return -EACCES;
}


static const struct file_operations proc_filemon_buffer_ops = {
	.open = filemon_buffer_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};


static int proc_filemon_init(void)
{
	struct proc_dir_entry *filemon_dir = proc_mkdir("filemon", NULL);

	proc_create("buffer", 0, filemon_dir, &proc_filemon_buffer_ops);
	proc_create("path_filter", 0, filemon_dir, &proc_filemon_filter_ops);
	proc_create("excluded_events", 0, filemon_dir, &proc_filemon_mask_ops);
	proc_create("dirty_count", 0, filemon_dir, &proc_filemon_dirtycount_ops);
	proc_create("enabled", 0, filemon_dir, &proc_filemon_enabled_ops);
	proc_create("listing_limit", 0, filemon_dir,
		    &proc_filemon_listlimit_ops);
	return 0;
}
late_initcall(proc_filemon_init);
