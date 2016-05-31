
static void CVE_2009_0859_linux2_6_23_shm_get_stat(struct ipc_namespace *ns, unsigned long *rss,
		unsigned long *swp)
{
	int i;

	*rss = 0;
	*swp = 0;

	for (i = 0; i <= shm_ids(ns).max_id; i++) {
		struct shmid_kernel *shp;
		struct inode *inode;

		shp = shm_get(ns, i);
		if(!shp)
			continue;

		inode = shp->shm_file->f_path.dentry->d_inode;

		if (is_file_hugepages(shp->shm_file)) {
			struct address_space *mapping = inode->i_mapping;
			*rss += (HPAGE_SIZE/PAGE_SIZE)*mapping->nrpages;
		} else {
			struct shmem_inode_info *info = SHMEM_I(inode);
			spin_lock(&info->lock);
			*rss += inode->i_mapping->nrpages;
			*swp += info->swapped;
			spin_unlock(&info->lock);
		}
	}
}