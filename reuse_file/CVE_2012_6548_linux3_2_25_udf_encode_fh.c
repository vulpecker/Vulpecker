static int CVE_2012_6548_linux3_2_25_udf_encode_fh(struct dentry *de, __u32 *fh, int *lenp,
			 int connectable)
{
	int len = *lenp;
	struct inode *inode =  de->d_inode;
	struct kernel_lb_addr location = UDF_I(inode)->i_location;
	struct fid *fid = (struct fid *)fh;
	int type = FILEID_UDF_WITHOUT_PARENT;

	if (connectable && (len < 5)) {
		*lenp = 5;
		return 255;
	} else if (len < 3) {
		*lenp = 3;
		return 255;
	}

	*lenp = 3;
	fid->udf.block = location.logicalBlockNum;
	fid->udf.partref = location.partitionReferenceNum;
	fid->udf.generation = inode->i_generation;

	if (connectable && !S_ISDIR(inode->i_mode)) {
		spin_lock(&de->d_lock);
		inode = de->d_parent->d_inode;
		location = UDF_I(inode)->i_location;
		fid->udf.parent_block = location.logicalBlockNum;
		fid->udf.parent_partref = location.partitionReferenceNum;
		fid->udf.parent_generation = inode->i_generation;
		spin_unlock(&de->d_lock);
		*lenp = 5;
		type = FILEID_UDF_WITH_PARENT;
	}

	return type;
}