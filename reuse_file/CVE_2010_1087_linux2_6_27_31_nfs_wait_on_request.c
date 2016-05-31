int
CVE_2010_1087_linux2_6_27_31_nfs_wait_on_request(struct nfs_page *req)
{
	int ret = 0;

	if (!test_bit(PG_BUSY, &req->wb_flags))
		goto out;
	ret = out_of_line_wait_on_bit(&req->wb_flags, PG_BUSY,
			nfs_wait_bit_killable, TASK_KILLABLE);
out:
	return ret;
}