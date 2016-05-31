int CVE_2010_4163_linux2_6_27_31_blk_rq_map_user_iov(struct request_queue *q, struct request *rq,
			struct sg_iovec *iov, int iov_count, unsigned int len)
{
	struct bio *bio;
	int i, read = rq_data_dir(rq) == READ;
	int unaligned = 0;

	if (!iov || iov_count <= 0)
		return -EINVAL;

	for (i = 0; i < iov_count; i++) {
		unsigned long uaddr = (unsigned long)iov[i].iov_base;

		if (uaddr & queue_dma_alignment(q)) {
			unaligned = 1;
			break;
		}
	}

	if (unaligned || (q->dma_pad_mask & len))
		bio = bio_copy_user_iov(q, iov, iov_count, read);
	else
		bio = bio_map_user_iov(q, NULL, iov, iov_count, read);

	if (IS_ERR(bio))
		return PTR_ERR(bio);

	if (bio->bi_size != len) {
		bio_endio(bio, 0);
		bio_unmap_user(bio);
		return -EINVAL;
	}

	if (!bio_flagged(bio, BIO_USER_MAPPED))
		rq->cmd_flags |= REQ_COPY_USER;

	blk_queue_bounce(q, &bio);
	bio_get(bio);
	blk_rq_bio_prep(q, rq, bio);
	rq->buffer = rq->data = NULL;
	return 0;
}