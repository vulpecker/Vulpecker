
static int CVE_2012_6537_linux2_6_10_copy_to_user_tmpl(struct xfrm_policy *xp, struct sk_buff *skb)
{
	struct xfrm_user_tmpl vec[XFRM_MAX_DEPTH];
	int i;

	if (xp->xfrm_nr == 0)
		return 0;

	for (i = 0; i < xp->xfrm_nr; i++) {
		struct xfrm_user_tmpl *up = &vec[i];
		struct xfrm_tmpl *kp = &xp->xfrm_vec[i];

		memcpy(&up->id, &kp->id, sizeof(up->id));
		up->family = xp->family;
		memcpy(&up->saddr, &kp->saddr, sizeof(up->saddr));
		up->reqid = kp->reqid;
		up->mode = kp->mode;
		up->share = kp->share;
		up->optional = kp->optional;
		up->aalgos = kp->aalgos;
		up->ealgos = kp->ealgos;
		up->calgos = kp->calgos;
	}
	RTA_PUT(skb, XFRMA_TMPL,
		(sizeof(struct xfrm_user_tmpl) * xp->xfrm_nr),
		vec);

	return 0;

rtattr_failure:
	return -1;
}