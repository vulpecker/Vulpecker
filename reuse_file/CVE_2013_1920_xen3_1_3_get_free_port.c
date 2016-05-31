

static int CVE_2013_1920_xen3_1_3_get_free_port(struct domain *d)
{
    struct evtchn *chn;
    int            port;

    if ( d->is_dying )
        return -EINVAL;

    for ( port = 0; port_is_valid(d, port); port++ )
        if ( evtchn_from_port(d, port)->state == ECS_FREE )
            return port;

    if ( port == MAX_EVTCHNS(d) )
        return -ENOSPC;

    chn = xmalloc_array(struct evtchn, EVTCHNS_PER_BUCKET);
    if ( unlikely(chn == NULL) )
        return -ENOMEM;
    memset(chn, 0, EVTCHNS_PER_BUCKET * sizeof(*chn));
    bucket_from_port(d, port) = chn;

    return port;
}