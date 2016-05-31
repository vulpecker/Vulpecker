
static int seg_write_packet(AVFormatContext *s, AVPacket *pkt)
{
    SegmentContext *seg = s->priv_data;
    AVFormatContext *oc = seg->avf;
    AVStream *st = oc->streams[pkt->stream_index];
    int64_t end_pts;
    int ret;

    if (seg->times) {
        end_pts = seg->segment_count <= seg->nb_times ?
            seg->times[seg->segment_count-1] : INT64_MAX;
    } else {
        end_pts = seg->time * seg->segment_count;
    }

    /* if the segment has video, start a new segment *only* with a key video frame */
    if ((st->codec->codec_type == AVMEDIA_TYPE_VIDEO || !seg->has_video) &&
        av_compare_ts(pkt->pts, st->time_base,
                      end_pts-seg->time_delta, AV_TIME_BASE_Q) >= 0 &&
        pkt->flags & AV_PKT_FLAG_KEY) {

        av_log(s, AV_LOG_DEBUG, "Next segment starts with packet stream:%d pts:%"PRId64" pts_time:%f\n",
               pkt->stream_index, pkt->pts, pkt->pts * av_q2d(st->time_base));

        if ((ret = segment_end(s)) < 0 || (ret = segment_start(s)) < 0)
            goto fail;
        seg->start_time = (double)pkt->pts * av_q2d(st->time_base);
    } else if (pkt->pts != AV_NOPTS_VALUE) {
        seg->end_time = FFMAX(seg->end_time,
                              (double)(pkt->pts + pkt->duration) * av_q2d(st->time_base));
    }

    ret = oc->oformat->write_packet(oc, pkt);

fail:
    if (ret < 0) {
        oc->streams = NULL;
        oc->nb_streams = 0;
        if (seg->list)
            avio_close(seg->list_pb);
        avformat_free_context(oc);
    }

    return ret;
}