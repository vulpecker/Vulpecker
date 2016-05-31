
void avcodec_align_dimensions2(AVCodecContext *s, int *width, int *height, int linesize_align[4]){
    int w_align= 1;
    int h_align= 1;

    switch(s->pix_fmt){
    case PIX_FMT_YUV420P:
    case PIX_FMT_YUYV422:
    case PIX_FMT_UYVY422:
    case PIX_FMT_YUV422P:
    case PIX_FMT_YUV440P:
    case PIX_FMT_YUV444P:
    case PIX_FMT_GRAY8:
    case PIX_FMT_GRAY16BE:
    case PIX_FMT_GRAY16LE:
    case PIX_FMT_YUVJ420P:
    case PIX_FMT_YUVJ422P:
    case PIX_FMT_YUVJ440P:
    case PIX_FMT_YUVJ444P:
    case PIX_FMT_YUVA420P:
    case PIX_FMT_YUV420P9LE:
    case PIX_FMT_YUV420P9BE:
    case PIX_FMT_YUV420P10LE:
    case PIX_FMT_YUV420P10BE:
    case PIX_FMT_YUV422P10LE:
    case PIX_FMT_YUV422P10BE:
    case PIX_FMT_YUV444P9LE:
    case PIX_FMT_YUV444P9BE:
    case PIX_FMT_YUV444P10LE:
    case PIX_FMT_YUV444P10BE:
        w_align= 16; //FIXME check for non mpeg style codecs and use less alignment
        h_align= 16;
        if(s->codec_id == CODEC_ID_MPEG2VIDEO || s->codec_id == CODEC_ID_MJPEG || s->codec_id == CODEC_ID_AMV || s->codec_id == CODEC_ID_THP || s->codec_id == CODEC_ID_H264)
            h_align= 32; // interlaced is rounded up to 2 MBs
        break;
    case PIX_FMT_YUV411P:
    case PIX_FMT_UYYVYY411:
        w_align=32;
        h_align=8;
        break;
    case PIX_FMT_YUV410P:
        if(s->codec_id == CODEC_ID_SVQ1){
            w_align=64;
            h_align=64;
        }
    case PIX_FMT_RGB555:
        if(s->codec_id == CODEC_ID_RPZA){
            w_align=4;
            h_align=4;
        }
    case PIX_FMT_PAL8:
    case PIX_FMT_BGR8:
    case PIX_FMT_RGB8:
        if (s->codec_id == CODEC_ID_SMC ||
            s->codec_id == CODEC_ID_CINEPAK) {
            w_align = 4;
            h_align = 4;
        }
        break;
    case PIX_FMT_BGR24:
        if((s->codec_id == CODEC_ID_MSZH) || (s->codec_id == CODEC_ID_ZLIB)){
            w_align=4;
            h_align=4;
        }
        break;
    case PIX_FMT_RGB24:
        if (s->codec_id == CODEC_ID_CINEPAK) {
            w_align = 4;
            h_align = 4;
        }
        break;
    default:
        w_align= 1;
        h_align= 1;
        break;
    }

    *width = FFALIGN(*width , w_align);
    *height= FFALIGN(*height, h_align);
    if(s->codec_id == CODEC_ID_H264 || s->lowres)
        *height+=2; // some of the optimized chroma MC reads one line too much
                    // which is also done in mpeg decoders with lowres > 0

    linesize_align[0] =
    linesize_align[1] =
    linesize_align[2] =
    linesize_align[3] = STRIDE_ALIGN;
//STRIDE_ALIGN is 8 for SSE* but this does not work for SVQ1 chroma planes
//we could change STRIDE_ALIGN to 16 for x86/sse but it would increase the
//picture size unneccessarily in some cases. The solution here is not
//pretty and better ideas are welcome!
#if HAVE_MMX
    if(s->codec_id == CODEC_ID_SVQ1 || s->codec_id == CODEC_ID_VP5 ||
       s->codec_id == CODEC_ID_VP6 || s->codec_id == CODEC_ID_VP6F ||
       s->codec_id == CODEC_ID_VP6A) {
        linesize_align[0] =
        linesize_align[1] =
        linesize_align[2] = 16;
    }
#endif
}