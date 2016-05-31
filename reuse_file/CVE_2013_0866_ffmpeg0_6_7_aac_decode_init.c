
static av_cold int aac_decode_init(AVCodecContext *avctx)
{
    AACContext *ac = avctx->priv_data;

    ac->avctx = avctx;
    ac->m4ac.sample_rate = avctx->sample_rate;

    if (avctx->extradata_size > 0) {
        if (decode_audio_specific_config(ac, avctx->extradata, avctx->extradata_size))
            return -1;
    }

    avctx->sample_fmt = SAMPLE_FMT_S16;

    AAC_INIT_VLC_STATIC( 0, 304);
    AAC_INIT_VLC_STATIC( 1, 270);
    AAC_INIT_VLC_STATIC( 2, 550);
    AAC_INIT_VLC_STATIC( 3, 300);
    AAC_INIT_VLC_STATIC( 4, 328);
    AAC_INIT_VLC_STATIC( 5, 294);
    AAC_INIT_VLC_STATIC( 6, 306);
    AAC_INIT_VLC_STATIC( 7, 268);
    AAC_INIT_VLC_STATIC( 8, 510);
    AAC_INIT_VLC_STATIC( 9, 366);
    AAC_INIT_VLC_STATIC(10, 462);

    ff_aac_sbr_init();

    dsputil_init(&ac->dsp, avctx);

    ac->random_state = 0x1f2e3d4c;

    // -1024 - Compensate wrong IMDCT method.
    // 32768 - Required to scale values to the correct range for the bias method
    //         for float to int16 conversion.

    if (ac->dsp.float_to_int16_interleave == ff_float_to_int16_interleave_c) {
        ac->add_bias  = 385.0f;
        ac->sf_scale  = 1. / (-1024. * 32768.);
        ac->sf_offset = 0;
    } else {
        ac->add_bias  = 0.0f;
        ac->sf_scale  = 1. / -1024.;
        ac->sf_offset = 60;
    }

    ff_aac_tableinit();

    INIT_VLC_STATIC(&vlc_scalefactors,7,FF_ARRAY_ELEMS(ff_aac_scalefactor_code),
                    ff_aac_scalefactor_bits, sizeof(ff_aac_scalefactor_bits[0]), sizeof(ff_aac_scalefactor_bits[0]),
                    ff_aac_scalefactor_code, sizeof(ff_aac_scalefactor_code[0]), sizeof(ff_aac_scalefactor_code[0]),
                    352);

    ff_mdct_init(&ac->mdct, 11, 1, 1.0);
    ff_mdct_init(&ac->mdct_small, 8, 1, 1.0);
    // window initialization
    ff_kbd_window_init(ff_aac_kbd_long_1024, 4.0, 1024);
    ff_kbd_window_init(ff_aac_kbd_short_128, 6.0, 128);
    ff_init_ff_sine_windows(10);
    ff_init_ff_sine_windows( 7);

    cbrt_tableinit();

    return 0;
}