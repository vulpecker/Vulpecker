static void sbr_qmf_synthesis(DSPContext *dsp, FFTContext *mdct,
                              float *out, float X[2][38][64],
                              float mdct_buf[2][64],
                              float *v0, int *v_off, const unsigned int div,
                              float bias, float scale)
{
    int i, n;
    const float *sbr_qmf_window = div ? sbr_qmf_window_ds : sbr_qmf_window_us;
    int scale_and_bias = scale != 1.0f || bias != 0.0f;
    float *v;
    for (i = 0; i < 32; i++) {
        if (*v_off == 0) {
            int saved_samples = (1280 - 128) >> div;
            memcpy(&v0[SBR_SYNTHESIS_BUF_SIZE - saved_samples], v0, saved_samples * sizeof(float));
            *v_off = SBR_SYNTHESIS_BUF_SIZE - saved_samples - (128 >> div);
        } else {
            *v_off -= 128 >> div;
        }
        v = v0 + *v_off;
        if (div) {
            for (n = 0; n < 32; n++) {
                X[0][i][   n] = -X[0][i][n];
                X[0][i][32+n] =  X[1][i][31-n];
            }
            ff_imdct_half(mdct, mdct_buf[0], X[0][i]);
            for (n = 0; n < 32; n++) {
                v[     n] =  mdct_buf[0][63 - 2*n];
                v[63 - n] = -mdct_buf[0][62 - 2*n];
            }
        } else {
            for (n = 1; n < 64; n+=2) {
                X[1][i][n] = -X[1][i][n];
            }
            ff_imdct_half(mdct, mdct_buf[0], X[0][i]);
            ff_imdct_half(mdct, mdct_buf[1], X[1][i]);
            for (n = 0; n < 64; n++) {
                v[      n] = -mdct_buf[0][63 -   n] + mdct_buf[1][  n    ];
                v[127 - n] =  mdct_buf[0][63 -   n] + mdct_buf[1][  n    ];
            }
        }
        dsp->vector_fmul_add(out, v                , sbr_qmf_window               , zero64, 64 >> div);
        dsp->vector_fmul_add(out, v + ( 192 >> div), sbr_qmf_window + ( 64 >> div), out   , 64 >> div);
        dsp->vector_fmul_add(out, v + ( 256 >> div), sbr_qmf_window + (128 >> div), out   , 64 >> div);
        dsp->vector_fmul_add(out, v + ( 448 >> div), sbr_qmf_window + (192 >> div), out   , 64 >> div);
        dsp->vector_fmul_add(out, v + ( 512 >> div), sbr_qmf_window + (256 >> div), out   , 64 >> div);
        dsp->vector_fmul_add(out, v + ( 704 >> div), sbr_qmf_window + (320 >> div), out   , 64 >> div);
        dsp->vector_fmul_add(out, v + ( 768 >> div), sbr_qmf_window + (384 >> div), out   , 64 >> div);
        dsp->vector_fmul_add(out, v + ( 960 >> div), sbr_qmf_window + (448 >> div), out   , 64 >> div);
        dsp->vector_fmul_add(out, v + (1024 >> div), sbr_qmf_window + (512 >> div), out   , 64 >> div);
        dsp->vector_fmul_add(out, v + (1216 >> div), sbr_qmf_window + (576 >> div), out   , 64 >> div);
        if (scale_and_bias)
            for (n = 0; n < 64 >> div; n++)
                out[n] = out[n] * scale + bias;
        out += 64 >> div;
    }
}