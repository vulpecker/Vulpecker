
  SpeexCVE_2014_1549_firefox23_0_ResamplerState* CVE_2014_1549_firefox23_0_Resampler(uint32_t aChannels)
  {
    if (aChannels != mChannels && mCVE_2014_1549_firefox23_0_Resampler) {
      speex_resampler_destroy(mCVE_2014_1549_firefox23_0_Resampler);
      mCVE_2014_1549_firefox23_0_Resampler = nullptr;
    }

    if (!mCVE_2014_1549_firefox23_0_Resampler) {
      mChannels = aChannels;
      mCVE_2014_1549_firefox23_0_Resampler = speex_resampler_init(mChannels, mSampleRate,
                                        ComputeFinalOutSampleRate(),
                                        SPEEX_RESAMPLER_QUALITY_DEFAULT,
                                        nullptr);
    }
    return mCVE_2014_1549_firefox23_0_Resampler;
  }