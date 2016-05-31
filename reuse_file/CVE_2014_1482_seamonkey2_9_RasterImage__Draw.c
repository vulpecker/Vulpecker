NS_IMETHODIMP
CVE_2014_1482_seamonkey2_9_RasterImage::Draw(gfxContext *aContext,
                  gfxPattern::GraphicsFilter aFilter,
                  const gfxMatrix &aUserSpaceToImageSpace,
                  const gfxRect &aFill,
                  const nsIntRect &aSubimage,
                  const nsIntSize& /*aViewportSize - ignored*/,
                  PRUint32 aFlags)
{
  if (mError)
    return NS_ERROR_FAILURE;

  // Disallowed in the API
  if (mInDecoder && (aFlags & imgIContainer::FLAG_SYNC_DECODE))
    return NS_ERROR_FAILURE;

  // Illegal -- you can't draw with non-default decode flags.
  // (Disabling colorspace conversion might make sense to allow, but
  // we don't currently.)
  if ((aFlags & DECODE_FLAGS_MASK) != DECODE_FLAGS_DEFAULT)
    return NS_ERROR_FAILURE;

  NS_ENSURE_ARG_POINTER(aContext);

  // We can only draw with the default decode flags
  if (mFrameDecodeFlags != DECODE_FLAGS_DEFAULT) {
    if (!CanForciblyDiscard())
      return NS_ERROR_NOT_AVAILABLE;
    ForceDiscard();

    mFrameDecodeFlags = DECODE_FLAGS_DEFAULT;
  }

  // We use !mDecoded && mHasSourceData to mean discarded.
  if (!mDecoded && mHasSourceData) {
      mDrawStartTime = TimeStamp::Now();
  }

  // If a synchronous draw is requested, flush anything that might be sitting around
  if (aFlags & FLAG_SYNC_DECODE) {
    nsresult rv = SyncDecode();
    NS_ENSURE_SUCCESS(rv, rv);
  }

  imgFrame *frame = GetCurrentDrawableImgFrame();
  if (!frame) {
    return NS_OK; // Getting the frame (above) touches the image and kicks off decoding
  }

  nsIntRect framerect = frame->GetRect();
  nsIntMargin padding(framerect.x, framerect.y, 
                      mSize.width - framerect.XMost(),
                      mSize.height - framerect.YMost());

  frame->Draw(aContext, aFilter, aUserSpaceToImageSpace, aFill, padding, aSubimage);

  if (mDecoded && !mDrawStartTime.IsNull()) {
      TimeDuration drawLatency = TimeStamp::Now() - mDrawStartTime;
      Telemetry::Accumulate(Telemetry::IMAGE_DECODE_ON_DRAW_LATENCY, PRInt32(drawLatency.ToMicroseconds()));
      // clear the value of mDrawStartTime
      mDrawStartTime = TimeStamp();
  }
  return NS_OK;
}