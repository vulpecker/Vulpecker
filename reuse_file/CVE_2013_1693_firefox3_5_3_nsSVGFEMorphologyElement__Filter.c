
nsresult
CVE_2013_1693_firefox3_5_3_nsSVGFEMorphologyElement::Filter(nsSVGFilterInstance *instance,
                                 const nsTArray<const Image*>& aSources,
                                 const Image* aTarget,
                                 const nsIntRect& rect)
{
#ifdef DEBUG_tor
  fprintf(stderr, "FILTER MORPH rect: %d,%d  %dx%d\n",
          rect.x, rect.y, rect.width, rect.height);
#endif

  PRInt32 rx, ry;
  GetRXY(&rx, &ry, *instance);

  if (rx < 0 || ry < 0) {
    // XXX nsSVGUtils::ReportToConsole()
    return NS_OK;
  }
  if (rx == 0 && ry == 0) {
    return NS_OK;
  }

  PRUint8* sourceData = aSources[0]->mImage->Data();
  PRUint8* targetData = aTarget->mImage->Data();
  PRUint32 stride = aTarget->mImage->Stride();
  PRUint32 xExt[4], yExt[4];  // X, Y indices of RGBA extrema
  PRUint8 extrema[4];         // RGBA magnitude of extrema
  PRUint16 op = mEnumAttributes[OPERATOR].GetAnimValue();

  /* Scan the kernel for each pixel to determine max/min RGBA values.  Note that
   * as we advance in the x direction, each kernel overlaps the previous kernel.
   * Thus, we can avoid iterating over the entire kernel by comparing the
   * leading edge of the new kernel against the extrema found in the previous
   * kernel.   We must still scan the entire kernel if the previous extrema do
   * not fall within the current kernel or if we are starting a new row.
   */
  for (PRInt32 y = rect.y; y < rect.YMost(); y++) {
    PRUint32 startY = PR_MAX(0, y - ry);
    // We need to read pixels not just in 'rect', which is limited to
    // the dirty part of our filter primitive subregion, but all pixels in
    // the given radii from the source surface, so use the surface size here.
    PRUint32 endY = PR_MIN(y + ry, instance->GetSurfaceHeight() - 1);
    for (PRInt32 x = rect.x; x < rect.XMost(); x++) {
      PRUint32 startX = PR_MAX(0, x - rx);
      PRUint32 endX = PR_MIN(x + rx, instance->GetSurfaceWidth() - 1);
      PRUint32 targIndex = y * stride + 4 * x;

      // We need to scan the entire kernel
      if (x == rect.x || xExt[0]  <= startX || xExt[1] <= startX ||
          xExt[2] <= startX || xExt[3] <= startX) {
        PRUint32 i;
        for (i = 0; i < 4; i++) {
          extrema[i] = sourceData[targIndex + i];
        }
        for (PRUint32 y1 = startY; y1 <= endY; y1++) {
          for (PRUint32 x1 = startX; x1 <= endX; x1++) {
            for (i = 0; i < 4; i++) {
              PRUint8 pixel = sourceData[y1 * stride + 4 * x1 + i];
              if ((extrema[i] >= pixel &&
                   op == nsSVGFEMorphologyElement::SVG_OPERATOR_ERODE) ||
                  (extrema[i] <= pixel &&
                   op == nsSVGFEMorphologyElement::SVG_OPERATOR_DILATE)) {
                extrema[i] = pixel;
                xExt[i] = x1;
                yExt[i] = y1;
              }
            }
          }
        }
      } else { // We only need to look at the newest column
        for (PRUint32 y1 = startY; y1 <= endY; y1++) {
          for (PRUint32 i = 0; i < 4; i++) {
            PRUint8 pixel = sourceData[y1 * stride + 4 * endX + i];
            if ((extrema[i] >= pixel &&
                 op == nsSVGFEMorphologyElement::SVG_OPERATOR_ERODE) ||
                (extrema[i] <= pixel &&
                 op == nsSVGFEMorphologyElement::SVG_OPERATOR_DILATE)) {
                extrema[i] = pixel;
                xExt[i] = endX;
                yExt[i] = y1;
            }
          }
        }
      }
      targetData[targIndex  ] = extrema[0];
      targetData[targIndex+1] = extrema[1];
      targetData[targIndex+2] = extrema[2];
      targetData[targIndex+3] = extrema[3];
    }
  }
  return NS_OK;
}