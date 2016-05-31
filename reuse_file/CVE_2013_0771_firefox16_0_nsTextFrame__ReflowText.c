
void
CVE_2013_0771_firefox16_0_nsTextFrame::ReflowText(nsLineLayout& aLineLayout, nscoord aAvailableWidth,
                        nsRenderingContext* aRenderingContext,
                        bool aShouldBlink,
                        nsHTMLReflowMetrics& aMetrics,
                        nsReflowStatus& aStatus)
{
#ifdef NOISY_REFLOW
  ListTag(stdout);
  printf(": BeginReflow: availableWidth=%d\n", aAvailableWidth);
#endif

  nsPresContext* presContext = PresContext();

#ifdef ACCESSIBILITY
  // Schedule the update of accessible tree since rendered text might be changed.
  ReflowTextA11yNotifier(presContext, mContent);
#endif

  /////////////////////////////////////////////////////////////////////
  // Set up flags and clear out state
  /////////////////////////////////////////////////////////////////////

  // Clear out the reflow state flags in mState (without destroying
  // the TEXT_BLINK_ON bit). We also clear the whitespace flags because this
  // can change whether the frame maps whitespace-only text or not.
  RemoveStateBits(TEXT_REFLOW_FLAGS | TEXT_WHITESPACE_FLAGS);

  // Temporarily map all possible content while we construct our new textrun.
  // so that when doing reflow our styles prevail over any part of the
  // textrun we look at. Note that next-in-flows may be mapping the same
  // content; gfxTextRun construction logic will ensure that we take priority.
  PRInt32 maxContentLength = GetInFlowContentLength();

  // We don't need to reflow if there is no content.
  if (!maxContentLength) {
    ClearMetrics(aMetrics);
    aStatus = NS_FRAME_COMPLETE;
    return;
  }

  if (aShouldBlink) {
    if (0 == (mState & TEXT_BLINK_ON)) {
      mState |= TEXT_BLINK_ON;
      nsBlinkTimer::AddBlinkFrame(presContext, this);
    }
  }
  else {
    if (0 != (mState & TEXT_BLINK_ON)) {
      mState &= ~TEXT_BLINK_ON;
      nsBlinkTimer::RemoveBlinkFrame(this);
    }
  }

#ifdef NOISY_BIDI
    printf("Reflowed textframe\n");
#endif

  const nsStyleText* textStyle = GetStyleText();

  bool atStartOfLine = aLineLayout.LineAtStart();
  if (atStartOfLine) {
    AddStateBits(TEXT_START_OF_LINE);
  }

  PRUint32 flowEndInTextRun;
  nsIFrame* lineContainer = aLineLayout.GetLineContainerFrame();
  gfxContext* ctx = aRenderingContext->ThebesContext();
  const nsTextFragment* frag = mContent->GetText();

  // DOM offsets of the text range we need to measure, after trimming
  // whitespace, restricting to first-letter, and restricting preformatted text
  // to nearest newline
  PRInt32 length = maxContentLength;
  PRInt32 offset = GetContentOffset();

  // Restrict preformatted text to the nearest newline
  PRInt32 newLineOffset = -1; // this will be -1 or a content offset
  PRInt32 contentNewLineOffset = -1;
  // Pointer to the nsGkAtoms::newline set on this frame's element
  NewlineProperty* cachedNewlineOffset = nsnull;
  if (textStyle->NewlineIsSignificant()) {
    cachedNewlineOffset =
      static_cast<NewlineProperty*>(mContent->GetProperty(nsGkAtoms::newline));
    if (cachedNewlineOffset && cachedNewlineOffset->mStartOffset <= offset &&
        (cachedNewlineOffset->mNewlineOffset == -1 ||
         cachedNewlineOffset->mNewlineOffset >= offset)) {
      contentNewLineOffset = cachedNewlineOffset->mNewlineOffset;
    } else {
      contentNewLineOffset = FindChar(frag, offset, 
                                      mContent->TextLength() - offset, '\n');
    }
    if (contentNewLineOffset < offset + length) {
      /*
        The new line offset could be outside this frame if the frame has been
        split by bidi resolution. In that case we won't use it in this reflow
        (newLineOffset will remain -1), but we will still cache it in mContent
      */
      newLineOffset = contentNewLineOffset;
    }
    if (newLineOffset >= 0) {
      length = newLineOffset + 1 - offset;
    }
  }
  if ((atStartOfLine && !textStyle->WhiteSpaceIsSignificant()) ||
      (GetStateBits() & TEXT_FORCE_TRIM_WHITESPACE)) {
    // Skip leading whitespace. Make sure we don't skip a 'pre-line'
    // newline if there is one.
    PRInt32 skipLength = newLineOffset >= 0 ? length - 1 : length;
    PRInt32 whitespaceCount =
      GetTrimmableWhitespaceCount(frag, offset, skipLength, 1);
    offset += whitespaceCount;
    length -= whitespaceCount;
  }

  bool completedFirstLetter = false;
  // Layout dependent styles are a problem because we need to reconstruct
  // the gfxTextRun based on our layout.
  if (aLineLayout.GetInFirstLetter() || aLineLayout.GetInFirstLine()) {
    SetLength(maxContentLength, &aLineLayout,
              ALLOW_FRAME_CREATION_AND_DESTRUCTION);

    if (aLineLayout.GetInFirstLetter()) {
      // floating first-letter boundaries are significant in textrun
      // construction, so clear the textrun out every time we hit a first-letter
      // and have changed our length (which controls the first-letter boundary)
      ClearTextRuns();
      // Find the length of the first-letter. We need a textrun for this.
      // REVIEW: maybe-bogus inflation should be ok (fixed below)
      gfxSkipCharsIterator iter =
        EnsureTextRun(nsTextFrame::eInflated, ctx,
                      lineContainer, aLineLayout.GetLine(),
                      &flowEndInTextRun);

      if (mTextRun) {
        PRInt32 firstLetterLength = length;
        if (aLineLayout.GetFirstLetterStyleOK()) {
          completedFirstLetter =
            FindFirstLetterRange(frag, mTextRun, offset, iter, &firstLetterLength);
          if (newLineOffset >= 0) {
            // Don't allow a preformatted newline to be part of a first-letter.
            firstLetterLength = NS_MIN(firstLetterLength, length - 1);
            if (length == 1) {
              // There is no text to be consumed by the first-letter before the
              // preformatted newline. Note that the first letter is therefore
              // complete (FindFirstLetterRange will have returned false).
              completedFirstLetter = true;
            }
          }
        } else {
          // We're in a first-letter frame's first in flow, so if there
          // was a first-letter, we'd be it. However, for one reason
          // or another (e.g., preformatted line break before this text),
          // we're not actually supposed to have first-letter style. So
          // just make a zero-length first-letter.
          firstLetterLength = 0;
          completedFirstLetter = true;
        }
        length = firstLetterLength;
        if (length) {
          AddStateBits(TEXT_FIRST_LETTER);
        }
        // Change this frame's length to the first-letter length right now
        // so that when we rebuild the textrun it will be built with the
        // right first-letter boundary
        SetLength(offset + length - GetContentOffset(), &aLineLayout,
                  ALLOW_FRAME_CREATION_AND_DESTRUCTION);
        // Ensure that the textrun will be rebuilt
        ClearTextRuns();
      }
    } 
  }

  float fontSizeInflation = nsLayoutUtils::FontSizeInflationFor(this);

  if (fontSizeInflation != GetFontSizeInflation()) {
    // FIXME: Ideally, if we already have a text run, we'd move it to be
    // the uninflated text run.
    ClearTextRun(nsnull, nsTextFrame::eInflated);
  }

  gfxSkipCharsIterator iter =
    EnsureTextRun(nsTextFrame::eInflated, ctx,
                  lineContainer, aLineLayout.GetLine(), &flowEndInTextRun);

  NS_ABORT_IF_FALSE(GetFontSizeInflation() == fontSizeInflation,
                    "EnsureTextRun should have set font size inflation");

  if (mTextRun && iter.GetOriginalEnd() < offset + length) {
    // The textrun does not map enough text for this frame. This can happen
    // when the textrun was ended in the middle of a text node because a
    // preformatted newline was encountered, and prev-in-flow frames have
    // consumed all the text of the textrun. We need a new textrun.
    ClearTextRuns();
    iter = EnsureTextRun(nsTextFrame::eInflated, ctx,
                         lineContainer, aLineLayout.GetLine(),
                         &flowEndInTextRun);
  }

  if (!mTextRun) {
    ClearMetrics(aMetrics);
    aStatus = NS_FRAME_COMPLETE;
    return;
  }

  NS_ASSERTION(gfxSkipCharsIterator(iter).ConvertOriginalToSkipped(offset + length)
                    <= mTextRun->GetLength(),
               "Text run does not map enough text for our reflow");

  /////////////////////////////////////////////////////////////////////
  // See how much text should belong to this text frame, and measure it
  /////////////////////////////////////////////////////////////////////
  
  iter.SetOriginalOffset(offset);
  nscoord xOffsetForTabs = (mTextRun->GetFlags() & nsTextFrameUtils::TEXT_HAS_TAB) ?
    (aLineLayout.GetCurrentFrameXDistanceFromBlock() -
       lineContainer->GetUsedBorderAndPadding().left)
    : -1;
  PropertyProvider provider(mTextRun, textStyle, frag, this, iter, length,
      lineContainer, xOffsetForTabs, nsTextFrame::eInflated);

  PRUint32 transformedOffset = provider.GetStart().GetSkippedOffset();

  // The metrics for the text go in here
  gfxTextRun::Metrics textMetrics;
  gfxFont::BoundingBoxType boundingBoxType = IsFloatingFirstLetterChild() ?
                                               gfxFont::TIGHT_HINTED_OUTLINE_EXTENTS :
                                               gfxFont::LOOSE_INK_EXTENTS;
  NS_ASSERTION(!(NS_REFLOW_CALC_BOUNDING_METRICS & aMetrics.mFlags),
               "We shouldn't be passed NS_REFLOW_CALC_BOUNDING_METRICS anymore");

  PRInt32 limitLength = length;
  PRInt32 forceBreak = aLineLayout.GetForcedBreakPosition(mContent);
  bool forceBreakAfter = false;
  if (forceBreak >= offset + length) {
    forceBreakAfter = forceBreak == offset + length;
    // The break is not within the text considered for this textframe.
    forceBreak = -1;
  }
  if (forceBreak >= 0) {
    limitLength = forceBreak - offset;
    NS_ASSERTION(limitLength >= 0, "Weird break found!");
  }
  // This is the heart of text reflow right here! We don't know where
  // to break, so we need to see how much text fits in the available width.
  PRUint32 transformedLength;
  if (offset + limitLength >= PRInt32(frag->GetLength())) {
    NS_ASSERTION(offset + limitLength == PRInt32(frag->GetLength()),
                 "Content offset/length out of bounds");
    NS_ASSERTION(flowEndInTextRun >= transformedOffset,
                 "Negative flow length?");
    transformedLength = flowEndInTextRun - transformedOffset;
  } else {
    // we're not looking at all the content, so we need to compute the
    // length of the transformed substring we're looking at
    gfxSkipCharsIterator iter(provider.GetStart());
    iter.SetOriginalOffset(offset + limitLength);
    transformedLength = iter.GetSkippedOffset() - transformedOffset;
  }
  PRUint32 transformedLastBreak = 0;
  bool usedHyphenation;
  gfxFloat trimmedWidth = 0;
  gfxFloat availWidth = aAvailableWidth;
  bool canTrimTrailingWhitespace = !textStyle->WhiteSpaceIsSignificant() ||
                                   (GetStateBits() & TEXT_FORCE_TRIM_WHITESPACE);
  PRInt32 unusedOffset;  
  gfxBreakPriority breakPriority;
  aLineLayout.GetLastOptionalBreakPosition(&unusedOffset, &breakPriority);
  PRUint32 transformedCharsFit =
    mTextRun->BreakAndMeasureText(transformedOffset, transformedLength,
                                  (GetStateBits() & TEXT_START_OF_LINE) != 0,
                                  availWidth,
                                  &provider, !aLineLayout.LineIsBreakable(),
                                  canTrimTrailingWhitespace ? &trimmedWidth : nsnull,
                                  &textMetrics, boundingBoxType, ctx,
                                  &usedHyphenation, &transformedLastBreak,
                                  textStyle->WordCanWrap(), &breakPriority);
  if (!length && !textMetrics.mAscent && !textMetrics.mDescent) {
    // If we're measuring a zero-length piece of text, update
    // the height manually.
    nsFontMetrics* fm = provider.GetFontMetrics();
    if (fm) {
      textMetrics.mAscent = gfxFloat(fm->MaxAscent());
      textMetrics.mDescent = gfxFloat(fm->MaxDescent());
    }
  }
  // The "end" iterator points to the first character after the string mapped
  // by this frame. Basically, its original-string offset is offset+charsFit
  // after we've computed charsFit.
  gfxSkipCharsIterator end(provider.GetEndHint());
  end.SetSkippedOffset(transformedOffset + transformedCharsFit);
  PRInt32 charsFit = end.GetOriginalOffset() - offset;
  if (offset + charsFit == newLineOffset) {
    // We broke before a trailing preformatted '\n'. The newline should
    // be assigned to this frame. Note that newLineOffset will be -1 if
    // there was no preformatted newline, so we wouldn't get here in that
    // case.
    ++charsFit;
  }
  // That might have taken us beyond our assigned content range (because
  // we might have advanced over some skipped chars that extend outside
  // this frame), so get back in.
  PRInt32 lastBreak = -1;
  if (charsFit >= limitLength) {
    charsFit = limitLength;
    if (transformedLastBreak != PR_UINT32_MAX) {
      // lastBreak is needed.
      // This may set lastBreak greater than 'length', but that's OK
      lastBreak = end.ConvertSkippedToOriginal(transformedOffset + transformedLastBreak);
    }
    end.SetOriginalOffset(offset + charsFit);
    // If we were forced to fit, and the break position is after a soft hyphen,
    // note that this is a hyphenation break.
    if ((forceBreak >= 0 || forceBreakAfter) &&
        HasSoftHyphenBefore(frag, mTextRun, offset, end)) {
      usedHyphenation = true;
    }
  }
  if (usedHyphenation) {
    // Fix up metrics to include hyphen
    AddHyphenToMetrics(this, mTextRun, &textMetrics, boundingBoxType, ctx);
    AddStateBits(TEXT_HYPHEN_BREAK | TEXT_HAS_NONCOLLAPSED_CHARACTERS);
  }

  gfxFloat trimmableWidth = 0;
  bool brokeText = forceBreak >= 0 || transformedCharsFit < transformedLength;
  if (canTrimTrailingWhitespace) {
    // Optimization: if we trimmed trailing whitespace, and we can be sure
    // this frame will be at the end of the line, then leave it trimmed off.
    // Otherwise we have to undo the trimming, in case we're not at the end of
    // the line. (If we actually do end up at the end of the line, we'll have
    // to trim it off again in TrimTrailingWhiteSpace, and we'd like to avoid
    // having to re-do it.)
    if (brokeText ||
        (GetStateBits() & TEXT_FORCE_TRIM_WHITESPACE)) {
      // We're definitely going to break so our trailing whitespace should
      // definitely be trimmed. Record that we've already done it.
      AddStateBits(TEXT_TRIMMED_TRAILING_WHITESPACE);
    } else if (!(GetStateBits() & TEXT_FORCE_TRIM_WHITESPACE)) {
      // We might not be at the end of the line. (Note that even if this frame
      // ends in breakable whitespace, it might not be at the end of the line
      // because it might be followed by breakable, but preformatted, whitespace.)
      // Undo the trimming.
      textMetrics.mAdvanceWidth += trimmedWidth;
      trimmableWidth = trimmedWidth;
      if (mTextRun->IsRightToLeft()) {
        // Space comes before text, so the bounding box is moved to the
        // right by trimmdWidth
        textMetrics.mBoundingBox.MoveBy(gfxPoint(trimmedWidth, 0));
      }
    }
  }

  if (!brokeText && lastBreak >= 0) {
    // Since everything fit and no break was forced,
    // record the last break opportunity
    NS_ASSERTION(textMetrics.mAdvanceWidth - trimmableWidth <= aAvailableWidth,
                 "If the text doesn't fit, and we have a break opportunity, why didn't MeasureText use it?");
    aLineLayout.NotifyOptionalBreakPosition(mContent, lastBreak, true, breakPriority);
  }

  PRInt32 contentLength = offset + charsFit - GetContentOffset();

  /////////////////////////////////////////////////////////////////////
  // Compute output metrics
  /////////////////////////////////////////////////////////////////////

  // first-letter frames should use the tight bounding box metrics for ascent/descent
  // for good drop-cap effects
  if (GetStateBits() & TEXT_FIRST_LETTER) {
    textMetrics.mAscent = NS_MAX(gfxFloat(0.0), -textMetrics.mBoundingBox.Y());
    textMetrics.mDescent = NS_MAX(gfxFloat(0.0), textMetrics.mBoundingBox.YMost());
  }

  // Setup metrics for caller
  // Disallow negative widths
  aMetrics.width = NSToCoordCeil(NS_MAX(gfxFloat(0.0), textMetrics.mAdvanceWidth));

  if (transformedCharsFit == 0 && !usedHyphenation) {
    aMetrics.ascent = 0;
    aMetrics.height = 0;
  } else if (boundingBoxType != gfxFont::LOOSE_INK_EXTENTS) {
    // Use actual text metrics for floating first letter frame.
    aMetrics.ascent = NSToCoordCeil(textMetrics.mAscent);
    aMetrics.height = aMetrics.ascent + NSToCoordCeil(textMetrics.mDescent);
  } else {
    // Otherwise, ascent should contain the overline drawable area.
    // And also descent should contain the underline drawable area.
    // nsFontMetrics::GetMaxAscent/GetMaxDescent contains them.
    nsFontMetrics* fm = provider.GetFontMetrics();
    nscoord fontAscent = fm->MaxAscent();
    nscoord fontDescent = fm->MaxDescent();
    aMetrics.ascent = NS_MAX(NSToCoordCeil(textMetrics.mAscent), fontAscent);
    nscoord descent = NS_MAX(NSToCoordCeil(textMetrics.mDescent), fontDescent);
    aMetrics.height = aMetrics.ascent + descent;
  }

  NS_ASSERTION(aMetrics.ascent >= 0, "Negative ascent???");
  NS_ASSERTION(aMetrics.height - aMetrics.ascent >= 0, "Negative descent???");

  mAscent = aMetrics.ascent;

  // Handle text that runs outside its normal bounds.
  nsRect boundingBox = RoundOut(textMetrics.mBoundingBox) + nsPoint(0, mAscent);
  aMetrics.SetOverflowAreasToDesiredBounds();
  aMetrics.VisualOverflow().UnionRect(aMetrics.VisualOverflow(), boundingBox);

  // When we have text decorations, we don't need to compute their overflow now
  // because we're guaranteed to do it later
  // (see nsLineLayout::RelativePositionFrames)
  UnionAdditionalOverflow(presContext, *aLineLayout.GetLineContainerRS(),
                          provider, &aMetrics.VisualOverflow(), false);

  /////////////////////////////////////////////////////////////////////
  // Clean up, update state
  /////////////////////////////////////////////////////////////////////

  // If all our characters are discarded or collapsed, then trimmable width
  // from the last textframe should be preserved. Otherwise the trimmable width
  // from this textframe overrides. (Currently in CSS trimmable width can be
  // at most one space so there's no way for trimmable width from a previous
  // frame to accumulate with trimmable width from this frame.)
  if (transformedCharsFit > 0) {
    aLineLayout.SetTrimmableWidth(NSToCoordFloor(trimmableWidth));
    AddStateBits(TEXT_HAS_NONCOLLAPSED_CHARACTERS);
  }
  if (charsFit > 0 && charsFit == length &&
      textStyle->mHyphens != NS_STYLE_HYPHENS_NONE &&
      HasSoftHyphenBefore(frag, mTextRun, offset, end)) {
    // Record a potential break after final soft hyphen
    aLineLayout.NotifyOptionalBreakPosition(mContent, offset + length,
        textMetrics.mAdvanceWidth + provider.GetHyphenWidth() <= availWidth,
                                           eNormalBreak);
  }
  bool breakAfter = forceBreakAfter;
  // length == 0 means either the text is empty or it's all collapsed away
  bool emptyTextAtStartOfLine = atStartOfLine && length == 0;
  if (!breakAfter && charsFit == length && !emptyTextAtStartOfLine &&
      transformedOffset + transformedLength == mTextRun->GetLength() &&
      (mTextRun->GetFlags() & nsTextFrameUtils::TEXT_HAS_TRAILING_BREAK)) {
    // We placed all the text in the textrun and we have a break opportunity at
    // the end of the textrun. We need to record it because the following
    // content may not care about nsLineBreaker.

    // Note that because we didn't break, we can be sure that (thanks to the
    // code up above) textMetrics.mAdvanceWidth includes the width of any
    // trailing whitespace. So we need to subtract trimmableWidth here
    // because if we did break at this point, that much width would be trimmed.
    if (textMetrics.mAdvanceWidth - trimmableWidth > availWidth) {
      breakAfter = true;
    } else {
      aLineLayout.NotifyOptionalBreakPosition(mContent, offset + length,
                                              true, eNormalBreak);
    }
  }

  // Compute reflow status
  aStatus = contentLength == maxContentLength
    ? NS_FRAME_COMPLETE : NS_FRAME_NOT_COMPLETE;

  if (charsFit == 0 && length > 0 && !usedHyphenation) {
    // Couldn't place any text
    aStatus = NS_INLINE_LINE_BREAK_BEFORE();
  } else if (contentLength > 0 && mContentOffset + contentLength - 1 == newLineOffset) {
    // Ends in \n
    aStatus = NS_INLINE_LINE_BREAK_AFTER(aStatus);
    aLineLayout.SetLineEndsInBR(true);
  } else if (breakAfter) {
    aStatus = NS_INLINE_LINE_BREAK_AFTER(aStatus);
  }
  if (completedFirstLetter) {
    aLineLayout.SetFirstLetterStyleOK(false);
    aStatus |= NS_INLINE_BREAK_FIRST_LETTER_COMPLETE;
  }

  // Updated the cached NewlineProperty, or delete it.
  if (contentLength < maxContentLength &&
      textStyle->NewlineIsSignificant() &&
      (contentNewLineOffset < 0 ||
       mContentOffset + contentLength <= contentNewLineOffset)) {
    if (!cachedNewlineOffset) {
      cachedNewlineOffset = new NewlineProperty;
      if (NS_FAILED(mContent->SetProperty(nsGkAtoms::newline, cachedNewlineOffset,
                                          NewlineProperty::Destroy))) {
        delete cachedNewlineOffset;
        cachedNewlineOffset = nsnull;
      }
    }
    if (cachedNewlineOffset) {
      cachedNewlineOffset->mStartOffset = offset;
      cachedNewlineOffset->mNewlineOffset = contentNewLineOffset;
    }
  } else if (cachedNewlineOffset) {
    mContent->DeleteProperty(nsGkAtoms::newline);
  }

  // Compute space and letter counts for justification, if required
  if (!textStyle->WhiteSpaceIsSignificant() &&
      (lineContainer->GetStyleText()->mTextAlign == NS_STYLE_TEXT_ALIGN_JUSTIFY ||
       lineContainer->GetStyleText()->mTextAlignLast == NS_STYLE_TEXT_ALIGN_JUSTIFY)) {
    AddStateBits(TEXT_JUSTIFICATION_ENABLED);    // This will include a space for trailing whitespace, if any is present.
    // This is corrected for in nsLineLayout::TrimWhiteSpaceIn.
    PRInt32 numJustifiableCharacters =
      provider.ComputeJustifiableCharacters(offset, charsFit);

    NS_ASSERTION(numJustifiableCharacters <= charsFit,
                 "Bad justifiable character count");
    aLineLayout.SetTextJustificationWeights(numJustifiableCharacters,
        charsFit - numJustifiableCharacters);
  }

  SetLength(contentLength, &aLineLayout, ALLOW_FRAME_CREATION_AND_DESTRUCTION);

  Invalidate(aMetrics.VisualOverflow());

#ifdef NOISY_REFLOW
  ListTag(stdout);
  printf(": desiredSize=%d,%d(b=%d) status=%x\n",
         aMetrics.width, aMetrics.height, aMetrics.ascent,
         aStatus);
#endif
}