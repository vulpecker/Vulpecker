
NS_IMETHODIMP
CVE_2013_1732_firefox12_0_nsBlockFrame::Reflow(nsPresContext*           aPresContext,
                     nsHTMLReflowMetrics&     aMetrics,
                     const nsHTMLReflowState& aReflowState,
                     nsReflowStatus&          aStatus)
{
  DO_GLOBAL_REFLOW_COUNT("nsBlockFrame");
  DISPLAY_REFLOW(aPresContext, this, aReflowState, aMetrics, aStatus);
#ifdef DEBUG
  if (gNoisyReflow) {
    IndentBy(stdout, gNoiseIndent);
    ListTag(stdout);
    printf(": begin reflow availSize=%d,%d computedSize=%d,%d\n",
           aReflowState.availableWidth, aReflowState.availableHeight,
           aReflowState.ComputedWidth(), aReflowState.ComputedHeight());
  }
  AutoNoisyIndenter indent(gNoisy);
  PRTime start = LL_ZERO; // Initialize these variablies to silence the compiler.
  PRInt32 ctc = 0;        // We only use these if they are set (gLameReflowMetrics).
  if (gLameReflowMetrics) {
    start = PR_Now();
    ctc = nsLineBox::GetCtorCount();
  }
#endif

  const nsHTMLReflowState *reflowState = &aReflowState;
  nsAutoPtr<nsHTMLReflowState> mutableReflowState;
  // If we have non-auto height, we're clipping our kids and we fit,
  // make sure our kids fit too.
  if (aReflowState.availableHeight != NS_UNCONSTRAINEDSIZE &&
      aReflowState.ComputedHeight() != NS_AUTOHEIGHT &&
      ApplyOverflowClipping(this, aReflowState.mStyleDisplay)) {
    nsMargin heightExtras = aReflowState.mComputedBorderPadding;
    if (GetSkipSides() & NS_SIDE_TOP) {
      heightExtras.top = 0;
    } else {
      // Bottom margin never causes us to create continuations, so we
      // don't need to worry about whether it fits in its entirety.
      heightExtras.top += aReflowState.mComputedMargin.top;
    }

    if (GetEffectiveComputedHeight(aReflowState) + heightExtras.TopBottom() <=
        aReflowState.availableHeight) {
      mutableReflowState = new nsHTMLReflowState(aReflowState);
      mutableReflowState->availableHeight = NS_UNCONSTRAINEDSIZE;
      reflowState = mutableReflowState;
    }
  }

  // See comment below about oldSize. Use *only* for the
  // abs-pos-containing-block-size-change optimization!
  nsSize oldSize = GetSize();

  // Should we create a float manager?
  nsAutoFloatManager autoFloatManager(const_cast<nsHTMLReflowState&>(*reflowState));

  // XXXldb If we start storing the float manager in the frame rather
  // than keeping it around only during reflow then we should create it
  // only when there are actually floats to manage.  Otherwise things
  // like tables will gain significant bloat.
  bool needFloatManager = nsBlockFrame::BlockNeedsFloatManager(this);
  if (needFloatManager)
    autoFloatManager.CreateFloatManager(aPresContext);

  // OK, some lines may be reflowed. Blow away any saved line cursor
  // because we may invalidate the nondecreasing
  // overflowArea.VisualOverflow().y/yMost invariant, and we may even
  // delete the line with the line cursor.
  ClearLineCursor();

  if (IsFrameTreeTooDeep(*reflowState, aMetrics, aStatus)) {
    return NS_OK;
  }

  bool marginRoot = BlockIsMarginRoot(this);
  nsBlockReflowState state(*reflowState, aPresContext, this, aMetrics,
                           marginRoot, marginRoot, needFloatManager);

#ifdef IBMBIDI
  if (GetStateBits() & NS_BLOCK_NEEDS_BIDI_RESOLUTION)
    static_cast<nsBlockFrame*>(GetFirstContinuation())->ResolveBidi();
#endif // IBMBIDI

  if (RenumberLists(aPresContext)) {
    AddStateBits(NS_FRAME_HAS_DIRTY_CHILDREN);
  }

  nsresult rv = NS_OK;

  // ALWAYS drain overflow. We never want to leave the previnflow's
  // overflow lines hanging around; block reflow depends on the
  // overflow line lists being cleared out between reflow passes.
  DrainOverflowLines();

  // Handle paginated overflow (see nsContainerFrame.h)
  nsOverflowAreas ocBounds;
  nsReflowStatus ocStatus = NS_FRAME_COMPLETE;
  if (GetPrevInFlow()) {
    ReflowOverflowContainerChildren(aPresContext, *reflowState, ocBounds, 0,
                                    ocStatus);
  }

  // Now that we're done cleaning up our overflow container lists, we can
  // give |state| its nsOverflowContinuationTracker.
  nsOverflowContinuationTracker tracker(aPresContext, this, false);
  state.mOverflowTracker = &tracker;

  // Drain & handle pushed floats
  DrainPushedFloats(state);
  nsOverflowAreas fcBounds;
  nsReflowStatus fcStatus = NS_FRAME_COMPLETE;
  rv = ReflowPushedFloats(state, fcBounds, fcStatus);
  NS_ENSURE_SUCCESS(rv, rv);

  // If we're not dirty (which means we'll mark everything dirty later)
  // and our width has changed, mark the lines dirty that we need to
  // mark dirty for a resize reflow.
  if (reflowState->mFlags.mHResize)
    PrepareResizeReflow(state);

  mState &= ~NS_FRAME_FIRST_REFLOW;

  // Now reflow...
  rv = ReflowDirtyLines(state);
  NS_ASSERTION(NS_SUCCEEDED(rv), "reflow dirty lines failed");
  if (NS_FAILED(rv)) return rv;

  NS_MergeReflowStatusInto(&state.mReflowStatus, ocStatus);
  NS_MergeReflowStatusInto(&state.mReflowStatus, fcStatus);

  // If we end in a BR with clear and affected floats continue,
  // we need to continue, too.
  if (NS_UNCONSTRAINEDSIZE != reflowState->availableHeight &&
      NS_FRAME_IS_COMPLETE(state.mReflowStatus) &&
      state.mFloatManager->ClearContinues(FindTrailingClear())) {
    NS_FRAME_SET_INCOMPLETE(state.mReflowStatus);
  }

  if (!NS_FRAME_IS_FULLY_COMPLETE(state.mReflowStatus)) {
    if (GetOverflowLines() || GetPushedFloats()) {
      state.mReflowStatus |= NS_FRAME_REFLOW_NEXTINFLOW;
    }

#ifdef DEBUG_kipp
    ListTag(stdout); printf(": block is not fully complete\n");
#endif
  }

  CheckFloats(state);

  // Place the "marker" (bullet) frame if it is placed next to a block
  // child.
  //
  // According to the CSS2 spec, section 12.6.1, the "marker" box
  // participates in the height calculation of the list-item box's
  // first line box.
  //
  // There are exactly two places a bullet can be placed: near the
  // first or second line. It's only placed on the second line in a
  // rare case: an empty first line followed by a second line that
  // contains a block (example: <LI>\n<P>... ). This is where
  // the second case can happen.
  if (mBullet && HaveOutsideBullet() && !mLines.empty() &&
      (mLines.front()->IsBlock() ||
       (0 == mLines.front()->mBounds.height &&
        mLines.front() != mLines.back() &&
        mLines.begin().next()->IsBlock()))) {
    // Reflow the bullet
    nsHTMLReflowMetrics metrics;
    // XXX Use the entire line when we fix bug 25888.
    nsLayoutUtils::LinePosition position;
    bool havePosition = nsLayoutUtils::GetFirstLinePosition(this, &position);
    nscoord lineTop = havePosition ? position.mTop
                                   : reflowState->mComputedBorderPadding.top;
    ReflowBullet(state, metrics, lineTop);
    NS_ASSERTION(!BulletIsEmpty() || metrics.height == 0,
                 "empty bullet took up space");

    if (havePosition && !BulletIsEmpty()) {
      // We have some lines to align the bullet with.  

      // Doing the alignment using the baseline will also cater for
      // bullets that are placed next to a child block (bug 92896)
    
      // Tall bullets won't look particularly nice here...
      nsRect bbox = mBullet->GetRect();
      bbox.y = position.mBaseline - metrics.ascent;
      mBullet->SetRect(bbox);
    }
    // Otherwise just leave the bullet where it is, up against our top padding.
  }

  // Compute our final size
  nscoord bottomEdgeOfChildren;
  ComputeFinalSize(*reflowState, state, aMetrics, &bottomEdgeOfChildren);
  nsRect areaBounds = nsRect(0, 0, aMetrics.width, aMetrics.height);
  ComputeOverflowAreas(areaBounds, reflowState->mStyleDisplay,
                       bottomEdgeOfChildren, aMetrics.mOverflowAreas);
  // Factor overflow container child bounds into the overflow area
  aMetrics.mOverflowAreas.UnionWith(ocBounds);
  // Factor pushed float child bounds into the overflow area
  aMetrics.mOverflowAreas.UnionWith(fcBounds);

  // Let the absolutely positioned container reflow any absolutely positioned
  // child frames that need to be reflowed, e.g., elements with a percentage
  // based width/height
  // We want to do this under either of two conditions:
  //  1. If we didn't do the incremental reflow above.
  //  2. If our size changed.
  // Even though it's the padding edge that's the containing block, we
  // can use our rect (the border edge) since if the border style
  // changed, the reflow would have been targeted at us so we'd satisfy
  // condition 1.
  // XXX checking oldSize is bogus, there are various reasons we might have
  // reflowed but our size might not have been changed to what we
  // asked for (e.g., we ended up being pushed to a new page)
  // When WillReflowAgainForClearance is true, we will reflow again without
  // resetting the size. Because of this, we must not reflow our abs-pos children
  // in that situation --- what we think is our "new size"
  // will not be our real new size. This also happens to be more efficient.
  if (HasAbsolutelyPositionedChildren()) {
    nsAbsoluteContainingBlock* absoluteContainer = GetAbsoluteContainingBlock();
    bool haveInterrupt = aPresContext->HasPendingInterrupt();
    if (reflowState->WillReflowAgainForClearance() ||
        haveInterrupt) {
      // Make sure that when we reflow again we'll actually reflow all the abs
      // pos frames that might conceivably depend on our size (or all of them,
      // if we're dirty right now and interrupted; in that case we also need
      // to mark them all with NS_FRAME_IS_DIRTY).  Sadly, we can't do much
      // better than that, because we don't really know what our size will be,
      // and it might in fact not change on the followup reflow!
      if (haveInterrupt && (GetStateBits() & NS_FRAME_IS_DIRTY)) {
        absoluteContainer->MarkAllFramesDirty();
      } else {
        absoluteContainer->MarkSizeDependentFramesDirty();
      }
    } else {
      nsSize containingBlockSize =
        CalculateContainingBlockSizeForAbsolutes(*reflowState,
                                                 nsSize(aMetrics.width,
                                                        aMetrics.height));

      // Mark frames that depend on changes we just made to this frame as dirty:
      // Now we can assume that the padding edge hasn't moved.
      // We need to reflow the absolutes if one of them depends on
      // its placeholder position, or the containing block size in a
      // direction in which the containing block size might have
      // changed.
      bool cbWidthChanged = aMetrics.width != oldSize.width;
      bool isRoot = !GetContent()->GetParent();
      // If isRoot and we have auto height, then we are the initial
      // containing block and the containing block height is the
      // viewport height, which can't change during incremental
      // reflow.
      bool cbHeightChanged =
        !(isRoot && NS_UNCONSTRAINEDSIZE == reflowState->ComputedHeight()) &&
        aMetrics.height != oldSize.height;

      absoluteContainer->Reflow(this, aPresContext, *reflowState,
                                state.mReflowStatus,
                                containingBlockSize.width,
                                containingBlockSize.height, true,
                                cbWidthChanged, cbHeightChanged,
                                &aMetrics.mOverflowAreas);

      //XXXfr Why isn't this rv (and others in this file) checked/returned?
    }
  }

  // Determine if we need to repaint our border, background or outline
  CheckInvalidateSizeChange(aMetrics);

  FinishAndStoreOverflow(&aMetrics);

  // Clear the float manager pointer in the block reflow state so we
  // don't waste time translating the coordinate system back on a dead
  // float manager.
  if (needFloatManager)
    state.mFloatManager = nsnull;

  aStatus = state.mReflowStatus;

#ifdef DEBUG
  // Between when we drain pushed floats and when we complete reflow,
  // we're allowed to have multiple continuations of the same float on
  // our floats list, since a first-in-flow might get pushed to a later
  // continuation of its containing block.  But it's not permitted
  // outside that time.
  nsLayoutUtils::AssertNoDuplicateContinuations(this, mFloats);

  if (gNoisyReflow) {
    IndentBy(stdout, gNoiseIndent);
    ListTag(stdout);
    printf(": status=%x (%scomplete) metrics=%d,%d carriedMargin=%d",
           aStatus, NS_FRAME_IS_COMPLETE(aStatus) ? "" : "not ",
           aMetrics.width, aMetrics.height,
           aMetrics.mCarriedOutBottomMargin.get());
    if (HasOverflowAreas()) {
      printf(" overflow-vis={%d,%d,%d,%d}",
             aMetrics.VisualOverflow().x,
             aMetrics.VisualOverflow().y,
             aMetrics.VisualOverflow().width,
             aMetrics.VisualOverflow().height);
      printf(" overflow-scr={%d,%d,%d,%d}",
             aMetrics.ScrollableOverflow().x,
             aMetrics.ScrollableOverflow().y,
             aMetrics.ScrollableOverflow().width,
             aMetrics.ScrollableOverflow().height);
    }
    printf("\n");
  }

  if (gLameReflowMetrics) {
    PRTime end = PR_Now();

    PRInt32 ectc = nsLineBox::GetCtorCount();
    PRInt32 numLines = mLines.size();
    if (!numLines) numLines = 1;
    PRTime delta, perLineDelta, lines;
    LL_I2L(lines, numLines);
    LL_SUB(delta, end, start);
    LL_DIV(perLineDelta, delta, lines);

    ListTag(stdout);
    char buf[400];
    PR_snprintf(buf, sizeof(buf),
                ": %lld elapsed (%lld per line) (%d lines; %d new lines)",
                delta, perLineDelta, numLines, ectc - ctc);
    printf("%s\n", buf);
  }
#endif

  NS_FRAME_SET_TRUNCATION(aStatus, (*reflowState), aMetrics);
  return rv;
}