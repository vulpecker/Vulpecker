
NS_IMETHODIMP
CVE_2013_1732_thunderbird3_0_8_nsBlockFrame::Reflow(nsPresContext*           aPresContext,
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

  // See comment below about oldSize. Use *only* for the
  // abs-pos-containing-block-size-change optimization!
  nsSize oldSize = GetSize();

  // Should we create a float manager?
  nsAutoFloatManager autoFloatManager(const_cast<nsHTMLReflowState &>(aReflowState));

  // XXXldb If we start storing the float manager in the frame rather
  // than keeping it around only during reflow then we should create it
  // only when there are actually floats to manage.  Otherwise things
  // like tables will gain significant bloat.
  PRBool needFloatManager = nsBlockFrame::BlockNeedsFloatManager(this);
  if (needFloatManager)
    autoFloatManager.CreateFloatManager(aPresContext);

  // OK, some lines may be reflowed. Blow away any saved line cursor because
  // we may invalidate the nondecreasing combinedArea.y/yMost invariant,
  // and we may even delete the line with the line cursor.
  ClearLineCursor();

  if (IsFrameTreeTooDeep(aReflowState, aMetrics)) {
#ifdef DEBUG_kipp
    {
      extern char* nsPresShell_ReflowStackPointerTop;
      char marker;
      char* newsp = (char*) &marker;
      printf("XXX: frame tree is too deep; approx stack size = %d\n",
             nsPresShell_ReflowStackPointerTop - newsp);
    }
#endif
    aStatus = NS_FRAME_COMPLETE;
    return NS_OK;
  }

  PRBool marginRoot = BlockIsMarginRoot(this);
  nsBlockReflowState state(aReflowState, aPresContext, this, aMetrics,
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
  DrainOverflowLines(state);
  state.SetupOverflowPlaceholdersProperty();
 
  // If we're not dirty (which means we'll mark everything dirty later)
  // and our width has changed, mark the lines dirty that we need to
  // mark dirty for a resize reflow.
  if (aReflowState.mFlags.mHResize)
    PrepareResizeReflow(state);

  mState &= ~NS_FRAME_FIRST_REFLOW;

  // Now reflow...
  rv = ReflowDirtyLines(state);
  NS_ASSERTION(NS_SUCCEEDED(rv), "reflow dirty lines failed");
  if (NS_FAILED(rv)) return rv;

  // Handle paginated overflow (see nsContainerFrame.h)
  nsRect overflowContainerBounds;
  if (GetPrevInFlow()) {
    ReflowOverflowContainerChildren(aPresContext, aReflowState,
                                    overflowContainerBounds, 0,
                                    state.mReflowStatus);
  }

  // If the block is complete, put continued floats in the closest ancestor 
  // block that uses the same float manager and leave the block complete; this 
  // allows subsequent lines on the page to be impacted by floats. If the 
  // block is incomplete or there is no ancestor using the same float manager, 
  // put continued floats at the beginning of the first overflow line.
  if (state.mOverflowPlaceholders.NotEmpty()) {
    NS_ASSERTION(aReflowState.availableHeight != NS_UNCONSTRAINEDSIZE,
                 "Somehow we failed to fit all content, even though we have unlimited space!");
    if (NS_FRAME_IS_FULLY_COMPLETE(state.mReflowStatus)) {
      // find the nearest block ancestor that uses the same float manager
      for (const nsHTMLReflowState* ancestorRS = aReflowState.parentReflowState; 
           ancestorRS; 
           ancestorRS = ancestorRS->parentReflowState) {
        nsIFrame* ancestor = ancestorRS->frame;
        if (nsLayoutUtils::GetAsBlock(ancestor) &&
            aReflowState.mFloatManager == ancestorRS->mFloatManager) {
          // Put the continued floats in ancestor since it uses the same float manager
          nsFrameList* ancestorPlace =
            ((nsBlockFrame*)ancestor)->GetOverflowPlaceholders();
          // The ancestor should have this list, since it's being reflowed. But maybe
          // it isn't because of reflow roots or something.
          if (ancestorPlace) {
            for (nsIFrame* f = state.mOverflowPlaceholders.FirstChild();
                 f; f = f->GetNextSibling()) {
              NS_ASSERTION(IsContinuationPlaceholder(f),
                           "Overflow placeholders must be continuation placeholders");
              ReparentFrame(f, this, ancestorRS->frame);
              nsIFrame* oof = nsPlaceholderFrame::GetRealFrameForPlaceholder(f);
              mFloats.RemoveFrame(oof);
              ReparentFrame(oof, this, ancestorRS->frame);
              // Clear the next-sibling in case the frame wasn't in mFloats
              oof->SetNextSibling(nsnull);
              // Do not put the float into any child frame list, because
              // placeholders in the overflow-placeholder block-state list
              // don't keep their out of flows in a child frame list.
            }
            ancestorPlace->AppendFrames(nsnull, state.mOverflowPlaceholders.FirstChild());
            state.mOverflowPlaceholders.SetFrames(nsnull);
            break;
          }
        }
      }
    }
    if (!state.mOverflowPlaceholders.IsEmpty()) {
      state.mOverflowPlaceholders.SortByContentOrder();
      PRInt32 numOverflowPlace = state.mOverflowPlaceholders.GetLength();
      nsLineBox* newLine =
        state.NewLineBox(state.mOverflowPlaceholders.FirstChild(),
                         numOverflowPlace, PR_FALSE);
      if (newLine) {
        nsLineList* overflowLines = GetOverflowLines();
        if (overflowLines) {
          // Need to put the overflow placeholders' floats into our
          // overflow-out-of-flows list, since the overflow placeholders are
          // going onto our overflow line list. Put them last, because that's
          // where the placeholders are going.
          nsFrameList floats;
          nsIFrame* lastFloat = nsnull;
          for (nsIFrame* f = state.mOverflowPlaceholders.FirstChild();
               f; f = f->GetNextSibling()) {
            NS_ASSERTION(IsContinuationPlaceholder(f),
                         "Overflow placeholders must be continuation placeholders");
            nsIFrame* oof = nsPlaceholderFrame::GetRealFrameForPlaceholder(f);
            // oof is not currently in any child list
            floats.InsertFrames(nsnull, lastFloat, oof);
            lastFloat = oof;
          }

          // Put the new placeholders *last* in the overflow lines
          // because they might have previnflows in the overflow lines.
          nsIFrame* lastChild = overflowLines->back()->LastChild();
          lastChild->SetNextSibling(state.mOverflowPlaceholders.FirstChild());
          // Create a new line as the last line and put the
          // placeholders there
          overflowLines->push_back(newLine);

          nsAutoOOFFrameList oofs(this);
          oofs.mList.AppendFrames(nsnull, floats.FirstChild());
        }
        else {
          mLines.push_back(newLine);
          nsLineList::iterator nextToLastLine = ----end_lines();
          PushLines(state, nextToLastLine);
        }
        state.mOverflowPlaceholders.SetFrames(nsnull);
      }
      state.mReflowStatus |= NS_FRAME_REFLOW_NEXTINFLOW;
      NS_FRAME_SET_INCOMPLETE(state.mReflowStatus);
    }
  }

  if (NS_FRAME_IS_NOT_COMPLETE(state.mReflowStatus)) {
    if (GetOverflowLines()) {
      state.mReflowStatus |= NS_FRAME_REFLOW_NEXTINFLOW;
    }

#ifdef DEBUG_kipp
    ListTag(stdout); printf(": block is not complete\n");
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
    // FIXME: aReflowState.mComputedBorderPadding.top isn't even the
    // right place -- we really want the top of the line whose baseline
    // we're using (or, actually, the entire line, once we fix bug
    // 25888)
    ReflowBullet(state, metrics, aReflowState.mComputedBorderPadding.top);

    nscoord baseline;
    if (nsLayoutUtils::GetFirstLineBaseline(this, &baseline)) {
      // We have some lines to align the bullet with.  

      // Doing the alignment using the baseline will also cater for
      // bullets that are placed next to a child block (bug 92896)
    
      // Tall bullets won't look particularly nice here...
      nsRect bbox = mBullet->GetRect();
      bbox.y = baseline - metrics.ascent;
      mBullet->SetRect(bbox);
    }
    // Otherwise just leave the bullet where it is, up against our top padding.
  }

  // Compute our final size
  nscoord bottomEdgeOfChildren;
  ComputeFinalSize(aReflowState, state, aMetrics, &bottomEdgeOfChildren);
  ComputeCombinedArea(aReflowState, aMetrics, bottomEdgeOfChildren);
  // Factor overflow container child bounds into the overflow area
  aMetrics.mOverflowArea.UnionRect(aMetrics.mOverflowArea,
                                   overflowContainerBounds);

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
  if (mAbsoluteContainer.HasAbsoluteFrames()) {
    if (aReflowState.WillReflowAgainForClearance()) {
      // Make sure that when we reflow again we'll actually reflow all the abs
      // pos frames that might conceivably depend on our size.  Sadly, we can't
      // do much better than that, because we don't really know what our size
      // will be, and it might in fact not change on the followup reflow!
      mAbsoluteContainer.MarkSizeDependentFramesDirty();
    } else {
      nsRect childBounds;
      nsSize containingBlockSize =
        CalculateContainingBlockSizeForAbsolutes(aReflowState,
                                                 nsSize(aMetrics.width,
                                                        aMetrics.height));

      // Mark frames that depend on changes we just made to this frame as dirty:
      // Now we can assume that the padding edge hasn't moved.
      // We need to reflow the absolutes if one of them depends on
      // its placeholder position, or the containing block size in a
      // direction in which the containing block size might have
      // changed.
      PRBool cbWidthChanged = aMetrics.width != oldSize.width;
      PRBool isRoot = !GetContent()->GetParent();
      // If isRoot and we have auto height, then we are the initial
      // containing block and the containing block height is the
      // viewport height, which can't change during incremental
      // reflow.
      PRBool cbHeightChanged =
        !(isRoot && NS_UNCONSTRAINEDSIZE == aReflowState.ComputedHeight()) &&
        aMetrics.height != oldSize.height;

      rv = mAbsoluteContainer.Reflow(this, aPresContext, aReflowState,
                                     state.mReflowStatus,
                                     containingBlockSize.width,
                                     containingBlockSize.height, PR_TRUE,
                                     cbWidthChanged, cbHeightChanged,
                                     &childBounds);

      //XXXfr Why isn't this rv (and others in this file) checked/returned?

      // Factor the absolutely positioned child bounds into the overflow area
      aMetrics.mOverflowArea.UnionRect(aMetrics.mOverflowArea, childBounds);
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
  if (gNoisyReflow) {
    IndentBy(stdout, gNoiseIndent);
    ListTag(stdout);
    printf(": status=%x (%scomplete) metrics=%d,%d carriedMargin=%d",
           aStatus, NS_FRAME_IS_COMPLETE(aStatus) ? "" : "not ",
           aMetrics.width, aMetrics.height,
           aMetrics.mCarriedOutBottomMargin.get());
    if (mState & NS_FRAME_OUTSIDE_CHILDREN) {
      printf(" combinedArea={%d,%d,%d,%d}",
             aMetrics.mOverflowArea.x,
             aMetrics.mOverflowArea.y,
             aMetrics.mOverflowArea.width,
             aMetrics.mOverflowArea.height);
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

  NS_FRAME_SET_TRUNCATION(aStatus, aReflowState, aMetrics);
  return rv;
}