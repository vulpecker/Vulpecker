
nsresult
CVE_2012_3957_firefox10_0_2_nsBlockFrame::AddFrames(nsFrameList& aFrameList, nsIFrame* aPrevSibling)
{
  // Clear our line cursor, since our lines may change.
  ClearLineCursor();

  if (aFrameList.IsEmpty()) {
    return NS_OK;
  }

  // If we're inserting at the beginning of our list and we have an
  // inside bullet, insert after that bullet.
  if (!aPrevSibling && mBullet && !HaveOutsideBullet()) {
    NS_ASSERTION(!aFrameList.ContainsFrame(mBullet),
                 "Trying to make mBullet prev sibling to itself");
    aPrevSibling = mBullet;
  }
  
  nsIPresShell *presShell = PresContext()->PresShell();

  // Attempt to find the line that contains the previous sibling
  nsFrameList overflowFrames;
  nsLineList* lineList = &mLines;
  nsLineList::iterator prevSibLine = lineList->end();
  PRInt32 prevSiblingIndex = -1;
  if (aPrevSibling) {
    // XXX_perf This is technically O(N^2) in some cases, but by using
    // RFind instead of Find, we make it O(N) in the most common case,
    // which is appending content.

    // Find the line that contains the previous sibling
    if (!nsLineBox::RFindLineContaining(aPrevSibling, lineList->begin(),
                                        prevSibLine, mFrames.LastChild(),
                                        &prevSiblingIndex)) {
      // Not in mLines - try overflow lines.
      lineList = GetOverflowLines();
      if (lineList) {
        prevSibLine = lineList->end();
        prevSiblingIndex = -1;
        overflowFrames = nsFrameList(lineList->front()->mFirstChild,
                                     lineList->back()->LastChild());
        if (!nsLineBox::RFindLineContaining(aPrevSibling, lineList->begin(),
                                            prevSibLine,
                                            overflowFrames.LastChild(),
                                            &prevSiblingIndex)) {
          lineList = nsnull;
        }
      }
      if (!lineList) {
        // Note: defensive code! RFindLineContaining must not return
        // false in this case, so if it does...
        NS_NOTREACHED("prev sibling not in line list");
        lineList = &mLines;
        aPrevSibling = nsnull;
        prevSibLine = lineList->end();
      }
    }
  }

  // Find the frame following aPrevSibling so that we can join up the
  // two lists of frames.
  if (aPrevSibling) {
    // Split line containing aPrevSibling in two if the insertion
    // point is somewhere in the middle of the line.
    PRInt32 rem = prevSibLine->GetChildCount() - prevSiblingIndex - 1;
    if (rem) {
      // Split the line in two where the frame(s) are being inserted.
      nsLineBox* line = NS_NewLineBox(presShell, aPrevSibling->GetNextSibling(), rem, false);
      if (!line) {
        return NS_ERROR_OUT_OF_MEMORY;
      }
      lineList->after_insert(prevSibLine, line);
      prevSibLine->SetChildCount(prevSibLine->GetChildCount() - rem);
      // Mark prevSibLine dirty and as needing textrun invalidation, since
      // we may be breaking up text in the line. Its previous line may also
      // need to be invalidated because it may be able to pull some text up.
      MarkLineDirty(prevSibLine);
      // The new line will also need its textruns recomputed because of the
      // frame changes.
      line->MarkDirty();
      line->SetInvalidateTextRuns(true);
    }
  }
  else if (! lineList->empty()) {
    lineList->front()->MarkDirty();
    lineList->front()->SetInvalidateTextRuns(true);
  }
  nsFrameList& frames = lineList == &mLines ? mFrames : overflowFrames;
  const nsFrameList::Slice& newFrames =
    frames.InsertFrames(nsnull, aPrevSibling, aFrameList);

  // Walk through the new frames being added and update the line data
  // structures to fit.
  for (nsFrameList::Enumerator e(newFrames); !e.AtEnd(); e.Next()) {
    nsIFrame* newFrame = e.get();
    NS_ASSERTION(!aPrevSibling || aPrevSibling->GetNextSibling() == newFrame,
                 "Unexpected aPrevSibling");
    NS_ASSERTION(newFrame->GetType() != nsGkAtoms::placeholderFrame ||
                 (!newFrame->GetStyleDisplay()->IsAbsolutelyPositioned() &&
                  !newFrame->GetStyleDisplay()->IsFloating()),
                 "Placeholders should not float or be positioned");

    bool isBlock = newFrame->GetStyleDisplay()->IsBlockOutside();

    // If the frame is a block frame, or if there is no previous line or if the
    // previous line is a block line we need to make a new line.  We also make
    // a new line, as an optimization, in the two cases we know we'll need it:
    // if the previous line ended with a <br>, or if it has significant whitespace
    // and ended in a newline.
    if (isBlock || prevSibLine == lineList->end() || prevSibLine->IsBlock() ||
        (aPrevSibling && ShouldPutNextSiblingOnNewLine(aPrevSibling))) {
      // Create a new line for the frame and add its line to the line
      // list.
      nsLineBox* line = NS_NewLineBox(presShell, newFrame, 1, isBlock);
      if (!line) {
        return NS_ERROR_OUT_OF_MEMORY;
      }
      if (prevSibLine != lineList->end()) {
        // Append new line after prevSibLine
        lineList->after_insert(prevSibLine, line);
        ++prevSibLine;
      }
      else {
        // New line is going before the other lines
        lineList->push_front(line);
        prevSibLine = lineList->begin();
      }
    }
    else {
      prevSibLine->SetChildCount(prevSibLine->GetChildCount() + 1);
      // We're adding inline content to prevSibLine, so we need to mark it
      // dirty, ensure its textruns are recomputed, and possibly do the same
      // to its previous line since that line may be able to pull content up.
      MarkLineDirty(prevSibLine);
    }

    aPrevSibling = newFrame;
  }

#ifdef DEBUG
  VerifyLines(true);
#endif
  return NS_OK;
}