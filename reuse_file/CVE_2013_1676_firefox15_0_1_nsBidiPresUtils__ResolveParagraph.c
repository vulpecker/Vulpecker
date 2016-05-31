
nsresult
CVE_2013_1676_firefox15_0_1_nsBidiPresUtils::ResolveParagraph(nsBlockFrame* aBlockFrame,
                                  BidiParagraphData* aBpd)
{
  nsPresContext *presContext = aBlockFrame->PresContext();

  if (aBpd->BufferLength() < 1) {
    return NS_OK;
  }
  aBpd->mBuffer.ReplaceChar("\t\r\n", kSpace);

  PRInt32 runCount;

  nsresult rv = aBpd->SetPara();
  NS_ENSURE_SUCCESS(rv, rv);

  PRUint8 embeddingLevel = aBpd->GetParaLevel();

  rv = aBpd->CountRuns(&runCount);
  NS_ENSURE_SUCCESS(rv, rv);

  PRInt32     runLength      = 0;   // the length of the current run of text
  PRInt32     lineOffset     = 0;   // the start of the current run
  PRInt32     logicalLimit   = 0;   // the end of the current run + 1
  PRInt32     numRun         = -1;
  PRInt32     fragmentLength = 0;   // the length of the current text frame
  PRInt32     frameIndex     = -1;  // index to the frames in mLogicalFrames
  PRInt32     frameCount     = aBpd->FrameCount();
  PRInt32     contentOffset  = 0;   // offset of current frame in its content node
  bool        isTextFrame    = false;
  nsIFrame*   frame = nsnull;
  nsIContent* content = nsnull;
  PRInt32     contentTextLength = 0;

  FramePropertyTable *propTable = presContext->PropertyTable();
  nsLineBox* currentLine = nsnull;
  
#ifdef DEBUG
#ifdef NOISY_BIDI
  printf("Before Resolve(), aBlockFrame=0x%p, mBuffer='%s', frameCount=%d, runCount=%d\n",
         (void*)aBlockFrame, NS_ConvertUTF16toUTF8(aBpd->mBuffer).get(), frameCount, runCount);
#ifdef REALLY_NOISY_BIDI
  printf(" block frame tree=:\n");
  aBlockFrame->List(stdout, 0);
#endif
#endif
#endif

  nsIFrame* firstFrame = nsnull;
  nsIFrame* lastFrame = nsnull;

  for (; ;) {
    if (fragmentLength <= 0) {
      // Get the next frame from mLogicalFrames
      if (++frameIndex >= frameCount) {
        break;
      }
      frame = aBpd->FrameAt(frameIndex);
      if (frame == NS_BIDI_CONTROL_FRAME ||
          nsGkAtoms::textFrame != frame->GetType()) {
        /*
         * Any non-text frame corresponds to a single character in the text buffer
         * (a bidi control character, LINE SEPARATOR, or OBJECT SUBSTITUTE)
         */
        isTextFrame = false;
        fragmentLength = 1;
      }
      else {
        if (!firstFrame) {
          firstFrame = frame;
        }
        lastFrame = frame;
        currentLine = aBpd->GetLineForFrameAt(frameIndex);
        content = frame->GetContent();
        if (!content) {
          rv = NS_OK;
          break;
        }
        contentTextLength = content->TextLength();
        if (contentTextLength == 0) {
          frame->AdjustOffsetsForBidi(0, 0);
          // Set the base level and embedding level of the current run even
          // on an empty frame. Otherwise frame reordering will not be correct.
          propTable->Set(frame, nsIFrame::EmbeddingLevelProperty(),
                         NS_INT32_TO_PTR(embeddingLevel));
          propTable->Set(frame, nsIFrame::BaseLevelProperty(),
                         NS_INT32_TO_PTR(aBpd->GetParaLevel()));
          propTable->Set(frame, nsIFrame::ParagraphDepthProperty(),
                         NS_INT32_TO_PTR(aBpd->mParagraphDepth));
          continue;
        }
        PRInt32 start, end;
        frame->GetOffsets(start, end);
        NS_ASSERTION(!(contentTextLength < end - start),
                     "Frame offsets don't fit in content");
        fragmentLength = NS_MIN(contentTextLength, end - start);
        contentOffset = start;
        isTextFrame = true;
      }
    } // if (fragmentLength <= 0)

    if (runLength <= 0) {
      // Get the next run of text from the Bidi engine
      if (++numRun >= runCount) {
        break;
      }
      lineOffset = logicalLimit;
      if (NS_FAILED(aBpd->GetLogicalRun(
              lineOffset, &logicalLimit, &embeddingLevel) ) ) {
        break;
      }
      runLength = logicalLimit - lineOffset;
    } // if (runLength <= 0)

    if (frame == NS_BIDI_CONTROL_FRAME) {
      frame = nsnull;
      ++lineOffset;
    }
    else {
      propTable->Set(frame, nsIFrame::EmbeddingLevelProperty(),
                     NS_INT32_TO_PTR(embeddingLevel));
      propTable->Set(frame, nsIFrame::BaseLevelProperty(),
                     NS_INT32_TO_PTR(aBpd->GetParaLevel()));
      propTable->Set(frame, nsIFrame::ParagraphDepthProperty(),
                     NS_INT32_TO_PTR(aBpd->mParagraphDepth));
      if (isTextFrame) {
        if ( (runLength > 0) && (runLength < fragmentLength) ) {
          /*
           * The text in this frame continues beyond the end of this directional run.
           * Create a non-fluid continuation frame for the next directional run.
           */
          currentLine->MarkDirty();
          nsIFrame* nextBidi;
          PRInt32 runEnd = contentOffset + runLength;
          rv = EnsureBidiContinuation(frame, &nextBidi, frameIndex,
                                      contentOffset,
                                      runEnd);
          if (NS_FAILED(rv)) {
            break;
          }
          nextBidi->AdjustOffsetsForBidi(runEnd,
                                         contentOffset + fragmentLength);
          lastFrame = frame = nextBidi;
          contentOffset = runEnd;
        } // if (runLength < fragmentLength)
        else {
          if (contentOffset + fragmentLength == contentTextLength) {
            /* 
             * We have finished all the text in this content node. Convert any
             * further non-fluid continuations to fluid continuations and advance
             * frameIndex to the last frame in the content node
             */
            PRInt32 newIndex = aBpd->GetLastFrameForContent(content);
            if (newIndex > frameIndex) {
              RemoveBidiContinuation(aBpd, frame,
                                     frameIndex, newIndex, lineOffset);
              frameIndex = newIndex;
              lastFrame = frame = aBpd->FrameAt(frameIndex);
            }
          } else if (fragmentLength > 0 && runLength > fragmentLength) {
            /*
             * There is more text that belongs to this directional run in the next
             * text frame: make sure it is a fluid continuation of the current frame.
             * Do not advance frameIndex, because the next frame may contain
             * multi-directional text and need to be split
             */
            PRInt32 newIndex = frameIndex;
            do {
            } while (++newIndex < frameCount &&
                     aBpd->FrameAt(newIndex) == NS_BIDI_CONTROL_FRAME);
            if (newIndex < frameCount) {
              RemoveBidiContinuation(aBpd, frame,
                                     frameIndex, newIndex, lineOffset);
            }
          } else if (runLength == fragmentLength) {
            /*
             * If the directional run ends at the end of the frame, make sure
             * that any continuation is non-fluid
             */
            nsIFrame* next = frame->GetNextInFlow();
            if (next) {
              frame->SetNextContinuation(next);
              next->SetPrevContinuation(frame);
            }
          }
          frame->AdjustOffsetsForBidi(contentOffset, contentOffset + fragmentLength);
          currentLine->MarkDirty();
        }
      } // isTextFrame
      else {
        ++lineOffset;
      }
    } // not bidi control frame
    PRInt32 temp = runLength;
    runLength -= fragmentLength;
    fragmentLength -= temp;

    if (frame && fragmentLength <= 0) {
      // If the frame is at the end of a run, and this is not the end of our
      // paragrah, split all ancestor inlines that need splitting.
      // To determine whether we're at the end of the run, we check that we've
      // finished processing the current run, and that the current frame
      // doesn't have a fluid continuation (it could have a fluid continuation
      // of zero length, so testing runLength alone is not sufficient).
      if (runLength <= 0 && !frame->GetNextInFlow()) {
        if (numRun + 1 < runCount) {
          nsIFrame* child = frame;
          nsIFrame* parent = frame->GetParent();
          // As long as we're on the last sibling, the parent doesn't have to
          // be split.
          // However, if the parent has a fluid continuation, we do have to make
          // it non-fluid. This can happen e.g. when we have a first-letter
          // frame and the end of the first-letter coincides with the end of a
          // directional run.
          while (parent &&
                 IsBidiSplittable(parent) &&
                 !child->GetNextSibling()) {
            nsIFrame* next = parent->GetNextInFlow();
            if (next) {
              parent->SetNextContinuation(next);
              next->SetPrevContinuation(parent);
            }
            child = parent;
            parent = child->GetParent();
          }
          if (parent && IsBidiSplittable(parent)) {
            SplitInlineAncestors(parent, child);
          }
        }
      }
      else {
        // We're not at an end of a run. If |frame| is the last child of its
        // parent, and its ancestors happen to have bidi continuations, convert
        // them into fluid continuations.
        JoinInlineAncestors(frame);
      }
    }
  } // for

  if (aBpd->mParagraphDepth > 1) {
    nsIFrame* child;
    nsIFrame* parent;
    if (firstFrame) {
      child = firstFrame->GetParent();
      if (child) {
        parent = child->GetParent();
        if (parent && IsBidiSplittable(parent)) {
          // no need to null-check the result of GetPrevSibling, because
          // SplitInlineAncestors accepts a null parameter
          SplitInlineAncestors(parent, child->GetPrevSibling());
        }
      }
    }
    if (lastFrame) {
      child = lastFrame->GetParent();
      if (child) {
        parent = child->GetParent();
        if (parent && IsBidiSplittable(parent)) {
          SplitInlineAncestors(parent, child);
        }
      }
    }
  }

#ifdef DEBUG
#ifdef REALLY_NOISY_BIDI
  printf("---\nAfter Resolve(), frameTree =:\n");
  aBlockFrame->List(stdout, 0);
  printf("===\n");
#endif
#endif

  return rv;
}