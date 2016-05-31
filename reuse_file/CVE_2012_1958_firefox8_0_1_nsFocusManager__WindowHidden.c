
NS_IMETHODIMP
CVE_2012_1958_firefox8_0_1_nsFocusManager::WindowHidden(nsIDOMWindow* aWindow)
{
  // if there is no window or it is not the same or an ancestor of the
  // currently focused window, just return, as the current focus will not
  // be affected.

  nsCOMPtr<nsPIDOMWindow> window = do_QueryInterface(aWindow);
  NS_ENSURE_TRUE(window, NS_ERROR_INVALID_ARG);

  window = window->GetOuterWindow();

#ifdef DEBUG_FOCUS
  printf("Window %p Hidden [Currently: %p %p] <<", window.get(), mActiveWindow.get(), mFocusedWindow.get());
  nsCAutoString spec;
  nsCOMPtr<nsIDocument> doc = do_QueryInterface(window->GetExtantDocument());
  if (doc) {
    doc->GetDocumentURI()->GetSpec(spec);
    printf("Hide Window: %s", spec.get());
  }

  if (mFocusedWindow) {
    doc = do_QueryInterface(mFocusedWindow->GetExtantDocument());
    if (doc) {
      doc->GetDocumentURI()->GetSpec(spec);
      printf(" Focused Window: %s", spec.get());
    }
  }

  if (mActiveWindow) {
    doc = do_QueryInterface(mActiveWindow->GetExtantDocument());
    if (doc) {
      doc->GetDocumentURI()->GetSpec(spec);
      printf(" Active Window: %s", spec.get());
    }
  }
  printf(">>\n");
#endif

  if (!IsSameOrAncestor(window, mFocusedWindow))
    return NS_OK;

  // at this point, we know that the window being hidden is either the focused
  // window, or an ancestor of the focused window. Either way, the focus is no
  // longer valid, so it needs to be updated.

  nsIContent* oldFocusedContent = mFocusedContent;
  mFocusedContent = nsnull;

  if (oldFocusedContent && oldFocusedContent->IsInDoc()) {
    NotifyFocusStateChange(oldFocusedContent,
                           mFocusedWindow->ShouldShowFocusRing(),
                           PR_FALSE);
  }

  nsCOMPtr<nsIDocShell> focusedDocShell = mFocusedWindow->GetDocShell();
  nsCOMPtr<nsIPresShell> presShell;
  focusedDocShell->GetPresShell(getter_AddRefs(presShell));

  nsIMEStateManager::OnTextStateBlur(nsnull, nsnull);
  if (presShell) {
    nsIMEStateManager::OnChangeFocus(presShell->GetPresContext(), nsnull, IMEContext::FOCUS_REMOVED);
    SetCaretVisible(presShell, PR_FALSE, nsnull);
  }

  // if the docshell being hidden is being destroyed, then we want to move
  // focus somewhere else. Call ClearFocus on the toplevel window, which
  // will have the effect of clearing the focus and moving the focused window
  // to the toplevel window. But if the window isn't being destroyed, we are
  // likely just loading a new document in it, so we want to maintain the
  // focused window so that the new document gets properly focused.
  PRBool beingDestroyed;
  nsCOMPtr<nsIDocShell> docShellBeingHidden = window->GetDocShell();
  docShellBeingHidden->IsBeingDestroyed(&beingDestroyed);
  if (beingDestroyed) {
    // There is usually no need to do anything if a toplevel window is going
    // away, as we assume that WindowLowered will be called. However, this may
    // not happen if nsIAppStartup::eForceQuit is used to quit, and can cause
    // a leak. So if the active window is being destroyed, call WindowLowered
    // directly.
    NS_ASSERTION(mFocusedWindow->IsOuterWindow(), "outer window expected");
    if (mActiveWindow == mFocusedWindow || mActiveWindow == window)
      WindowLowered(mActiveWindow);
    else
      ClearFocus(mActiveWindow);
    return NS_OK;
  }

  // if the window being hidden is an ancestor of the focused window, adjust
  // the focused window so that it points to the one being hidden. This
  // ensures that the focused window isn't in a chain of frames that doesn't
  // exist any more.
  if (window != mFocusedWindow) {
    nsCOMPtr<nsIWebNavigation> webnav(do_GetInterface(mFocusedWindow));
    nsCOMPtr<nsIDocShellTreeItem> dsti = do_QueryInterface(webnav);
    if (dsti) {
      nsCOMPtr<nsIDocShellTreeItem> parentDsti;
      dsti->GetParent(getter_AddRefs(parentDsti));
      nsCOMPtr<nsPIDOMWindow> parentWindow = do_GetInterface(parentDsti);
      if (parentWindow)
        parentWindow->SetFocusedNode(nsnull);
    }

    mFocusedWindow = window;
  }

  return NS_OK;
}