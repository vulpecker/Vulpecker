
void
CVE_2013_1685_thunderbird17_0_5_nsDocument::ResetToURI(nsIURI *aURI, nsILoadGroup *aLoadGroup,
                       nsIPrincipal* aPrincipal)
{
  NS_PRECONDITION(aURI, "Null URI passed to ResetToURI");

#ifdef PR_LOGGING
  if (gDocumentLeakPRLog && PR_LOG_TEST(gDocumentLeakPRLog, PR_LOG_DEBUG)) {
    nsCAutoString spec;
    aURI->GetSpec(spec);
    PR_LogPrint("DOCUMENT %p ResetToURI %s", this, spec.get());
  }
#endif

  mSecurityInfo = nullptr;

  mDocumentLoadGroup = nullptr;

  // Delete references to sub-documents and kill the subdocument map,
  // if any. It holds strong references
  if (mSubDocuments) {
    PL_DHashTableDestroy(mSubDocuments);

    mSubDocuments = nullptr;
  }

  // Destroy link map now so we don't waste time removing
  // links one by one
  DestroyElementMaps();

  bool oldVal = mInUnlinkOrDeletion;
  mInUnlinkOrDeletion = true;
  uint32_t count = mChildren.ChildCount();
  { // Scope for update
    MOZ_AUTO_DOC_UPDATE(this, UPDATE_CONTENT_MODEL, true);    
    for (int32_t i = int32_t(count) - 1; i >= 0; i--) {
      nsCOMPtr<nsIContent> content = mChildren.ChildAt(i);

      nsIContent* previousSibling = content->GetPreviousSibling();

      if (nsINode::GetFirstChild() == content) {
        mFirstChild = content->GetNextSibling();
      }
      mChildren.RemoveChildAt(i);
      nsNodeUtils::ContentRemoved(this, content, i, previousSibling);
      content->UnbindFromTree();
    }
  }
  mInUnlinkOrDeletion = oldVal;
  mCachedRootElement = nullptr;

  // Reset our stylesheets
  ResetStylesheetsToURI(aURI);
  
  // Release the listener manager
  if (mListenerManager) {
    mListenerManager->Disconnect();
    mListenerManager = nullptr;
  }

  // Release the stylesheets list.
  mDOMStyleSheets = nullptr;

  // Release our principal after tearing down the document, rather than before.
  // This ensures that, during teardown, the document and the dying window (which
  // already nulled out its document pointer and cached the principal) have
  // matching principals.
  SetPrincipal(nullptr);

  // Clear the original URI so SetDocumentURI sets it.
  mOriginalURI = nullptr;

  SetDocumentURI(aURI);
  // If mDocumentBaseURI is null, nsIDocument::GetBaseURI() returns
  // mDocumentURI.
  mDocumentBaseURI = nullptr;

  if (aLoadGroup) {
    mDocumentLoadGroup = do_GetWeakReference(aLoadGroup);
    // there was an assertion here that aLoadGroup was not null.  This
    // is no longer valid: nsDocShell::SetDocument does not create a
    // load group, and it works just fine

    // XXXbz what does "just fine" mean exactly?  And given that there
    // is no nsDocShell::SetDocument, what is this talking about?
  }

  mLastModified.Truncate();
  // XXXbz I guess we're assuming that the caller will either pass in
  // a channel with a useful type or call SetContentType?
  SetContentTypeInternal(EmptyCString());
  mContentLanguage.Truncate();
  mBaseTarget.Truncate();
  mReferrer.Truncate();

  mXMLDeclarationBits = 0;

  // Now get our new principal
  if (aPrincipal) {
    SetPrincipal(aPrincipal);
  } else {
    nsIScriptSecurityManager *securityManager =
      nsContentUtils::GetSecurityManager();
    if (securityManager) {
      nsCOMPtr<nsIDocShell> docShell = do_QueryReferent(mDocumentContainer);

      if (!docShell && aLoadGroup) {
        nsCOMPtr<nsIInterfaceRequestor> cbs;
        aLoadGroup->GetNotificationCallbacks(getter_AddRefs(cbs));
        docShell = do_GetInterface(cbs);
      }

      MOZ_ASSERT(docShell,
                 "must be in a docshell or pass in an explicit principal");

      nsCOMPtr<nsIPrincipal> principal;
      nsresult rv = securityManager->
        GetDocShellCodebasePrincipal(mDocumentURI, docShell,
                                     getter_AddRefs(principal));
      if (NS_SUCCEEDED(rv)) {
        SetPrincipal(principal);
      }
    }
  }

  // Refresh the principal on the compartment.
  nsPIDOMWindow* win = GetInnerWindow();
  if (win) {
    win->RefreshCompartmentPrincipal();
  }
}