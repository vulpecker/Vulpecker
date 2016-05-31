
void
CVE_2013_5618_seamonkey2_17_Element::UnbindFromTree(bool aDeep, bool aNullParent)
{
  NS_PRECONDITION(aDeep || (!GetCurrentDoc() && !GetBindingParent()),
                  "Shallow unbind won't clear document and binding parent on "
                  "kids!");

  RemoveFromIdTable();

  // Make sure to unbind this node before doing the kids
  nsIDocument *document =
    HasFlag(NODE_FORCE_XBL_BINDINGS) ? OwnerDoc() : GetCurrentDoc();

  if (aNullParent) {
    if (IsFullScreenAncestor()) {
      // The element being removed is an ancestor of the full-screen element,
      // exit full-screen state.
      nsContentUtils::ReportToConsole(nsIScriptError::warningFlag,
                                      "DOM", OwnerDoc(),
                                      nsContentUtils::eDOM_PROPERTIES,
                                      "RemovedFullScreenElement");
      // Fully exit full-screen.
      nsIDocument::ExitFullScreen(false);
    }
    if (HasPointerLock()) {
      nsIDocument::UnlockPointer();
    }
    if (GetParent()) {
      NS_RELEASE(mParent);
    } else {
      mParent = nullptr;
    }
    SetParentIsContent(false);
  }
  ClearInDocument();

  // Begin keeping track of our subtree root.
  SetSubtreeRootPointer(aNullParent ? this : mParent->SubtreeRoot());

  if (document) {
    // Notify XBL- & nsIAnonymousContentCreator-generated
    // anonymous content that the document is changing.
    if (HasFlag(NODE_MAY_BE_IN_BINDING_MNGR)) {
      nsContentUtils::AddScriptRunner(
        new RemoveFromBindingManagerRunnable(document->BindingManager(), this,
                                             document, GetBindingParent()));
    }

    document->ClearBoxObjectFor(this);
  }

  // Ensure that CSS transitions don't continue on an element at a
  // different place in the tree (even if reinserted before next
  // animation refresh).
  // FIXME (Bug 522599): Need a test for this.
  if (HasFlag(NODE_HAS_PROPERTIES)) {
    DeleteProperty(nsGkAtoms::transitionsOfBeforeProperty);
    DeleteProperty(nsGkAtoms::transitionsOfAfterProperty);
    DeleteProperty(nsGkAtoms::transitionsProperty);
    DeleteProperty(nsGkAtoms::animationsOfBeforeProperty);
    DeleteProperty(nsGkAtoms::animationsOfAfterProperty);
    DeleteProperty(nsGkAtoms::animationsProperty);
  }

  // Unset this since that's what the old code effectively did.
  UnsetFlags(NODE_FORCE_XBL_BINDINGS);
  
#ifdef MOZ_XUL
  nsXULElement* xulElem = nsXULElement::FromContent(this);
  if (xulElem) {
    xulElem->SetXULBindingParent(nullptr);
  }
  else
#endif
  {
    nsDOMSlots *slots = GetExistingDOMSlots();
    if (slots) {
      slots->mBindingParent = nullptr;
    }
  }

  // This has to be here, rather than in nsGenericHTMLCVE_2013_5618_seamonkey2_17_Element::UnbindFromTree, 
  //  because it has to happen after unsetting the parent pointer, but before
  //  recursively unbinding the kids.
  if (IsHTML()) {
    RecomputeDirectionality(this, false);
  }

  if (aDeep) {
    // Do the kids. Don't call GetChildCount() here since that'll force
    // XUL to generate template children, which there is no need for since
    // all we're going to do is unbind them anyway.
    uint32_t i, n = mAttrsAndChildren.ChildCount();

    for (i = 0; i < n; ++i) {
      // Note that we pass false for aNullParent here, since we don't want
      // the kids to forget us.  We _do_ want them to forget their binding
      // parent, though, since this only walks non-anonymous kids.
      mAttrsAndChildren.ChildAt(i)->UnbindFromTree(true, false);
    }
  }

  nsNodeUtils::ParentChainChanged(this);
}