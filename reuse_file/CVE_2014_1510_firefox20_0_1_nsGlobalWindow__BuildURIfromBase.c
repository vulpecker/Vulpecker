
nsresult
CVE_2014_1510_firefox20_0_1_nsGlobalWindow::BuildURIfromBase(const char *aURL, nsIURI **aBuiltURI,
                                 bool *aFreeSecurityPass,
                                 JSContext **aCXused)
{
  nsIScriptContext *scx = GetContextInternal();
  JSContext *cx = nullptr;

  *aBuiltURI = nullptr;
  *aFreeSecurityPass = false;
  if (aCXused)
    *aCXused = nullptr;

  // get JSContext
  NS_ASSERTION(scx, "opening window missing its context");
  NS_ASSERTION(mDocument, "opening window missing its document");
  if (!scx || !mDocument)
    return NS_ERROR_FAILURE;

  nsCOMPtr<nsIDOMChromeWindow> chrome_win = do_QueryObject(this);

  if (nsContentUtils::IsCallerChrome() && !chrome_win) {
    // If open() is called from chrome on a non-chrome window, we'll
    // use the context from the window on which open() is being called
    // to prevent giving chrome priveleges to new windows opened in
    // such a way. This also makes us get the appropriate base URI for
    // the below URI resolution code.

    cx = scx->GetNativeContext();
  } else {
    // get the JSContext from the call stack
    nsCOMPtr<nsIThreadJSContextStack> stack(do_GetService(sJSStackContractID));
    if (stack)
      stack->Peek(&cx);
  }

  /* resolve the URI, which could be relative to the calling window
     (note the algorithm to get the base URI should match the one
     used to actually kick off the load in nsWindowWatcher.cpp). */
  nsAutoCString charset(NS_LITERAL_CSTRING("UTF-8")); // default to utf-8
  nsIURI* baseURI = nullptr;
  nsCOMPtr<nsIURI> uriToLoad;
  nsCOMPtr<nsIDOMWindow> sourceWindow;

  if (cx) {
    nsIScriptContext *scriptcx = nsJSUtils::GetDynamicScriptContext(cx);
    if (scriptcx)
      sourceWindow = do_QueryInterface(scriptcx->GetGlobalObject());
  }

  if (!sourceWindow) {
    sourceWindow = do_QueryInterface(NS_ISUPPORTS_CAST(nsIDOMWindow *, this));
    *aFreeSecurityPass = true;
  }

  if (sourceWindow) {
    nsCOMPtr<nsIDOMDocument> domDoc;
    sourceWindow->GetDocument(getter_AddRefs(domDoc));
    nsCOMPtr<nsIDocument> doc(do_QueryInterface(domDoc));
    if (doc) {
      baseURI = doc->GetDocBaseURI();
      charset = doc->GetDocumentCharacterSet();
    }
  }

  if (aCXused)
    *aCXused = cx;
  return NS_NewURI(aBuiltURI, nsDependentCString(aURL), charset.get(), baseURI);
}