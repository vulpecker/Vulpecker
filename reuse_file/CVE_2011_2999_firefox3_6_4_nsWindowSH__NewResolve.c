
NS_IMETHODIMP
CVE_2011_2999_firefox3_6_4_nsWindowSH::NewResolve(nsIXPConnectWrappedNative *wrapper, JSContext *cx,
                       JSObject *obj, jsval id, PRUint32 flags,
                       JSObject **objp, PRBool *_retval)
{
  nsGlobalWindow *win = nsGlobalWindow::FromWrapper(wrapper);

#ifdef DEBUG_SH_FORWARDING
  {
    nsDependentJSString str(::JS_ValueToString(cx, id));

    if (win->IsInnerWindow()) {
#ifdef DEBUG_PRINT_INNER
      printf("Property '%s' resolve on inner window %p\n",
             NS_ConvertUTF16toUTF8(str).get(), (void *)win);
#endif
    } else {
      printf("Property '%s' resolve on outer window %p\n",
             NS_ConvertUTF16toUTF8(str).get(), (void *)win);
    }
  }
#endif

  // Note, we won't forward resolve of the location property to the
  // inner window, we need to deal with that one for the outer too
  // since we've got special security protection code for that
  // property.  Also note that we want to enter this block even for
  // native wrappers, so that we'll ensure an inner window to wrap
  // against for the result of whatever we're getting.
  if (win->IsOuterWindow() && id != sLocation_id) {
    // XXXjst: Do security checks here when we remove the security
    // checks on the inner window.

    nsGlobalWindow *innerWin = win->GetCurrentInnerWindowInternal();

    if ((!innerWin || !innerWin->GetExtantDocument()) &&
        !win->IsCreatingInnerWindow()) {
      // We're resolving a property on an outer window for which there
      // is no inner window yet, and we're not in the midst of
      // creating the inner window or in the middle of initializing
      // XPConnect classes on it. If the context is already
      // initialized, force creation of a new inner window. This will
      // create a synthetic about:blank document, and an inner window
      // which may be reused by the actual document being loaded into
      // this outer window. This way properties defined on the window
      // before the document load started will be visible to the
      // document once it's loaded, assuming same origin etc.
      nsIScriptContext *scx = win->GetContextInternal();

      if (scx && scx->IsContextInitialized()) {
        // Grab the new inner window.
        innerWin = win->EnsureInnerWindowInternal();

        if (!innerWin) {
          return NS_ERROR_OUT_OF_MEMORY;
        }
      }
    }

    JSObject *innerObj;
    JSObject *realObj;
    wrapper->GetJSObject(&realObj);
    if (realObj == obj &&
        innerWin && (innerObj = innerWin->GetGlobalJSObject())) {
#ifdef DEBUG_SH_FORWARDING
      printf(" --- Forwarding resolve to inner window %p\n", (void *)innerWin);
#endif

      jsid interned_id;
      JSObject *pobj = NULL;
      jsval val;

      *_retval = (::JS_ValueToId(cx, id, &interned_id) &&
                  ::JS_LookupPropertyWithFlagsById(cx, innerObj, interned_id,
                                                   flags, &pobj, &val));

      if (*_retval && pobj) {
#ifdef DEBUG_SH_FORWARDING
        printf(" --- Resolve on inner window found property.\n");
#endif
        *objp = pobj;
      }

      return NS_OK;
    }
  }

  if (!JSVAL_IS_STRING(id)) {
    if (JSVAL_IS_INT(id) && !(flags & JSRESOLVE_ASSIGNING)) {
      // If we're resolving a numeric property, treat that as if
      // window.frames[n] is resolved (since window.frames ===
      // window), if window.frames[n] is a child frame, define a
      // property for this index.

      nsCOMPtr<nsIDOMWindow> frame = GetChildFrame(win, id);

      if (frame) {
        // A numeric property accessed and the numeric property is a
        // child frame. Define a property for this index.

        *_retval = ::JS_DefineElement(cx, obj, JSVAL_TO_INT(id), JSVAL_VOID,
                                      nsnull, nsnull, 0);

        if (*_retval) {
          *objp = obj;
        }
      }
    }

    return NS_OK;
  }

  nsIScriptContext *my_context = win->GetContextInternal();

  nsresult rv = NS_OK;

  // Resolve standard classes on my_context's JSContext (or on cx,
  // if we don't have a my_context yet), in case the two contexts
  // have different origins.  We want lazy standard class
  // initialization to behave as if it were done eagerly, on each
  // window's own context (not on some other window-caller's
  // context).

  JSBool did_resolve = JS_FALSE;
  JSContext *my_cx;

  if (!my_context) {
    my_cx = cx;
  } else {
    my_cx = (JSContext *)my_context->GetNativeContext();
  }

  JSBool ok;
  jsval exn;
  {
    JSAutoSuspendRequest asr(my_cx != cx ? cx : nsnull);
    {
      JSAutoRequest ar(my_cx);

      JSObject *realObj;
      wrapper->GetJSObject(&realObj);

      // Don't resolve standard classes on XPCNativeWrapper etc, only
      // resolve them if we're resolving on the real global object.
      ok = obj == realObj ?
           ::JS_ResolveStandardClass(my_cx, obj, id, &did_resolve) :
           JS_TRUE;

      if (!ok) {
        // Trust the JS engine (or the script security manager) to set
        // the exception in the JS engine.

        if (!JS_GetPendingException(my_cx, &exn)) {
          return NS_ERROR_UNEXPECTED;
        }

        // Return NS_OK to avoid stomping over the exception that was passed
        // down from the ResolveStandardClass call.
        // Note that the order of the JS_ClearPendingException and
        // JS_SetPendingException is important in the case that my_cx == cx.

        JS_ClearPendingException(my_cx);
      }
    }
  }

  if (!ok) {
    JS_SetPendingException(cx, exn);
    *_retval = JS_FALSE;
    return NS_OK;
  }

  if (did_resolve) {
    *objp = obj;

    return NS_OK;
  }

  if (!(flags & JSRESOLVE_ASSIGNING)) {
    // We want this code to be before the child frame lookup code
    // below so that a child frame named 'constructor' doesn't
    // shadow the window's constructor property.
    if (id == sConstructor_id) {
      return ResolveConstructor(cx, obj, objp);
    }
  }

  if (!my_context || !my_context->IsContextInitialized()) {
    // The context is not yet initialized so there's nothing we can do
    // here yet.

    return NS_OK;
  }


  // Hmm, we do an awful lot of QIs here; maybe we should add a
  // method on an interface that would let us just call into the
  // window code directly...

  JSString *str = JSVAL_TO_STRING(id);

  // Don't resolve named frames on native wrappers
  if (!ObjectIsNativeWrapper(cx, obj)) {
    nsCOMPtr<nsIDocShellTreeNode> dsn(do_QueryInterface(win->GetDocShell()));

    PRInt32 count = 0;

    if (dsn) {
      dsn->GetChildCount(&count);
    }

    if (count > 0) {
      nsCOMPtr<nsIDocShellTreeItem> child;

      const jschar *chars = ::JS_GetStringChars(str);

      dsn->FindChildWithName(reinterpret_cast<const PRUnichar*>(chars),
                             PR_FALSE, PR_TRUE, nsnull, nsnull,
                             getter_AddRefs(child));

      nsCOMPtr<nsIDOMWindow> child_win(do_GetInterface(child));

      if (child_win) {
        // We found a subframe of the right name, define the property
        // on the wrapper so that ::NewResolve() doesn't get called
        // again for this property name.

        JSObject *wrapperObj;
        wrapper->GetJSObject(&wrapperObj);

        jsval v;
        nsCOMPtr<nsIXPConnectJSObjectHolder> holder;
        rv = WrapNative(cx, wrapperObj, child_win,
                        &NS_GET_IID(nsIDOMWindowInternal), PR_TRUE, &v,
                        getter_AddRefs(holder));
        NS_ENSURE_SUCCESS(rv, rv);

#ifdef DEBUG
        if (!win->IsChromeWindow()) {
          NS_ASSERTION(JSVAL_IS_OBJECT(v) &&
                       !strcmp(STOBJ_GET_CLASS(JSVAL_TO_OBJECT(v))->name,
                               "XPCCrossOriginWrapper"),
                       "Didn't wrap a window!");
        }
#endif

        JSAutoRequest ar(cx);

        PRBool ok = ::JS_DefineUCProperty(cx, obj, chars,
                                          ::JS_GetStringLength(str),
                                          v, nsnull, nsnull, 0);

        if (!ok) {
          return NS_ERROR_FAILURE;
        }

        *objp = obj;

        return NS_OK;
      }
    }
  }

  // It is not worth calling GlobalResolve() if we are resolving
  // for assignment, since only read-write properties get dealt
  // with there.
  if (!(flags & JSRESOLVE_ASSIGNING)) {
    JSAutoRequest ar(cx);

    // Call GlobalResolve() after we call FindChildWithName() so
    // that named child frames will override external properties
    // which have been registered with the script namespace manager.

    JSBool did_resolve = JS_FALSE;
    rv = GlobalResolve(win, cx, obj, str, &did_resolve);
    NS_ENSURE_SUCCESS(rv, rv);

    if (did_resolve) {
      // GlobalResolve() resolved something, so we're done here.
      *objp = obj;

      return NS_OK;
    }
  }

  if (id == s_content_id) {
    // Map window._content to window.content for backwards
    // compatibility, this should spit out an message on the JS
    // console.

    JSObject *windowObj = win->GetGlobalJSObject();

    JSAutoRequest ar(cx);

    JSFunction *fun = ::JS_NewFunction(cx, ContentWindowGetter, 0, 0,
                                       windowObj, "_content");
    if (!fun) {
      return NS_ERROR_OUT_OF_MEMORY;
    }

    JSObject *funObj = ::JS_GetFunctionObject(fun);

    nsAutoGCRoot root(&funObj, &rv);
    NS_ENSURE_SUCCESS(rv, rv);

    if (!::JS_DefineUCProperty(cx, windowObj, ::JS_GetStringChars(str),
                               ::JS_GetStringLength(str), JSVAL_VOID,
                               JS_DATA_TO_FUNC_PTR(JSPropertyOp, funObj),
                               nsnull,
                               JSPROP_ENUMERATE | JSPROP_GETTER |
                               JSPROP_SHARED)) {
      return NS_ERROR_FAILURE;
    }

    *objp = obj;

    return NS_OK;
  }

  if (id == sLocation_id) {
    // This must be done even if we're just getting the value of
    // window.location (i.e. no checking flags & JSRESOLVE_ASSIGNING
    // here) since we must define window.location to prevent the
    // getter from being overriden (for security reasons).

    nsCOMPtr<nsIDOMLocation> location;
    rv = win->GetLocation(getter_AddRefs(location));
    NS_ENSURE_SUCCESS(rv, rv);

    // Make sure we wrap the location object in the inner window's
    // scope if we've got an inner window.
    JSObject *scope = nsnull;
    if (win->IsOuterWindow()) {
      nsGlobalWindow *innerWin = win->GetCurrentInnerWindowInternal();

      if (innerWin) {
        scope = innerWin->GetGlobalJSObject();
      }
    }

    if (!scope) {
      wrapper->GetJSObject(&scope);
    }

    nsCOMPtr<nsIXPConnectJSObjectHolder> holder;
    jsval v;
    rv = WrapNative(cx, scope, location, &NS_GET_IID(nsIDOMLocation), PR_TRUE,
                    &v, getter_AddRefs(holder));
    NS_ENSURE_SUCCESS(rv, rv);

#ifdef DEBUG
    if (!win->IsChromeWindow()) {
          NS_ASSERTION(JSVAL_IS_OBJECT(v) &&
                       !strcmp(STOBJ_GET_CLASS(JSVAL_TO_OBJECT(v))->name,
                               "XPCCrossOriginWrapper"),
                       "Didn't wrap a location object!");
    }
#endif

    JSAutoRequest ar(cx);

    JSBool ok = ::JS_DefineUCProperty(cx, obj, ::JS_GetStringChars(str),
                                      ::JS_GetStringLength(str), v, nsnull,
                                      nsnull,
                                      JSPROP_PERMANENT |
                                      JSPROP_ENUMERATE);

    if (!ok) {
      return NS_ERROR_FAILURE;
    }

    *objp = obj;

    return NS_OK;
  }

  if (id == sOnhashchange_id) {
    // Special handling so |"onhashchange" in window| returns true
    jsid interned_id;

    if (!JS_ValueToId(cx, id, &interned_id) ||
        !JS_DefinePropertyById(cx, obj, interned_id, JSVAL_VOID,
                                nsnull, nsnull, JSPROP_ENUMERATE)) {
      *_retval = PR_FALSE;
      return NS_ERROR_FAILURE;
    }

    *objp = obj;
    return NS_OK;
  }

  if (flags & JSRESOLVE_ASSIGNING) {
    if (IsReadonlyReplaceable(id) ||
        (!(flags & JSRESOLVE_QUALIFIED) && IsWritableReplaceable(id))) {
      // A readonly "replaceable" property is being set, or a
      // readwrite "replaceable" property is being set w/o being
      // fully qualified. Define the property on obj with the value
      // undefined to override the predefined property. This is done
      // for compatibility with other browsers.
      JSAutoRequest ar(cx);

      if (!::JS_DefineUCProperty(cx, obj, ::JS_GetStringChars(str),
                                 ::JS_GetStringLength(str),
                                 JSVAL_VOID, JS_PropertyStub, JS_PropertyStub,
                                 JSPROP_ENUMERATE)) {
        return NS_ERROR_FAILURE;
      }
      *objp = obj;

      return NS_OK;
    }
  } else {
    if (id == sNavigator_id) {
      nsCOMPtr<nsIDOMNavigator> navigator;
      rv = win->GetNavigator(getter_AddRefs(navigator));
      NS_ENSURE_SUCCESS(rv, rv);

      jsval v;
      nsCOMPtr<nsIXPConnectJSObjectHolder> holder;
      rv = WrapNative(cx, obj, navigator, &NS_GET_IID(nsIDOMNavigator), PR_TRUE,
                      &v, getter_AddRefs(holder));
      NS_ENSURE_SUCCESS(rv, rv);

      JSAutoRequest ar(cx);

      if (!::JS_DefineUCProperty(cx, obj, ::JS_GetStringChars(str),
                                 ::JS_GetStringLength(str), v, nsnull, nsnull,
                                 JSPROP_READONLY | JSPROP_PERMANENT |
                                 JSPROP_ENUMERATE)) {
        return NS_ERROR_FAILURE;
      }
      *objp = obj;

      return NS_OK;
    }

    if (id == sDocument_id) {
      nsCOMPtr<nsIDOMDocument> document;
      rv = win->GetDocument(getter_AddRefs(document));
      NS_ENSURE_SUCCESS(rv, rv);

      jsval v;
      nsCOMPtr<nsIXPConnectJSObjectHolder> holder;
      rv = WrapNative(cx, obj, document, &NS_GET_IID(nsIDOMDocument), PR_FALSE,
                      &v, getter_AddRefs(holder));
      NS_ENSURE_SUCCESS(rv, rv);

      // The PostCreate hook for the document will handle defining the
      // property
      *objp = obj;

      return NS_OK;
    }

    if (id == sWindow_id) {
      // window should *always* be the outer window object.
      nsGlobalWindow *oldWin = win;
      win = win->GetOuterWindowInternal();
      NS_ENSURE_TRUE(win, NS_ERROR_NOT_AVAILABLE);

      JSAutoRequest ar(cx);

      jsval winVal = OBJECT_TO_JSVAL(win->GetGlobalJSObject());
      if (!win->IsChromeWindow()) {
        JSObject *scope;
        nsGlobalWindow *innerWin;
        if (oldWin->IsInnerWindow()) {
          scope = oldWin->GetGlobalJSObject();
        } else if ((innerWin = oldWin->GetCurrentInnerWindowInternal())) {
          scope = innerWin->GetGlobalJSObject();
        } else {
          NS_ERROR("I don't know what scope to use!");
          scope = oldWin->GetGlobalJSObject();
        }

        rv = sXPConnect->GetXOWForObject(cx, scope, JSVAL_TO_OBJECT(winVal),
                                         &winVal);
        NS_ENSURE_SUCCESS(rv, rv);
      }
      PRBool ok =
        ::JS_DefineUCProperty(cx, obj, ::JS_GetStringChars(str),
                              ::JS_GetStringLength(str),
                              winVal, JS_PropertyStub, JS_PropertyStub,
                              JSPROP_READONLY | JSPROP_ENUMERATE);

      if (!ok) {
        return NS_ERROR_FAILURE;
      }
      *objp = obj;

      return NS_OK;
    }

    if (id == sJava_id || id == sPackages_id
#ifdef OJI
        || id == sNetscape_id || id == sSun_id || id == sJavaObject_id ||
        id == sJavaClass_id || id == sJavaArray_id || id == sJavaMember_id
#endif
        ) {
      static PRBool isResolvingJavaProperties;

      if (!isResolvingJavaProperties) {
        isResolvingJavaProperties = PR_TRUE;

        // Tell the window to initialize the Java properties. The
        // window needs to do this as we need to do this only once,
        // and detecting that reliably from here is hard.

        win->InitJavaProperties(); 

        PRBool hasProp;
        PRBool ok = ::JS_HasProperty(cx, obj, ::JS_GetStringBytes(str),
                                     &hasProp);

        isResolvingJavaProperties = PR_FALSE;

        if (!ok) {
          return NS_ERROR_FAILURE;
        }

        if (hasProp) {
          *objp = obj;

          return NS_OK;
        }
      }
    } else if (id == sDialogArguments_id &&
               mData == &sClassInfoData[eDOMClassInfo_ModalContentWindow_id]) {
      nsCOMPtr<nsIArray> args;
      ((nsGlobalModalWindow *)win)->GetDialogArguments(getter_AddRefs(args));

      nsIScriptContext *script_cx = win->GetContext();
      if (script_cx) {
        JSAutoSuspendRequest asr(cx);

        // Make nsJSContext::SetProperty()'s magic argument array
        // handling happen.
        rv = script_cx->SetProperty(obj, "dialogArguments", args);
        NS_ENSURE_SUCCESS(rv, rv);

        *objp = obj;
      }

      return NS_OK;
    }
  }

  JSObject *oldobj = *objp;
  rv = nsEventReceiverSH::NewResolve(wrapper, cx, obj, id, flags, objp,
                                     _retval);

  if (NS_FAILED(rv) || *objp != oldobj) {
    // Something went wrong, or the property got resolved. Return.
    return rv;
  }

  // Make a fast expando if we're assigning to (not declaring or
  // binding a name) a new undefined property that's not already
  // defined on our prototype chain. This way we can access this
  // expando w/o ever getting back into XPConnect.
  if ((flags & JSRESOLVE_ASSIGNING) && !(flags & JSRESOLVE_WITH) &&
      win->IsInnerWindow()) {
    JSObject *realObj;
    wrapper->GetJSObject(&realObj);

    if (obj == realObj) {
      JSObject *proto = STOBJ_GET_PROTO(obj);
      if (proto) {
        jsid interned_id;
        JSObject *pobj = NULL;
        jsval val;

        if (!::JS_ValueToId(cx, id, &interned_id) ||
            !::JS_LookupPropertyWithFlagsById(cx, proto, interned_id, flags,
                                              &pobj, &val)) {
          *_retval = JS_FALSE;

          return NS_OK;
        }

        if (pobj) {
          // A property was found on the prototype chain.
          *objp = pobj;
          return NS_OK;
        }
      }

      // Define a fast expando, the key here is to use JS_PropertyStub
      // as the getter/setter, which makes us stay out of XPConnect
      // when using this property.
      //
      // We don't need to worry about property attributes here as we
      // know here we're dealing with an undefined property set, so
      // we're not declaring readonly or permanent properties.
      //
      // Since we always create the undeclared property here without given a
      // chance for the interpreter to report applicable strict mode warnings,
      // we must take care to check those warnings here.

      JSString *str = JSVAL_TO_STRING(id);
      if (!::js_CheckUndeclaredVarAssignment(cx) ||
          !::JS_DefineUCProperty(cx, obj, ::JS_GetStringChars(str),
                                 ::JS_GetStringLength(str), JSVAL_VOID,
                                 JS_PropertyStub, JS_PropertyStub,
                                 JSPROP_ENUMERATE)) {
        *_retval = JS_FALSE;

        return NS_OK;
      }

      *objp = obj;
    }
  }

  return NS_OK;
}