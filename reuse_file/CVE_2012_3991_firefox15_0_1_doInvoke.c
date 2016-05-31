
static bool
CVE_2012_3991_firefox15_0_1_doInvoke(NPObject *npobj, NPIdentifier method, const NPVariant *args,
         uint32_t argCount, bool ctorCall, NPVariant *result)
{
  NPP npp = NPPStack::Peek();
  JSContext *cx = GetJSContext(npp);

  if (!cx) {
    return false;
  }

  if (!npobj || !result) {
    ThrowJSException(cx, "Null npobj, or result in CVE_2012_3991_firefox15_0_1_doInvoke!");

    return false;
  }

  // Initialize *result
  VOID_TO_NPVARIANT(*result);

  nsJSObjWrapper *npjsobj = (nsJSObjWrapper *)npobj;
  jsval fv;

  AutoCXPusher pusher(cx);
  JSAutoRequest ar(cx);
  JSAutoEnterCompartment ac;

  if (!ac.enter(cx, npjsobj->mJSObj))
    return false;

  AutoJSExceptionReporter reporter(cx);

  if (method != NPIdentifier_VOID) {
    if (!GetProperty(cx, npjsobj->mJSObj, method, &fv) ||
        ::JS_TypeOfValue(cx, fv) != JSTYPE_FUNCTION) {
      return false;
    }
  } else {
    fv = OBJECT_TO_JSVAL(npjsobj->mJSObj);
  }

  jsval jsargs_buf[8];
  jsval *jsargs = jsargs_buf;

  if (argCount > (sizeof(jsargs_buf) / sizeof(jsval))) {
    // Our stack buffer isn't large enough to hold all arguments,
    // malloc a buffer.
    jsargs = (jsval *)PR_Malloc(argCount * sizeof(jsval));
    if (!jsargs) {
      ::JS_ReportOutOfMemory(cx);

      return false;
    }
  }

  jsval v;
  JSBool ok;

  {
    JS::AutoArrayRooter tvr(cx, 0, jsargs);

    // Convert args
    for (PRUint32 i = 0; i < argCount; ++i) {
      jsargs[i] = NPVariantToJSVal(npp, cx, args + i);
      tvr.changeLength(i + 1);
    }

    if (ctorCall) {
      JSObject *newObj =
        ::JS_New(cx, npjsobj->mJSObj, argCount, jsargs);

      if (newObj) {
        v = OBJECT_TO_JSVAL(newObj);
        ok = JS_TRUE;
      } else {
        ok = JS_FALSE;
      }
    } else {
      ok = ::JS_CallFunctionValue(cx, npjsobj->mJSObj, fv, argCount, jsargs, &v);
    }

  }

  if (jsargs != jsargs_buf)
    PR_Free(jsargs);

  if (ok)
    ok = JSValToNPVariant(npp, cx, v, result);

  // return ok == JS_TRUE to quiet down compiler warning, even if
  // return ok is what we really want.
  return ok == JS_TRUE;
}