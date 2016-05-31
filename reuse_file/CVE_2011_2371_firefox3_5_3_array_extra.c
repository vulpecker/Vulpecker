
static JS_REQUIRES_STACK JSBool
CVE_2011_2371_firefox3_5_3_array_extra(JSContext *cx, ArrayExtraMode mode, uintN argc, jsval *vp)
{
    JSObject *obj;
    jsuint length, newlen;
    jsval *argv, *elemroot, *invokevp, *sp;
    JSBool ok, cond, hole;
    JSObject *callable, *thisp, *newarr;
    jsint start, end, step, i;
    void *mark;

    obj = JS_THIS_OBJECT(cx, vp);
    if (!obj || !js_GetLengthProperty(cx, obj, &length))
        return JS_FALSE;

    /*
     * First, get or compute our callee, so that we error out consistently
     * when passed a non-callable object.
     */
    if (argc == 0) {
        js_ReportMissingArg(cx, vp, 0);
        return JS_FALSE;
    }
    argv = vp + 2;
    callable = js_ValueToCallableObject(cx, &argv[0], JSV2F_SEARCH_STACK);
    if (!callable)
        return JS_FALSE;

    /*
     * Set our initial return condition, used for zero-length array cases
     * (and pre-size our map return to match our known length, for all cases).
     */
#ifdef __GNUC__ /* quell GCC overwarning */
    newlen = 0;
    newarr = NULL;
#endif
    start = 0, end = length, step = 1;

    switch (mode) {
      case REDUCE_RIGHT:
        start = length - 1, end = -1, step = -1;
        /* FALL THROUGH */
      case REDUCE:
        if (length == 0 && argc == 1) {
            JS_ReportErrorNumber(cx, js_GetErrorMessage, NULL,
                                 JSMSG_EMPTY_ARRAY_REDUCE);
            return JS_FALSE;
        }
        if (argc >= 2) {
            *vp = argv[1];
        } else {
            do {
                if (!GetArrayElement(cx, obj, start, &hole, vp))
                    return JS_FALSE;
                start += step;
            } while (hole && start != end);

            if (hole && start == end) {
                JS_ReportErrorNumber(cx, js_GetErrorMessage, NULL,
                                     JSMSG_EMPTY_ARRAY_REDUCE);
                return JS_FALSE;
            }
        }
        break;
      case MAP:
      case FILTER:
        newlen = (mode == MAP) ? length : 0;
        newarr = js_NewArrayObject(cx, newlen, NULL);
        if (!newarr)
            return JS_FALSE;
        *vp = OBJECT_TO_JSVAL(newarr);
        break;
      case SOME:
        *vp = JSVAL_FALSE;
        break;
      case EVERY:
        *vp = JSVAL_TRUE;
        break;
      case FOREACH:
        *vp = JSVAL_VOID;
        break;
    }

    if (length == 0)
        return JS_TRUE;

    if (argc > 1 && !REDUCE_MODE(mode)) {
        if (!js_ValueToObject(cx, argv[1], &thisp))
            return JS_FALSE;
        argv[1] = OBJECT_TO_JSVAL(thisp);
    } else {
        thisp = NULL;
    }

    /*
     * For all but REDUCE, we call with 3 args (value, index, array). REDUCE
     * requires 4 args (accum, value, index, array).
     */
    argc = 3 + REDUCE_MODE(mode);
    elemroot = js_AllocStack(cx, 1 + 2 + argc, &mark);
    if (!elemroot)
        return JS_FALSE;

    MUST_FLOW_THROUGH("out");
    ok = JS_TRUE;
    invokevp = elemroot + 1;

    for (i = start; i != end; i += step) {
        ok = JS_CHECK_OPERATION_LIMIT(cx) &&
             GetArrayElement(cx, obj, i, &hole, elemroot);
        if (!ok)
            goto out;
        if (hole)
            continue;

        /*
         * Push callable and 'this', then args. We must do this for every
         * iteration around the loop since js_Invoke uses spbase[0] for return
         * value storage, while some native functions use spbase[1] for local
         * rooting.
         */
        sp = invokevp;
        *sp++ = OBJECT_TO_JSVAL(callable);
        *sp++ = OBJECT_TO_JSVAL(thisp);
        if (REDUCE_MODE(mode))
            *sp++ = *vp;
        *sp++ = *elemroot;
        *sp++ = INT_TO_JSVAL(i);
        *sp++ = OBJECT_TO_JSVAL(obj);

        /* Do the call. */
        ok = js_Invoke(cx, argc, invokevp, 0);
        if (!ok)
            break;

        if (mode > MAP)
            cond = js_ValueToBoolean(*invokevp);
#ifdef __GNUC__ /* quell GCC overwarning */
        else
            cond = JS_FALSE;
#endif

        switch (mode) {
          case FOREACH:
            break;
          case REDUCE:
          case REDUCE_RIGHT:
            *vp = *invokevp;
            break;
          case MAP:
            ok = SetArrayElement(cx, newarr, i, *invokevp);
            if (!ok)
                goto out;
            break;
          case FILTER:
            if (!cond)
                break;
            /* The filter passed *elemroot, so push it onto our result. */
            ok = SetArrayElement(cx, newarr, newlen++, *elemroot);
            if (!ok)
                goto out;
            break;
          case SOME:
            if (cond) {
                *vp = JSVAL_TRUE;
                goto out;
            }
            break;
          case EVERY:
            if (!cond) {
                *vp = JSVAL_FALSE;
                goto out;
            }
            break;
        }
    }

  out:
    js_FreeStack(cx, mark);
    if (ok && mode == FILTER)
        ok = js_SetLengthProperty(cx, newarr, newlen);
    return ok;
}