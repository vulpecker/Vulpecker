
static JSBool
CVE_2011_0055_firefox3_5_3_JO(JSContext *cx, jsval *vp, StringifyContext *scx)
{
    JSObject *obj = JSVAL_TO_OBJECT(*vp);

    jschar c = jschar('{');
    if (!scx->callback(&c, 1, scx->data))
        return JS_FALSE;

    jsval vec[3] = {JSVAL_NULL, JSVAL_NULL, JSVAL_NULL};
    JSAutoTempValueRooter tvr(cx, 3, vec);
    jsval& key = vec[0];
    jsval& outputValue = vec[1];

    JSObject *iterObj = NULL;
    jsval *keySource = vp;
    bool usingWhitelist = false;

    // if the replacer is an array, we use the keys from it
    if (scx->replacer && JS_IsArrayObject(cx, scx->replacer)) {
        usingWhitelist = true;
        vec[2] = OBJECT_TO_JSVAL(scx->replacer);
        keySource = &vec[2];
    }

    if (!js_ValueToIterator(cx, JSITER_ENUMERATE, keySource))
        return JS_FALSE;
    iterObj = JSVAL_TO_OBJECT(*keySource);

    JSBool memberWritten = JS_FALSE;
    JSBool ok;

    do {
        outputValue = JSVAL_VOID;
        ok = js_CallIteratorNext(cx, iterObj, &key);
        if (!ok)
            break;
        if (key == JSVAL_HOLE)
            break;

        jsuint index = 0;
        if (usingWhitelist) {
            // skip non-index properties
            if (!js_IdIsIndex(key, &index))
                continue;

            jsval newKey;
            if (!OBJ_GET_PROPERTY(cx, scx->replacer, key, &newKey))
                return JS_FALSE;
            key = newKey;
        }

        JSString *ks;
        if (JSVAL_IS_STRING(key)) {
            ks = JSVAL_TO_STRING(key);
        } else {
            ks = js_ValueToString(cx, key);
            if (!ks) {
                ok = JS_FALSE;
                break;
            }
        }
        JSAutoTempValueRooter keyStringRoot(cx, ks);

        // Don't include prototype properties, since this operation is
        // supposed to be implemented as if by ES3.1 Object.keys()
        jsid id;
        jsval v = JS_FALSE;
        if (!js_ValueToStringId(cx, STRING_TO_JSVAL(ks), &id) ||
            !js_HasOwnProperty(cx, obj->map->ops->lookupProperty, obj, id, &v)) {
            ok = JS_FALSE;
            break;
        }

        if (v != JSVAL_TRUE)
            continue;

        ok = JS_GetPropertyById(cx, obj, id, &outputValue);
        if (!ok)
            break;

        if (JSVAL_IS_OBJECT(outputValue)) {
            ok = js_TryJSON(cx, &outputValue);
            if (!ok)
                break;
        }

        // call this here, so we don't write out keys if the replacer function
        // wants to elide the value.
        if (!CallReplacerFunction(cx, id, obj, scx, &outputValue))
            return JS_FALSE;

        JSType type = JS_TypeOfValue(cx, outputValue);

        // elide undefined values and functions and XML
        if (outputValue == JSVAL_VOID || type == JSTYPE_FUNCTION || type == JSTYPE_XML)
            continue;

        // output a comma unless this is the first member to write
        if (memberWritten) {
            c = jschar(',');
            ok = scx->callback(&c, 1, scx->data);
            if (!ok)
                break;
        }
        memberWritten = JS_TRUE;

        if (!WriteIndent(cx, scx, scx->depth))
            return JS_FALSE;

        // Be careful below, this string is weakly rooted
        JSString *s = js_ValueToString(cx, key);
        if (!s) {
            ok = JS_FALSE;
            break;
        }

        ok = write_string(cx, scx->callback, scx->data, JS_GetStringChars(s), JS_GetStringLength(s));
        if (!ok)
            break;

        c = jschar(':');
        ok = scx->callback(&c, 1, scx->data);
        if (!ok)
            break;

        ok = Str(cx, id, obj, scx, &outputValue, false);
        if (!ok)
            break;

    } while (ok);

    if (iterObj) {
        // Always close the iterator, but make sure not to stomp on OK
        JS_ASSERT(OBJECT_TO_JSVAL(iterObj) == *keySource);
        ok &= js_CloseIterator(cx, *keySource);
    }

    if (!ok)
        return JS_FALSE;

    if (memberWritten && !WriteIndent(cx, scx, scx->depth - 1))
        return JS_FALSE;

    c = jschar('}');

    return scx->callback(&c, 1, scx->data);
}