static JSBool
CVE_2013_0756_firefox15_0_1_obj_toSource(JSContext *cx, unsigned argc, Value *vp)
{
    bool comma = false;
    const jschar *vchars;
    size_t vlength;
    Value *val;
    JSString *gsop[2];

    JS_CHECK_RECURSION(cx, return JS_FALSE);

    Value localroot[4];
    PodArrayZero(localroot);
    AutoArrayRooter tvr(cx, ArrayLength(localroot), localroot);

    /* If outermost, we need parentheses to be an expression, not a block. */
    bool outermost = (cx->sharpObjectMap.depth == 0);

    RootedObject obj(cx, ToObject(cx, &vp[1]));
    if (!obj)
        return false;

    JSIdArray *ida;
    bool alreadySeen = false;
    bool isSharp = false;
    if (!js_EnterSharpObject(cx, obj, &ida, &alreadySeen, &isSharp))
        return false;

    if (!ida) {
        /*
         * We've already seen obj, so don't serialize it again (particularly as
         * we might recur in the process): just serialize an empty object.
         */
        JS_ASSERT(alreadySeen);
        JSString *str = js_NewStringCopyZ(cx, "{}");
        if (!str)
            return false;
        vp->setString(str);
        return true;
    }

    JS_ASSERT(!isSharp);
    if (alreadySeen) {
        JSSharpTable::Ptr p = cx->sharpObjectMap.table.lookup(obj);
        JS_ASSERT(p);
        JS_ASSERT(!p->value.isSharp);
        p->value.isSharp = true;
    }

    /* Automatically call js_LeaveSharpObject when we leave this frame. */
    class AutoLeaveSharpObject {
        JSContext *cx;
        JSIdArray *ida;
      public:
        AutoLeaveSharpObject(JSContext *cx, JSIdArray *ida) : cx(cx), ida(ida) {}
        ~AutoLeaveSharpObject() {
            js_LeaveSharpObject(cx, &ida);
        }
    } autoLeaveSharpObject(cx, ida);

    StringBuffer buf(cx);
    if (outermost && !buf.append('('))
        return false;
    if (!buf.append('{'))
        return false;

    /*
     * We have four local roots for cooked and raw value GC safety.  Hoist the
     * "localroot + 2" out of the loop using the val local, which refers to
     * the raw (unconverted, "uncooked") values.
     */
    val = localroot + 2;

    RootedId id(cx);
    for (int i = 0; i < ida->length; i++) {
        /* Get strings for id and value and GC-root them via vp. */
        id = ida->vector[i];
        JSLinearString *idstr;

        JSObject *obj2;
        JSProperty *prop;
        if (!obj->lookupGeneric(cx, id, &obj2, &prop))
            return false;

        /*
         * Convert id to a value and then to a string.  Decide early whether we
         * prefer get/set or old getter/setter syntax.
         */
        JSString *s = ToString(cx, IdToValue(id));
        if (!s || !(idstr = s->ensureLinear(cx)))
            return false;

        int valcnt = 0;
        if (prop) {
            bool doGet = true;
            if (obj2->isNative()) {
                const Shape *shape = (Shape *) prop;
                unsigned attrs = shape->attributes();
                if (attrs & JSPROP_GETTER) {
                    doGet = false;
                    val[valcnt] = shape->getterValue();
                    gsop[valcnt] = cx->runtime->atomState.getAtom;
                    valcnt++;
                }
                if (attrs & JSPROP_SETTER) {
                    doGet = false;
                    val[valcnt] = shape->setterValue();
                    gsop[valcnt] = cx->runtime->atomState.setAtom;
                    valcnt++;
                }
            }
            if (doGet) {
                valcnt = 1;
                gsop[0] = NULL;
                if (!obj->getGeneric(cx, id, &val[0]))
                    return false;
            }
        }

        /*
         * If id is a string that's not an identifier, or if it's a negative
         * integer, then it must be quoted.
         */
        if (JSID_IS_ATOM(id)
            ? !IsIdentifier(idstr)
            : (!JSID_IS_INT(id) || JSID_TO_INT(id) < 0)) {
            s = js_QuoteString(cx, idstr, jschar('\''));
            if (!s || !(idstr = s->ensureLinear(cx)))
                return false;
        }

        for (int j = 0; j < valcnt; j++) {
            /*
             * Censor an accessor descriptor getter or setter part if it's
             * undefined.
             */
            if (gsop[j] && val[j].isUndefined())
                continue;

            /* Convert val[j] to its canonical source form. */
            JSString *valstr = js_ValueToSource(cx, val[j]);
            if (!valstr)
                return false;
            localroot[j].setString(valstr);             /* local root */
            vchars = valstr->getChars(cx);
            if (!vchars)
                return false;
            vlength = valstr->length();

            /*
             * Remove '(function ' from the beginning of valstr and ')' from the
             * end so that we can put "get" in front of the function definition.
             */
            if (gsop[j] && IsFunctionObject(val[j])) {
                const jschar *start = vchars;
                const jschar *end = vchars + vlength;

                uint8_t parenChomp = 0;
                if (vchars[0] == '(') {
                    vchars++;
                    parenChomp = 1;
                }

                /* Try to jump "function" keyword. */
                if (vchars)
                    vchars = js_strchr_limit(vchars, ' ', end);

                /*
                 * Jump over the function's name: it can't be encoded as part
                 * of an ECMA getter or setter.
                 */
                if (vchars)
                    vchars = js_strchr_limit(vchars, '(', end);

                if (vchars) {
                    if (*vchars == ' ')
                        vchars++;
                    vlength = end - vchars - parenChomp;
                } else {
                    gsop[j] = NULL;
                    vchars = start;
                }
            }

            if (comma && !buf.append(", "))
                return false;
            comma = true;

            if (gsop[j])
                if (!buf.append(gsop[j]) || !buf.append(' '))
                    return false;

            if (!buf.append(idstr))
                return false;
            if (!buf.append(gsop[j] ? ' ' : ':'))
                return false;

            if (!buf.append(vchars, vlength))
                return false;
        }
    }

    if (!buf.append('}'))
        return false;
    if (outermost && !buf.append(')'))
        return false;

    JSString *str = buf.finishString();
    if (!str)
        return false;
    vp->setString(str);
    return true;
}