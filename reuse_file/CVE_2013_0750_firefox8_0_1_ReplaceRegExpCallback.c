
static bool
CVE_2013_0750_firefox8_0_1_ReplaceRegExpCallback(JSContext *cx, RegExpStatics *res, size_t count, void *p)
{
    ReplaceData &rdata = *static_cast<ReplaceData *>(p);

    rdata.calledBack = true;
    JSLinearString &str = rdata.str->asLinear();  /* flattened for regexp */
    size_t leftoff = rdata.leftIndex;
    const jschar *left = str.chars() + leftoff;
    size_t leftlen = res->matchStart() - leftoff;
    rdata.leftIndex = res->matchLimit();

    size_t replen = 0;  /* silence 'unused' warning */
    if (!FindReplaceLength(cx, res, rdata, &replen))
        return false;

    size_t growth = leftlen + replen;
    if (!rdata.sb.reserve(rdata.sb.length() + growth))
        return false;
    rdata.sb.infallibleAppend(left, leftlen); /* skipped-over portion of the search value */
    DoReplace(cx, res, rdata);
    return true;
}