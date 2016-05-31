
void
CVE_2013_1722_seamonkey2_10_1_nsAnimationManager::BuildAnimations(nsStyleContext* aStyleContext,
                                    InfallibleTArray<ElementAnimation>& aAnimations)
{
  NS_ABORT_IF_FALSE(aAnimations.IsEmpty(), "expect empty array");

  ResolvedStyleCache resolvedStyles;

  const nsStyleDisplay *disp = aStyleContext->GetStyleDisplay();
  TimeStamp now = mPresContext->RefreshDriver()->MostRecentRefresh();
  for (PRUint32 animIdx = 0, animEnd = disp->mAnimations.Length();
       animIdx != animEnd; ++animIdx) {
    const nsAnimation& aSrc = disp->mAnimations[animIdx];
    ElementAnimation& aDest = *aAnimations.AppendElement();

    aDest.mName = aSrc.GetName();
    aDest.mIterationCount = aSrc.GetIterationCount();
    aDest.mDirection = aSrc.GetDirection();
    aDest.mFillMode = aSrc.GetFillMode();
    aDest.mPlayState = aSrc.GetPlayState();

    aDest.mStartTime = now + TimeDuration::FromMilliseconds(aSrc.GetDelay());
    if (aDest.IsPaused()) {
      aDest.mPauseStart = now;
    } else {
      aDest.mPauseStart = TimeStamp();
    }

    aDest.mIterationDuration = TimeDuration::FromMilliseconds(aSrc.GetDuration());

    nsCSSKeyframesRule *rule = KeyframesRuleFor(aDest.mName);
    if (!rule) {
      // no segments
      continue;
    }

    // Build the set of unique keyframes in the @keyframes rule.  Per
    // css3-animations, later keyframes with the same key replace
    // earlier ones (no cascading).
    nsDataHashtable<PercentageHashKey, nsCSSKeyframeRule*> keyframes;
    keyframes.Init(16); // FIXME: make infallible!
    for (PRUint32 ruleIdx = 0, ruleEnd = rule->StyleRuleCount();
         ruleIdx != ruleEnd; ++ruleIdx) {
      css::Rule* cssRule = rule->GetStyleRuleAt(ruleIdx);
      NS_ABORT_IF_FALSE(cssRule, "must have rule");
      NS_ABORT_IF_FALSE(cssRule->GetType() == css::Rule::KEYFRAME_RULE,
                        "must be keyframe rule");
      nsCSSKeyframeRule *kfRule = static_cast<nsCSSKeyframeRule*>(cssRule);

      const nsTArray<float> &keys = kfRule->GetKeys();
      for (PRUint32 keyIdx = 0, keyEnd = keys.Length();
           keyIdx != keyEnd; ++keyIdx) {
        float key = keys[keyIdx];
        // FIXME (spec):  The spec doesn't say what to do with
        // out-of-range keyframes.  We'll ignore them.
        // (And PercentageHashKey currently assumes we either ignore or
        // clamp them.)
        if (0.0f <= key && key <= 1.0f) {
          keyframes.Put(key, kfRule);
        }
      }
    }

    KeyframeDataArray sortedKeyframes;
    keyframes.EnumerateRead(AppendKeyframeData, &sortedKeyframes);
    sortedKeyframes.Sort(KeyframeDataComparator());

    if (sortedKeyframes.Length() == 0) {
      // no segments
      continue;
    }

    // Record the properties that are present in any keyframe rules we
    // are using.
    nsCSSPropertySet properties;

    for (PRUint32 kfIdx = 0, kfEnd = sortedKeyframes.Length();
         kfIdx != kfEnd; ++kfIdx) {
      css::Declaration *decl = sortedKeyframes[kfIdx].mRule->Declaration();
      for (PRUint32 propIdx = 0, propEnd = decl->Count();
           propIdx != propEnd; ++propIdx) {
        properties.AddProperty(decl->OrderValueAt(propIdx));
      }
    }

    for (nsCSSProperty prop = nsCSSProperty(0);
         prop < eCSSProperty_COUNT_no_shorthands;
         prop = nsCSSProperty(prop + 1)) {
      if (!properties.HasProperty(prop) ||
          nsCSSProps::kAnimTypeTable[prop] == eStyleAnimType_None) {
        continue;
      }

      AnimationProperty &propData = *aDest.mProperties.AppendElement();
      propData.mProperty = prop;

      KeyframeData *fromKeyframe = nsnull;
      nsRefPtr<nsStyleContext> fromContext;
      bool interpolated = true;
      for (PRUint32 kfIdx = 0, kfEnd = sortedKeyframes.Length();
           kfIdx != kfEnd; ++kfIdx) {
        KeyframeData &toKeyframe = sortedKeyframes[kfIdx];
        if (!toKeyframe.mRule->Declaration()->HasProperty(prop)) {
          continue;
        }

        nsRefPtr<nsStyleContext> toContext =
          resolvedStyles.Get(mPresContext, aStyleContext, toKeyframe.mRule);

        if (fromKeyframe) {
          interpolated = interpolated &&
            BuildSegment(propData.mSegments, prop, aSrc,
                         fromKeyframe->mKey, fromContext,
                         fromKeyframe->mRule->Declaration(),
                         toKeyframe.mKey, toContext);
        } else {
          if (toKeyframe.mKey != 0.0f) {
            // There's no data for this property at 0%, so use the
            // cascaded value above us.
            interpolated = interpolated &&
              BuildSegment(propData.mSegments, prop, aSrc,
                           0.0f, aStyleContext, nsnull,
                           toKeyframe.mKey, toContext);
          }
        }

        fromContext = toContext;
        fromKeyframe = &toKeyframe;
      }

      if (fromKeyframe->mKey != 1.0f) {
        // There's no data for this property at 100%, so use the
        // cascaded value above us.
        interpolated = interpolated &&
          BuildSegment(propData.mSegments, prop, aSrc,
                       fromKeyframe->mKey, fromContext,
                       fromKeyframe->mRule->Declaration(),
                       1.0f, aStyleContext);
      }

      // If we failed to build any segments due to inability to
      // interpolate, remove the property from the animation.  (It's not
      // clear if this is the right thing to do -- we could run some of
      // the segments, but it's really not clear whether we should skip
      // values (which?) or skip segments, so best to skip the whole
      // thing for now.)
      if (!interpolated) {
        aDest.mProperties.RemoveElementAt(aDest.mProperties.Length() - 1);
      }
    }
  }
}