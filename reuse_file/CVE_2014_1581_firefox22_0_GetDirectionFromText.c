static Directionality
CVE_2014_1581_firefox22_0_GetDirectionFromText(const PRUnichar* aText, const uint32_t aLength,
                     uint32_t* aFirstStrong = nullptr)
{
  const PRUnichar* start = aText;
  const PRUnichar* end = aText + aLength;

  while (start < end) {
    uint32_t current = start - aText;
    uint32_t ch = *start++;

    if (NS_IS_HIGH_SURROGATE(ch) &&
        start < end &&
        NS_IS_LOW_SURROGATE(*start)) {
      ch = SURROGATE_TO_UCS4(ch, *start++);
    }

    Directionality dir = GetDirectionFromChar(ch);
    if (dir != eDir_NotSet) {
      if (aFirstStrong) {
        *aFirstStrong = current;
      }
      return dir;
    }
  }

  if (aFirstStrong) {
    *aFirstStrong = UINT32_MAX;
  }
  return eDir_NotSet;
}