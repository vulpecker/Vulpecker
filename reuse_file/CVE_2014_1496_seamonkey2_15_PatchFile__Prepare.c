
int
CVE_2014_1496_seamonkey2_15_PatchFile::Prepare()
{
  LOG(("PREPARE PATCH " LOG_S "\n", mFile));

  // extract the patch to a temporary file
  mPatchIndex = sPatchIndex++;

  NS_tsnprintf(spath, sizeof(spath)/sizeof(spath[0]),
               NS_T("%s/%d.patch"), gSourcePath, mPatchIndex);

  NS_tremove(spath);

  FILE *fp = NS_tfopen(spath, NS_T("wb"));
  if (!fp)
    return WRITE_ERROR;

#ifdef XP_WIN
  char sourcefile[MAXPATHLEN];
  if (!WideCharToMultiByte(CP_UTF8, 0, mPatchFile, -1, sourcefile, MAXPATHLEN,
                           NULL, NULL)) {
    LOG(("error converting wchar to utf8: %d\n", GetLastError()));
    return STRING_CONVERSION_ERROR;
  }

  int rv = gArchiveReader.ExtractFileToStream(sourcefile, fp);
#else
  int rv = gArchiveReader.ExtractFileToStream(mPatchFile, fp);
#endif
  fclose(fp);
  return rv;
}