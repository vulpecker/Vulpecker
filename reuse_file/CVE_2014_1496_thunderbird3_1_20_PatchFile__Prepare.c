
int
CVE_2014_1496_thunderbird3_1_20_PatchFile::Prepare()
{
  LOG(("PREPARE PATCH %s\n", mFile));

  // extract the patch to a temporary file
  mPatchIndex = sPatchIndex++;

  NS_tsnprintf(spath, sizeof(spath)/sizeof(spath[0]),
               NS_T("%s/%d.patch"), gSourcePath, mPatchIndex);

  NS_tremove(spath);

  FILE *fp = NS_tfopen(spath, NS_T("wb"));
  if (!fp)
    return WRITE_ERROR;

  int rv = gArchiveReader.ExtractFileToStream(mPatchFile, fp);
  fclose(fp);
  return rv;
}