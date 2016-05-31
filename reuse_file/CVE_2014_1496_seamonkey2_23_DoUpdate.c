
int CVE_2014_1496_seamonkey2_23_DoUpdate()
{
  NS_tchar manifest[MAXPATHLEN];
  NS_tsnprintf(manifest, sizeof(manifest)/sizeof(manifest[0]),
               NS_T("%s/update.manifest"), gSourcePath);

  // extract the manifest
  int rv = gArchiveReader.ExtractFile("updatev2.manifest", manifest);
  if (rv) {
    rv = gArchiveReader.ExtractFile("update.manifest", manifest);
    if (rv) {
      LOG(("CVE_2014_1496_seamonkey2_23_DoUpdate: error extracting manifest file"));
      return rv;
    }
  }

  NS_tchar *rb = GetManifestContents(manifest);
  if (rb == NULL) {
    LOG(("CVE_2014_1496_seamonkey2_23_DoUpdate: error opening manifest file: " LOG_S, manifest));
    return READ_ERROR;
  }


  ActionList list;
  NS_tchar *line;
  bool isFirstAction = true;

  while((line = mstrtok(kNL, &rb)) != 0) {
    // skip comments
    if (*line == NS_T('#'))
      continue;

    NS_tchar *token = mstrtok(kWhitespace, &line);
    if (!token) {
      LOG(("CVE_2014_1496_seamonkey2_23_DoUpdate: token not found in manifest"));
      return PARSE_ERROR;
    }

    if (isFirstAction && NS_tstrcmp(token, NS_T("type")) == 0) {
      const NS_tchar *type = mstrtok(kQuote, &line);
      LOG(("UPDATE TYPE " LOG_S, type));
      if (NS_tstrcmp(type, NS_T("complete")) == 0) {
        rv = AddPreCompleteActions(&list);
        if (rv)
          return rv;
      }
      isFirstAction = false;
      continue;
    }

    isFirstAction = false;

    Action *action = NULL;
    if (NS_tstrcmp(token, NS_T("remove")) == 0) { // rm file
      action = new RemoveFile();
    }
    else if (NS_tstrcmp(token, NS_T("rmdir")) == 0) { // rmdir if  empty
      action = new RemoveDir();
    }
    else if (NS_tstrcmp(token, NS_T("rmrfdir")) == 0) { // rmdir recursive
      const NS_tchar *reldirpath = mstrtok(kQuote, &line);
      if (!reldirpath)
        return PARSE_ERROR;

      if (reldirpath[NS_tstrlen(reldirpath) - 1] != NS_T('/'))
        return PARSE_ERROR;

      rv = add_dir_entries(reldirpath, &list);
      if (rv)
        return rv;

      continue;
    }
    else if (NS_tstrcmp(token, NS_T("add")) == 0) {
      action = new AddFile();
    }
    else if (NS_tstrcmp(token, NS_T("patch")) == 0) {
      action = new PatchFile();
    }
    else if (NS_tstrcmp(token, NS_T("add-if")) == 0) { // Add if exists
      action = new AddIfFile();
    }
    else if (NS_tstrcmp(token, NS_T("patch-if")) == 0) { // Patch if exists
      action = new PatchIfFile();
    }
    else if (NS_tstrcmp(token, NS_T("add-cc")) == 0) { // no longer supported
      continue;
    }
    else {
      LOG(("CVE_2014_1496_seamonkey2_23_DoUpdate: unknown token: " LOG_S, token));
      return PARSE_ERROR;
    }

    if (!action)
      return BAD_ACTION_ERROR;

    rv = action->Parse(line);
    if (rv)
      return rv;

    list.Append(action);
  }

  rv = list.Prepare();
  if (rv)
    return rv;

  rv = list.Execute();

  list.Finish(rv);
  return rv;
}