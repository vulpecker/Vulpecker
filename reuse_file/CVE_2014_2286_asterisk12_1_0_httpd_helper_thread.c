
static void *CVE_2014_2286_asterisk12_1_0_httpd_helper_thread(void *data)
{
	char buf[4096];
	char header_line[4096];
	struct ast_tcptls_session_instance *ser = data;
	struct ast_variable *headers = NULL;
	struct ast_variable *tail = headers;
	char *uri, *method;
	enum ast_http_method http_method = AST_HTTP_UNKNOWN;
	const char *transfer_encoding;

	if (ast_atomic_fetchadd_int(&session_count, +1) >= session_limit) {
		goto done;
	}

	if (!fgets(buf, sizeof(buf), ser->f)) {
		goto done;
	}

	/* Get method */
	method = ast_skip_blanks(buf);
	uri = ast_skip_nonblanks(method);
	if (*uri) {
		*uri++ = '\0';
	}

	if (!strcasecmp(method,"GET")) {
		http_method = AST_HTTP_GET;
	} else if (!strcasecmp(method,"POST")) {
		http_method = AST_HTTP_POST;
	} else if (!strcasecmp(method,"HEAD")) {
		http_method = AST_HTTP_HEAD;
	} else if (!strcasecmp(method,"PUT")) {
		http_method = AST_HTTP_PUT;
	} else if (!strcasecmp(method,"DELETE")) {
		http_method = AST_HTTP_DELETE;
	} else if (!strcasecmp(method,"OPTIONS")) {
		http_method = AST_HTTP_OPTIONS;
	}

	uri = ast_skip_blanks(uri);	/* Skip white space */

	if (*uri) {			/* terminate at the first blank */
		char *c = ast_skip_nonblanks(uri);

		if (*c) {
			*c = '\0';
		}
	}

	/* process "Request Headers" lines */
	while (fgets(header_line, sizeof(header_line), ser->f)) {
		char *name, *value;

		/* Trim trailing characters */
		ast_trim_blanks(header_line);
		if (ast_strlen_zero(header_line)) {
			break;
		}

		value = header_line;
		name = strsep(&value, ":");
		if (!value) {
			continue;
		}

		value = ast_skip_blanks(value);
		if (ast_strlen_zero(value) || ast_strlen_zero(name)) {
			continue;
		}

		ast_trim_blanks(name);

		if (!headers) {
			headers = ast_variable_new(name, value, __FILE__);
			tail = headers;
		} else {
			tail->next = ast_variable_new(name, value, __FILE__);
			tail = tail->next;
		}
	}

	transfer_encoding = get_transfer_encoding(headers);
	/* Transfer encoding defaults to identity */
	if (!transfer_encoding) {
		transfer_encoding = "identity";
	}

	/*
	 * RFC 2616, section 3.6, we should respond with a 501 for any transfer-
	 * codings we don't understand.
	 */
	if (strcasecmp(transfer_encoding, "identity") != 0 &&
		strcasecmp(transfer_encoding, "chunked") != 0) {
		/* Transfer encodings not supported */
		ast_http_error(ser, 501, "Unimplemented", "Unsupported Transfer-Encoding.");
		goto done;
	}

	if (!*uri) {
		ast_http_error(ser, 400, "Bad Request", "Invalid Request");
		goto done;
	}

	handle_uri(ser, uri, http_method, headers);

done:
	ast_atomic_fetchadd_int(&session_count, -1);

	/* clean up all the header information */
	if (headers) {
		ast_variables_destroy(headers);
	}

	if (ser->f) {
		fclose(ser->f);
	}
	ao2_ref(ser, -1);
	ser = NULL;
	return NULL;
}