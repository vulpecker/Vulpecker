int CVE_2012_1184_asterisk1_8_3_1_ast_parse_digest(const char *digest, struct ast_http_digest *d, int request, int pedantic) {
	int i;
	char *c, key[512], val[512], tmp[512];
	struct ast_str *str = ast_str_create(16);

	if (ast_strlen_zero(digest) || !d || !str) {
		ast_free(str);
		return -1;
	}

	ast_str_set(&str, 0, "%s", digest);

	c = ast_skip_blanks(ast_str_buffer(str));

	if (strncasecmp(tmp, "Digest ", strlen("Digest "))) {
		ast_log(LOG_WARNING, "Missing Digest.\n");
		ast_free(str);
		return -1;
	}
	c += strlen("Digest ");

	/* lookup for keys/value pair */
	while (*c && *(c = ast_skip_blanks(c))) {
		/* find key */
		i = 0;
		while (*c && *c != '=' && *c != ',' && !isspace(*c)) {
			key[i++] = *c++;
		}
		key[i] = '\0';
		c = ast_skip_blanks(c);
		if (*c == '=') {
			c = ast_skip_blanks(++c);
			i = 0;
			if (*c == '\"') {
				/* in quotes. Skip first and look for last */
				c++;
				while (*c && *c != '\"') {
					if (*c == '\\' && c[1] != '\0') { /* unescape chars */
						c++;
					}
					val[i++] = *c++;
				}
			} else {
				/* token */
				while (*c && *c != ',' && !isspace(*c)) {
					val[i++] = *c++;
				}
			}
			val[i] = '\0';
		}

		while (*c && *c != ',') {
			c++;
		}
		if (*c) {
			c++;
		}

		if (!strcasecmp(key, "username")) {
			ast_string_field_set(d, username, val);
		} else if (!strcasecmp(key, "realm")) {
			ast_string_field_set(d, realm, val);
		} else if (!strcasecmp(key, "nonce")) {
			ast_string_field_set(d, nonce, val);
		} else if (!strcasecmp(key, "uri")) {
			ast_string_field_set(d, uri, val);
		} else if (!strcasecmp(key, "domain")) {
			ast_string_field_set(d, domain, val);
		} else if (!strcasecmp(key, "response")) {
			ast_string_field_set(d, response, val);
		} else if (!strcasecmp(key, "algorithm")) {
			if (strcasecmp(val, "MD5")) {
				ast_log(LOG_WARNING, "Digest algorithm: \"%s\" not supported.\n", val);
				return -1;
			}
		} else if (!strcasecmp(key, "cnonce")) {
			ast_string_field_set(d, cnonce, val);
		} else if (!strcasecmp(key, "opaque")) {
			ast_string_field_set(d, opaque, val);
		} else if (!strcasecmp(key, "qop") && !strcasecmp(val, "auth")) {
			d->qop = 1;
		} else if (!strcasecmp(key, "nc")) {
			unsigned long u;
			if (sscanf(val, "%30lx", &u) != 1) {
				ast_log(LOG_WARNING, "Incorrect Digest nc value: \"%s\".\n", val);
				return -1;
			}
			ast_string_field_set(d, nc, val);
		}
	}
	ast_free(str);

	/* Digest checkout */
	if (ast_strlen_zero(d->realm) || ast_strlen_zero(d->nonce)) {
		/* "realm" and "nonce" MUST be always exist */
		return -1;
	}

	if (!request) {
		/* Additional check for Digest response */
		if (ast_strlen_zero(d->username) || ast_strlen_zero(d->uri) || ast_strlen_zero(d->response)) {
			return -1;
		}

		if (pedantic && d->qop && (ast_strlen_zero(d->cnonce) || ast_strlen_zero(d->nc))) {
			return -1;
		}
	}

	return 0;
}