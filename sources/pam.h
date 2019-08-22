#include <security/pam_appl.h>



#define STATUS_OK				(0)
#define STATUS_ERROR			(-1)
#define STATUS_EOF				(-2)
#define STATUS_FOUND			(1)
#define STATUS_WAITING			(2)

/*
 * PAM conversation function
 */

static int
pam_passwd_conv_proc(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr)
{
	const char *passwd;
	struct pam_response *reply;
	int			i;

	passwd = (char *) appdata_ptr;

	*resp = NULL;				/* in case of error exit */

	if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
		return PAM_CONV_ERR;

	/*
	 * Explicitly not using palloc here - PAM will free this memory in
	 * pam_end()
	 */
	if ((reply = calloc(num_msg, sizeof(struct pam_response))) == NULL)
	{
		/*ereport(LOG,
		        (errcode(ERRCODE_OUT_OF_MEMORY),
				        errmsg("out of memory")));*/
		return PAM_CONV_ERR;
	}

	for (i = 0; i < num_msg; i++)
	{
		switch (msg[i]->msg_style)
		{
			case PAM_PROMPT_ECHO_OFF:
				if (strlen(passwd) == 0)
				{
					/*
					 * Password wasn't passed to PAM the first time around -
					 * let's go ask the client to send a password, which we
					 * then stuff into PAM.
					 */
					//sendAuthRequest(pam_port_cludge, AUTH_REQ_PASSWORD, NULL, 0);
					//passwd = recv_password_packet(pam_port_cludge);
					if (passwd == NULL)
					{
						/*
						 * Client didn't want to send password.  We
						 * intentionally do not log anything about this.
						 */

					}
					goto fail;
				}
				if ((reply[i].resp = strdup(passwd)) == NULL)
					goto fail;
				reply[i].resp_retcode = PAM_SUCCESS;
				break;
			case PAM_ERROR_MSG:
				/*ereport(LOG,
				        (errmsg("error from underlying PAM layer: %s",
				                msg[i]->msg)));*/
				/* FALL THROUGH */
			case PAM_TEXT_INFO:
				/* we don't bother to log TEXT_INFO messages */
				if ((reply[i].resp = strdup("")) == NULL)
					goto fail;
				reply[i].resp_retcode = PAM_SUCCESS;
				break;
			default:
				/*elog(LOG, "unsupported PAM conversation %d/\"%s\"",
				     msg[i]->msg_style,
				     msg[i]->msg ? msg[i]->msg : "(none)");*/
				goto fail;
		}
	}

	*resp = reply;
	return PAM_SUCCESS;

	fail:
	/* free up whatever we allocated */
	for (i = 0; i < num_msg; i++)
	{
		if (reply[i].resp != NULL)
			free(reply[i].resp);
	}
	free(reply);

	return PAM_CONV_ERR;
}

/*
 * Check authentication against PAM.
 */
static int
CheckPAMAuth(const char *hostinfo, const char *pamservice, const char *user, const char *password)
{
	int			retval;
	pam_handle_t *pamh = NULL;
	/*char		hostinfo[NI_MAXHOST];

	retval = pg_getnameinfo_all(&port->raddr.addr, port->raddr.salen,
	                            hostinfo, sizeof(hostinfo), NULL, 0,
	                            port->hba->pam_use_hostname ? 0 : NI_NUMERICHOST | NI_NUMERICSERV);
	if (retval != 0)
	{
		//ereport(WARNING,
		//        (errmsg_internal("pg_getnameinfo_all() failed: %s",
		//                         gai_strerror(retval))));
		return STATUS_ERROR;
	}

	*//*
	 * We can't entirely rely on PAM to pass through appdata --- it appears
	 * not to work on at least Solaris 2.6.  So use these ugly static
	 * variables instead.
	 *//*
	char *pam_passwd = password;
	char *pam_port_cludge = port;*/

	/*
	 * Set the application data portion of the conversation struct.  This is
	 * later used inside the PAM conversation to pass the password to the
	 * authentication module.
	 */
	static struct pam_conv pam_passw_conv = {
			&pam_passwd_conv_proc,
			NULL
	};

	/*pam_passw_conv.appdata_ptr = (char *) password; *//* from password above,
													 * not allocated */

	retval = pam_start(pamservice, "odyssey@",
		                   &pam_passw_conv, &pamh);

	if (retval != PAM_SUCCESS)
	{
		//ereport(LOG,
		//        (errmsg("could not create PAM authenticator: %s",
		//                pam_strerror(pamh, retval))));
		return STATUS_ERROR;
	}

	retval = pam_set_item(pamh, PAM_USER, user);

	if (retval != PAM_SUCCESS)
	{
		//ereport(LOG,
		//        (errmsg("pam_set_item(PAM_USER) failed: %s",
		//                pam_strerror(pamh, retval))));
		return STATUS_ERROR;
	}

	retval = pam_set_item(pamh, PAM_RHOST, hostinfo);

	if (retval != PAM_SUCCESS)
	{
		//ereport(LOG,
		//        (errmsg("pam_set_item(PAM_RHOST) failed: %s",
		//                pam_strerror(pamh, retval))));
		return STATUS_ERROR;
	}

	retval = pam_set_item(pamh, PAM_CONV, &pam_passw_conv);

	if (retval != PAM_SUCCESS)
	{
		//ereport(LOG,
		//        (errmsg("pam_set_item(PAM_CONV) failed: %s",
		//                pam_strerror(pamh, retval))));
		return STATUS_ERROR;
	}

	retval = pam_authenticate(pamh, 0);

	if (retval != PAM_SUCCESS)
	{
		//ereport(LOG,
		//        (errmsg("pam_authenticate failed: %s",
		//                pam_strerror(pamh, retval))));
		return STATUS_ERROR;
	}

	retval = pam_acct_mgmt(pamh, 0);

	if (retval != PAM_SUCCESS)
	{
		//ereport(LOG,
		//        (errmsg("pam_acct_mgmt failed: %s",
		//                pam_strerror(pamh, retval))));
		return STATUS_ERROR;
	}

	retval = pam_end(pamh, retval);

	if (retval != PAM_SUCCESS)
	{
		//ereport(LOG,
		//        (errmsg("could not release PAM authenticator: %s",
		//                pam_strerror(pamh, retval))));
	}

	return (retval == PAM_SUCCESS ? STATUS_OK : STATUS_ERROR);
}