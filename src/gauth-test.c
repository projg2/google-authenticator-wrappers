/* gauth-test -- trivial helper to test gauth PAM stack
 * (c) 2018 Michał Górny
 * Licensed under 2-clause BSD license
 */

#include <stdio.h>

#include <sys/types.h>
#include <pwd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

int main()
{
	const struct pam_conv conv = {
		misc_conv,
		NULL
	};

	pam_handle_t* pam_handle;
	int ret;

	const struct passwd* pw = getpwuid(getuid());

	if (!pw)
	{
		perror("Unable to get user info from passwd");
		return 1;
	}

	ret = pam_start("gauth", pw->pw_name, &conv, &pam_handle);
	if (ret != PAM_SUCCESS)
	{
		fprintf(stderr, "Unable to start PAM conversation: %s\n",
				pam_strerror(pam_handle, ret));
		return 1;
	}

	ret = pam_authenticate(pam_handle, 0);
	if (ret != PAM_SUCCESS)
	{
		fprintf(stderr, "Authentication failed: %s\n",
				pam_strerror(pam_handle, ret));
		return 1;
	}

	ret = pam_end(pam_handle, ret);
	if (ret != PAM_SUCCESS)
	{
		fprintf(stderr, "Unable to finish PAM conversation: %s\n",
				pam_strerror(pam_handle, ret));
		return 1;
	}

	fputs("Authentication succeeded\n", stderr);
	return 0;
}
