/* gauthctl -- manage secure gauth configs
 * (c) 2018 Michał Górny
 * Licensed under 2-clause BSD license
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

/* constant used for assert(not_reached) */
static const bool not_reached = false;

/* program long options */
const struct option long_opts[] = {
	{"enable", required_argument, NULL, 'e'},
	{"disable", no_argument, NULL, 'd'},

	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{NULL},
};

/* enum to keep selected command */
enum command
{
	CMD_NULL,
	CMD_ENABLE,
	CMD_DISABLE,
	CMD_NEXT
};

/**
 * print usage or full help message
 * prog_name: program name to print (from argv[0])
 * help: true for full help message, false for short usage
 * returns exit status for program (0 for help, 1 otherwise)
 */
int usage(const char* prog_name, bool help)
{
	FILE* const out = help ? stdout : stderr;

	fprintf(out, "Usage: %s --enable <config-path>\n", prog_name);
	if (help)
		fputs("            Enable gauth using specified config\n", out);
	fprintf(out, "       %s --disable\n", prog_name);
	if (help)
		fputs("            Disable gauth for the user\n", out);
	return help ? 0 : 1;
}

/**
 * get the username for spawning user
 * returns pointer to const username string
 */
const char* get_user()
{
	const struct passwd* pw = getpwuid(getuid());

	if (!pw)
		return NULL;
	return pw->pw_name;
}

/**
 * authenticate user via PAM
 * username: the username for the current user
 * returns true on success, false otherwise
 */
bool authenticate(const char* username)
{
	const struct pam_conv conv = {
		misc_conv,
		NULL
	};

	pam_handle_t* pam_handle;
	int ret;

	ret = pam_start("gauthctl", username, &conv, &pam_handle);
	if (ret != PAM_SUCCESS)
	{
		fprintf(stderr, "Unable to start PAM conversation: %s\n",
				pam_strerror(pam_handle, ret));
		return false;
	}

	ret = pam_authenticate(pam_handle, 0);
	if (ret != PAM_SUCCESS)
	{
		fprintf(stderr, "Authentication failed: %s\n",
				pam_strerror(pam_handle, ret));
		return false;
	}

	ret = pam_acct_mgmt(pam_handle, 0);
	if (ret != PAM_SUCCESS)
	{
		fprintf(stderr, "Account unavailable: %s\n",
				pam_strerror(pam_handle, ret));
		return false;
	}

	ret = pam_end(pam_handle, ret);
	if (ret != PAM_SUCCESS)
	{
		fprintf(stderr, "Unable to finish PAM conversation: %s\n",
				pam_strerror(pam_handle, ret));
		return false;
	}
	
	return true;
}

/**
 * allocate a buffer and write the path to the state file to it
 * username: user to write the path for
 * returns an allocated buffer with the path, or NULL on alloc failure
 */
char* get_state_path(const char* username)
{
	const size_t buf_size
		= (sizeof GAUTH_STATEDIR) + strlen(username) + 1;
	char* buf = malloc(buf_size);

	if (buf)
		sprintf(buf, "%s/%s", GAUTH_STATEDIR, username);
	return buf;
}

/**
 * enable gauth for current user
 * state_path: path to the state file
 * path: path to the new config file
 * returns true on success, false on error
 */
bool enable(const char* state_path, const char* path)
{
	char* tmp_buf;
	struct stat st;
	int in_fd;
	int out_fd;
	int ret;

	tmp_buf = malloc(strlen(state_path) + 4);
	if (!tmp_buf)
	{
		perror("Memory allocation failed");
		return false;
	}
	sprintf(tmp_buf, "%s.new", state_path);

	/* note: we need to be extra careful to prevent symlink attacks */
	in_fd = open(path, O_RDONLY|O_NOFOLLOW);
	if (in_fd == -1)
	{
		perror("Unable to open new config file");
		free(tmp_buf);
		return false;
	}

	/* verify that the file was secure */
	if (fstat(in_fd, &st) != 0)
	{
		perror("Unable to stat input file");
		close(in_fd);
		free(tmp_buf);
		return false;
	}

	if (st.st_uid != getuid())
	{
		fputs("Input file is not owned by calling user\n", stderr);
		close(in_fd);
		free(tmp_buf);
		return false;
	}
	if ((st.st_mode & 077) != 0)
	{
		fputs("Input file has insecure permissions (readable to others)\n", stderr);
		close(in_fd);
		free(tmp_buf);
		return false;
	}

	/* write into a temporary file */
	ret = unlink(tmp_buf);
	if (ret != 0 && errno != ENOENT)
	{
		perror("Unable to pre-unlink temporary file");
		close(in_fd);
		free(tmp_buf);
		return false;
	}

	out_fd = open(tmp_buf, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (out_fd == -1)
	{
		perror("Unable to open temporary file for writing");
		close(in_fd);
		free(tmp_buf);
		return false;
	}

	while (true)
	{
		char buf[4096];
		ssize_t rd;
		ssize_t wr;

		rd = read(in_fd, buf, sizeof buf);
		if (rd == 0)
			break;
		else if (rd == -1)
		{
			perror("Reading config file failed");
			close(out_fd);
			close(in_fd);
			free(tmp_buf);
			return false;
		}

		wr = write(out_fd, buf, rd);
		if (wr == -1)
		{
			perror("Writing temporary file failed");
			close(out_fd);
			close(in_fd);
			free(tmp_buf);
			return false;
		}
	}

	close(out_fd);
	close(in_fd);

	/* now we can move the file! */
	ret = rename(tmp_buf, state_path);
	if (ret != 0)
	{
		perror("Replacing state file failed");
		free(tmp_buf);
		return false;
	}

	free(tmp_buf);
	fputs("GAuth set up successfully\n", stderr);
	return true;
}

/**
 * disable gauth for the current user
 * state_path: path to the state file
 * returns true on success (or if not enabled), false on error
 */
bool disable(const char* state_path)
{
	int ret = unlink(state_path);
	if (ret == 0 || errno == ENOENT)
	{
		fputs("GAuth disabled successfully\n", stderr);
		return true;
	}

	perror("Unable to remove state file");
	return false;
}

int main(int argc, char* argv[])
{
	char opt;
	enum command cmd = CMD_NULL;
	const char* path;
	const char* username;
	char* state_path;
	bool ret;

	while ((opt = getopt_long(argc, argv, "e:dhV", long_opts, NULL)) != -1)
	{
		switch (opt)
		{
			case 'e':
				cmd = CMD_ENABLE;
				path = optarg;
				break;
			case 'd':
				cmd = CMD_DISABLE;
				break;
			case 'h':
				return usage(argv[0], true);
			case 'V':
				printf("gauthctl " VERSION "\n");
				return 0;
			default:
				return usage(argv[0], false);
		}
	}

	if (cmd == CMD_NULL || optind != argc)
		return usage(argv[0], false);

	umask(077);

	username = get_user();
	if (!username)
	{
		perror("Unable to get username");
		return 1;
	}

	state_path = get_state_path(username);
	if (!state_path)
	{
		perror("Memory allocation failed");
		return 1;
	}

	if (!authenticate(username))
		return 1;

	assert(cmd > CMD_NULL && cmd < CMD_NEXT);
	switch (cmd)
	{
		case CMD_ENABLE:
			ret = enable(state_path, path);
			break;
		case CMD_DISABLE:
			ret = disable(state_path);
			break;
		case CMD_NULL:
		case CMD_NEXT:
			assert(not_reached);
	}

	free(state_path);

	return ret ? 0 : 1;
}
