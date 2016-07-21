#ifndef _xingyi_userspace_functions_H_
#define _xingyi_userspace_functions_H_

static inline char *n_malloc(int size) 
{
	char *retme = NULL;
	
	if (size > 0) {
		retme = malloc((size_t)(size + 1));
		if (retme != NULL)
			memset(retme, (int)'\0', (size_t)(size + 1));
	}
	if (retme == NULL)
		return (char *)'\0';
	
	return retme;
}

int daemonize()
{
	pid_t worker_pid;
	
	worker_pid = fork();
	if (worker_pid != 0) 
		exit(0);
	return 0;
}

static int _write_pid_to_file(const char *file_path)
{
	FILE *filp;
	pid_t mypid;
	int retme = 0;

	mypid = getpid();
	filp = fopen(file_path, "w");
	if (filp != NULL) {
		fprintf (filp, "%d\n", (int)mypid);	
		fclose(filp);
		retme = 1;	
	}
	else
		retme = -1;
	
	return retme;
}

static int _log_file(char *path, int port)
{	
	int retval = 0;
	FILE *fp = NULL;

	fp = fopen(path, "w");
	if (fp != NULL)	{
		fprintf (fp, "%d\n", port);	
		fclose(fp);
		retval = 1;	
	}
	else
		retval = -1;

	return retval;	
}

#endif
