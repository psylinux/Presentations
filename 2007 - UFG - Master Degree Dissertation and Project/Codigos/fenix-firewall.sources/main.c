/*
 * fenix-firewall
 *
 * Copyright (C) 2009 DigitalSec
 * Marcos Azevedo <marcos@digitalsec.com.br>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Fenix Firewall System.
 * Module: iptables backend
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <errno.h>
#include <unistd.h>

#include <libintl.h>
#define _(x) gettext(x)

#include "backend.h"
#include "interface.h"

pid_t suidPID = -1;

int
main (int argc, char *argv[])
{
	int lsock, csock;
	struct sockaddr_un laddr, caddr;
	socklen_t len;
	gboolean activate_rules = FALSE;
	
	/* check command line parameters */
	if (argc > 1)
	{
		activate_rules = !strcmp(argv[1],"--activate");
	}
	
	/* command line paramater tells us just to do setup and exit */
	if (activate_rules)
	{
		do_clear();
		do_load_rules();
		do_rules_apply();
		exit(0);
	}
	
	/* fork frontend process */
	suidPID = fork();
	
	if (suidPID < 0)
	{
		perror(_("Unable to fork"));
		exit(errno);
	}
	
	if (!suidPID)
	{
		setuid(0);
		seteuid(0);	
		
		/* initialize socket server */
		lsock = socket(AF_LOCAL, SOCK_STREAM, 0);
		unlink(PK_SOCKET);
		bzero(&laddr,sizeof(laddr));
		laddr.sun_family = AF_LOCAL;
		strcpy(laddr.sun_path, PK_SOCKET);
		
		bind(lsock, (struct sockaddr *) &laddr, sizeof(laddr));
		listen(lsock, 1);
			
		chmod(PK_SOCKET,S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP | S_IRUSR | S_IWUSR);
		
		len = sizeof(caddr);
		
		if ((csock = accept(lsock, (struct sockaddr*)&caddr, &len)) < 0)
		{
			fprintf(stderr,"Err: accept - %s\n",strerror(errno));
			close(lsock);
			exit(1);
		}
		else
		{
			suidloop(csock);
			close(csock);
		}
	}
	else
	{
		/* we abandon all privileges */
		setresuid(getuid(),getuid(),getuid());
		setresgid(getgid(),getgid(),getgid());
		
		signal(SIGTERM, do_safe_exit);
		signal(SIGINT, do_safe_exit);
		mainloop(argc, argv);	
		kill(suidPID,SIGTERM);
	}
	
	unlink(PK_SOCKET);
	return 0;
}
