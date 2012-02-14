/*
*            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
*                    Version 2, December 2004
*
* Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
*
* Everyone is permitted to copy and distribute verbatim or modified
* copies of this license document, and changing it is allowed as long
* as the name is changed.
*
*            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
*   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
*
*  0. You just DO WHAT THE FUCK YOU WANT TO.
*/

#include "includes.h"

#define LDAP_HOST "ldap.utopia.net"
#define LDAP_ROOT_DN "cn=Administrator, dc=utopia, dc=net"
#define LDAP_ROOT_PW "supinfo"
// Les mots de passe en clair c'est la vie

#define TARGET_USER 0
#define TARGET_COMPUTER 1
#define TARGET_USER_ARG "user"
#define TARGET_COMPUTER_ARG "computer"

#define BASE_GPO_DIRECTORY "/mnt/gpo/"
#define BASE_GPO_EXEC "/bin/sh -c '%s'"

void die_help()
{
	printf("Simple LDAP GPO Manager\n");
	printf("By Arnaud Barisain Monrose\n");
	printf("---------------------------\n");
	printf("usage : slgm [-v] <type> <name>\n");
	printf("	-v : verbose, prints log to stdrr. Still logs to syslog\n");
	printf("	type : computer/user - GPO type to apply\n");
	printf("	name : if computer type : hostname, otherwise username\n");
	exit(EXIT_SUCCESS);
}

int main( int argc, char *argv[] ) 
{
	if(argc < 3)
	{
		die_help();
	}
	char* argTargetType = argv[1];
	char* argTargetName = argv[2];
	int targetType; 

	int logFlags = LOG_CONS | LOG_PID;

	//Mode verbose
	if(strcmp(argTargetType, "-v") == 0)
	{
		if(argc < 4)
		{
			die_help();
		}
		argTargetType = argv[2];
		argTargetName = argv[3];
		logFlags = logFlags | LOG_PERROR;	
	}

	//On ouvre syslog
	openlog(PROGRAM_NAME, logFlags, LOG_LOCAL7);

	if(strcmp(argTargetType, TARGET_USER_ARG) != 0)
	{	
		if(strcmp(argTargetType, TARGET_COMPUTER_ARG) != 0)
		{
			die_help();
		}
		else
		{
			targetType = TARGET_COMPUTER;
			syslog(LOG_INFO, "Computer mode\n");
		}
	}
	else
	{
		targetType = TARGET_USER;
		syslog(LOG_INFO, "User mode\n");
	}

   LDAP* ld = slgm_ldap_init(LDAP_HOST, LDAP_ROOT_DN, LDAP_ROOT_PW); 

	char* resultDn;
	if(targetType == TARGET_COMPUTER)
	{
		resultDn = slgm_search_dn_computer(ld, argTargetName);
	}
	else
	{
		resultDn = slgm_search_dn_user(ld, argTargetName);
	}
	syslog(LOG_INFO, "Search result - fqdn : %s\n", resultDn);
	char** splittedDn = split_dn(resultDn);
	char** tree = build_dn_tree(splittedDn);
	splittedDn = free_array(splittedDn);
	syslog(LOG_INFO, "Searching for GPOs \n");
	GPODescriptor** foundGpos = slgm_fetch_gpos(ld, resultDn);
	int gpoCount = arraycnt((void**) foundGpos);
	syslog(LOG_INFO, "Found %d GPOs\n", gpoCount);
	int k;
	for(k = 0; k < gpoCount; k++)
	{
		GPODescriptor* gpo = foundGpos[k];
		if(!gpo || !gpo->valid)
		{
			syslog(LOG_WARNING, "Invalid GPO hit (probably a duplicate).\n");
			continue;
		}
		char* gpoPath = malloc(sizeof(char) * (strlen(BASE_GPO_DIRECTORY) + strlen(gpo->uri) + 1));
		sprintf(gpoPath, "%s%s", BASE_GPO_DIRECTORY, gpo->uri);
		syslog(LOG_INFO, "--------------\n");
		syslog(LOG_INFO, "GPO n°%d\n",k+1);
		syslog(LOG_INFO, "fqdn = %s\n", gpo->fqdn);
		syslog(LOG_INFO, "id = %s\n", gpo->id);
		syslog(LOG_INFO, "uri = %s\n", gpo->uri);
		syslog(LOG_INFO, "Executing %s\n", gpoPath);
		char* systemCommand = malloc(sizeof(char) * (strlen(BASE_GPO_EXEC) + strlen(gpoPath) - 1));
		sprintf(systemCommand, BASE_GPO_EXEC, gpoPath);
		system(systemCommand);
		free(gpoPath);
		free(systemCommand);
	}

	int j = arraycnt((void**) tree);
	int i;
	syslog(LOG_DEBUG, "Tree :\n");
	for(i = 0; i < j; i++)
	{
		syslog(LOG_DEBUG, "%s\n",tree[i]);
	}
	tree = free_array(tree);
	if(resultDn != NULL)
	{
		free(resultDn);
		resultDn = NULL;
	}

	slgm_ldap_close(ld);

	syslog(LOG_INFO, "Done.\n");
	closelog();
   return EXIT_SUCCESS;
}
