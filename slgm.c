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

#define FILTER_COMPUTER "(&(cn=%s)(objectClass=device))"
#define FILTER_USER "(&(uid=%s)(objectClass=posixAccount))"
#define FILTER_GPO "(objectClass=groupPolicyDescriptor)"
#define BASE_DN_COMPUTER "ou=computers,dc=utopia,dc=net"
#define BASE_DN_USER "ou=people,dc=utopia,dc=net"

#define LDAP_GPO_SCHEMA_ID "id"
#define LDAP_GPO_SCHEMA_URI "uri"

//targetDn = FQDN de l'utilisateur/ordinateur
GPODescriptor** slgm_fetch_gpos(LDAP* ld, char* targetDn)
{
	LDAPMessage* msg;
	GPODescriptor** fetchedPolicies = NULL;
	char** splittedDn = split_dn(targetDn);
	char** tree = build_dn_tree(splittedDn);
	int objectCount = arraycnt((void**) tree);
	int gpoCount = 0;
	int currentGpoPosition = 0;

	int i;
	fetchedPolicies = malloc(sizeof(GPODescriptor*));
	//i = 1 car on saute le premier element qui est dc=net
	for(i = 1; i < objectCount; i++)
	{
		//Remplacer basedn par element du tableau
   	int ldapErrno = ldap_search_s(ld, tree[i], LDAP_SCOPE_ONELEVEL, FILTER_GPO, NULL, 0, &msg); 
   	if(ldapErrno != LDAP_SUCCESS)
		{
			syslog(LOG_ERR, "Ldap error : %d %s - Base dn : %s\n", ldapErrno, ldap_err2string(ldapErrno), tree[i]);
      	//ldap_perror( ld, "ldap_search_s" );
      	//Pas besoin de planter si la recherche ne renvoie rien
			//exit(EXIT_FAILURE);
			continue;
   	}
		
   	int searchResultCount = ldap_count_entries(ld, msg);		
		if(searchResultCount < 1) {
			continue;
		}
		gpoCount += searchResultCount;
		//+1 Pour l'element vide a la fin du tableau, comme d'habitude
		fetchedPolicies = realloc(fetchedPolicies, sizeof(GPODescriptor*) * (gpoCount + 1));
		int j;
		//On ne fait pas -1 car on veut bien seulement les nouveaux elements du tableau
		for(j = gpoCount - searchResultCount; j < gpoCount; j++)
		{
			fetchedPolicies[j] = NULL;
		}
		LDAPMessage* entry = NULL;
		for(j = 0; j < searchResultCount; j++)
		{	
			GPODescriptor* gpo = malloc(sizeof(GPODescriptor));
			gpo->valid = 1;
			if(entry == NULL)
			{
				entry = ldap_first_entry(ld, msg);
			} else {
				entry = ldap_next_entry(ld, entry);
			}
			if(entry == NULL)
			{
				syslog(LOG_ERR, "Internal error (entry)\n");
				exit(EXIT_FAILURE);
			}
			char* resultDn = ldap_get_dn(ld, entry);
			if(resultDn == NULL)
			{
				syslog(LOG_ERR, "Internal error (dn)\n");
				exit(EXIT_FAILURE);
			}
			gpo->fqdn = malloc(sizeof(char) * (strlen(resultDn) + 1));
			strcpy(gpo->fqdn, resultDn);
			ldap_memfree(resultDn);
			resultDn = NULL;

			int gpoIdFound = 0;
			int gpoUriFound = 0;
			char** attrValues = NULL;
			
			attrValues = ldap_get_values(ld, entry, LDAP_GPO_SCHEMA_ID);
			//On check count ET [0] car OpenLdap répond parfois des trucs étrange ...
			if(attrValues && ldap_count_values(attrValues) > 0 && attrValues[0] != NULL)
			{
				//On ignore le cas ou il y a plusieurs attributs avec le même nom.
				//Ca serait une description de GPO invalide de toute facon
				gpoIdFound = 1;
				strcpy(gpo->id, attrValues[0]);
			}
			if(attrValues)
			{
				ldap_value_free(attrValues);
			}

			attrValues = ldap_get_values(ld, entry, LDAP_GPO_SCHEMA_URI);
			//Pareil que plus haut, on ne change pas une condition qui gagne	
			if(attrValues && ldap_count_values(attrValues) > 0 && attrValues[0] != NULL)
			{	
				gpoUriFound = 1;
				strcpy(gpo->uri, attrValues[0]);
			}
			if(attrValues)
			{
				ldap_value_free(attrValues);
			}
	
			int duplicateId = 0;
			int k;
			for(k = 0; k < gpoCount; k++)
			{
				GPODescriptor* tmpGpo = fetchedPolicies[k];
				if(tmpGpo != NULL && (strcmp(gpo->id, tmpGpo->id) == 0))
				{
					duplicateId = 1;
					syslog(LOG_WARNING, "Skipping duplicate gpo id %s, at %s duplicate of %s\n", tmpGpo->id, tmpGpo->fqdn, gpo->fqdn);
				}
			}
			if(!gpoIdFound || !gpoUriFound || duplicateId)
			{
				//En cas de GPO malformée, mettre le flag valid sur 0
				gpo->valid = 0;
			}
			fetchedPolicies[currentGpoPosition] = gpo;
			currentGpoPosition++;	
		}
		ldap_msgfree(msg);
		msg = NULL;
	}	
	fetchedPolicies[gpoCount] = NULL;
	splittedDn = free_array(splittedDn);
	tree = free_array(tree);
	return fetchedPolicies;
}

char** split_dn(char* fqdn)
{
	int objectCount = strccnt(fqdn, ',') + 1;
	char* tmpFqdn = malloc(sizeof(char) * (strlen(fqdn) + 1));
	strcpy(tmpFqdn, fqdn);
	char** splitted = malloc(sizeof(char*) * (objectCount + 1));
	char* extracted = strtok (tmpFqdn, ",");
	int i = 0;
	while (extracted != NULL)
	{	
		splitted[i] = malloc(sizeof(char*) * (strlen(extracted) + 1));
		strcpy(splitted[i], extracted);
		i++;
		extracted = strtok (NULL, ",");
	}
	//On termine l'array par null pour le parcourir facilement
	splitted[i] = NULL;
	return splitted;
}

char** build_dn_tree(char** splittedDn)
{
	int objectCount = arraycnt((void**) splittedDn); 
	int tmpStringSize = 0;
	//Pas besoin d'allouer +1 a objectCount car on saute un element.
	//On a donc deja une ligne en trop !
	char** tree = malloc(sizeof(char*) * (objectCount));
	int i;
	//On saute le dernier element lu (donc le premier du tableau)
	//Car c'est l'utilisateur/ordinateur trouvé
	//Les autres objectCount-1-i n'ont aucun rapport, ils sont la
	//pour compenser le fait que un tableau démarre à 0
	for(i = 0; i < objectCount-1; i++)
	{	
		tmpStringSize += strlen(splittedDn[objectCount-1-i]);
		if(i > 0)
		{
			//+1 pour la ,
			tmpStringSize++;
		}
		//+1 pour \0 de fin de string
		char* treeElement = malloc(sizeof(char) * (tmpStringSize + 1));
		if(i > 0)
		{
			//On copie l'ancienne string pour completer l'arbre
			sprintf(treeElement, "%s,%s", splittedDn[objectCount-1-i], tree[i-1]); 	
		}
		else
		{
			sprintf(treeElement, "%s", splittedDn[objectCount-1-i]);
		}
		tree[i] = treeElement;
	}
	//Fin du tableau
	tree[objectCount-1] = NULL;
	return tree;
}

char* slgm_search_dn(LDAP* ld, char* basedn, char* filter)
{
	LDAPMessage* msg;
	char* dn;

   if (ldap_search_s(ld, basedn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, &msg) != LDAP_SUCCESS) 
   {
      ldap_perror( ld, "ldap_search_s" );
      exit(EXIT_FAILURE);
   }

   if(ldap_count_entries(ld, msg) < 1)
	{
		syslog(LOG_ERR, "Error : user or computer not found. Filter : %s\n", filter);
		exit(EXIT_FAILURE);
	}
   
	LDAPMessage* entry = ldap_first_entry(ld, msg);
	if(entry == NULL)
	{
		syslog(LOG_ERR, "Internal error\n");
		exit(EXIT_FAILURE);
	}

	char* tmpDn = ldap_get_dn(ld, entry);
	dn = NULL;
	if(tmpDn != NULL)
	{
		dn = malloc(sizeof(char) * (strlen(tmpDn) + 1));
		strcpy(dn, tmpDn);
	}
	ldap_memfree(tmpDn);	
   ldap_msgfree(msg);
	return dn;
}

char* slgm_search_dn_computer(LDAP* ld, char* name)
{
	//On enleve le %s de la taille
	char* filter = malloc(sizeof(char) * (strlen(FILTER_COMPUTER) - 2 + 1 + strlen(name)));
	sprintf(filter, FILTER_COMPUTER, name);
	char* result = slgm_search_dn(ld, BASE_DN_COMPUTER, filter);
	free(filter);
	return result;
}

char* slgm_search_dn_user(LDAP* ld, char* name)
{
	//On enleve le %s de la taille
	char* filter = malloc(sizeof(char) * (strlen(FILTER_USER) - 2 + 1 + strlen(name)));
	sprintf(filter, FILTER_USER, name);
	char* result = slgm_search_dn(ld, BASE_DN_USER, filter);
	free(filter);
	return result;
}

LDAP* slgm_ldap_init(char* ldap_host, char* root_dn, char* root_pw)
{	
   LDAP* ld;
   int auth_method = LDAP_AUTH_SIMPLE;
   int desired_version = LDAP_VERSION3;
   char* errstring;
  
   if ((ld = ldap_init(ldap_host, LDAP_PORT)) == NULL ) 
   {
      perror( "ldap_init failed" );
      exit( EXIT_FAILURE );
   }

   if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version) != LDAP_OPT_SUCCESS)
   {
      ldap_perror(ld, "ldap_set_option");
      exit(EXIT_FAILURE);
   }

   if (ldap_bind_s(ld, root_dn, root_pw, auth_method) != LDAP_SUCCESS ) 
   {
      ldap_perror( ld, "ldap_bind" );
      exit( EXIT_FAILURE );
   }
	
	return ld;
}

void slgm_ldap_close(LDAP* ld)
{
   int result = ldap_unbind_s(ld);
   if (result != 0) 
   {
      syslog(LOG_ERR, "Error in ldap_unbind_s: %s\n", ldap_err2string(result));
      exit( EXIT_FAILURE );
   }
}
