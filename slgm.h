#ifndef SLGM_H
#define SLGM_H

#define PROGRAM_NAME "slgm"

typedef struct {
	char* fqdn;
	char id[33];
	char uri[256];
	int valid;
} GPODescriptor;

GPODescriptor** slgm_fetch_gpos(LDAP* ld, char* targetDn);
char** split_dn(char* fqdn);
char** build_dn_tree(char** splittedDn);
char* slgm_search_dn(LDAP* ld, char* basedn, char* filter);
char* slgm_search_dn_computer(LDAP* ld, char* name);
char* slgm_search_dn_user(LDAP* ld, char* name);
LDAP* slgm_ldap_init(char* ldap_host, char* root_dn, char* root_pw);
void slgm_ldap_close(LDAP* ld);

#endif
