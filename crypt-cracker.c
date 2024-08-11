#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "sblist.h"

struct hash {
	char user[32];
	char salt[32];
	char hash[60];
	unsigned saltlen;
};

static sblist *parse_hashes(char *fn) {
	char buf[256];
	FILE *f = fopen(fn, "rb");
	sblist *hashes = sblist_new(sizeof(struct hash), 8192);
	struct hash hcurr;
	while(fgets(buf, sizeof buf, f)) {
		char *p = strchr(buf, ':');
		if(!p) {
			if(!buf[0] || buf[0] == '\n') continue;
			hcurr.user[0] = 0;
			p = buf;
		} else {
			*p = 0;
			strcpy(hcurr.user, buf);
			*(p++) = ':';
		}
		assert(strncmp(p, "$sm3$", 5) == 0);
		char *q = strchr(p+5, '$');
		if(q) {
			*q = 0;
			strcpy(hcurr.salt, p);
			hcurr.saltlen = strlen(p)-5;
			*(q++) = '$';
			strcpy(hcurr.hash, q);
			if((p = strchr(hcurr.hash, '\n')))
			*p = 0;
		}
		sblist_add(hashes, &hcurr);
	}
	fclose(f);
	return hashes;
}

static int usage(void) {
	printf(	"usage: prog hashfile.sm3 [potfile.pot]\n"
		"if potfile is omitted, cracks in pot format are printed to stderr\n"
		"pass password candidates on stdin.\n");
	return 1;
}

static inline int inline_strcmp(const char *l, const char *r)
{
	for (; *l==*r && *l; l++, r++);
	return *(unsigned char *)l - *(unsigned char *)r;
}

static void remove_cracked(sblist *hashes, FILE *pot) {
	char buf[128];
	size_t i, cnt = 0;
	while(fgets(buf, sizeof(buf), pot)) {
		char *p = strchr(buf, ':');
		if(!p) continue;
		*p = 0;
		for(i = 0; i < sblist_getsize(hashes);)  {
			struct hash *hash = sblist_get(hashes, i);
			if(!strncmp(hash->salt, buf, hash->saltlen) && !strcmp(hash->hash, buf+6+hash->saltlen))
				sblist_delete(hashes, i), ++cnt;
			else
				++i;
		}
	}
	if(cnt) printf("pot: removed %zu known hashes\n", cnt);
}

#include "crypt-sm3.c"

int main(int argc, char**argv) {
	if((argc == 2 && !inline_strcmp(argv[1], "--help")) ||
	   (argc != 3 && argc != 2)) return usage();
	sblist *hashes = parse_hashes(argv[1]);
	FILE *pot = stderr;
	if(argc == 3) {
		pot = fopen(argv[2], "rb");
		remove_cracked(hashes, pot);
		fclose(pot);
		pot = stderr; //fopen(argv[2], "ab");
	}
	char buf[128], output[384], scratch[8192];
	unsigned cracks = 0;
	while(fgets(buf, sizeof(buf), stdin)) {
		size_t i, l = strlen(buf);
		if(l && buf[l-1] == '\n') buf[--l] = 0;
		for(i = 0; i < sblist_getsize(hashes);)  {
			struct hash *hash = sblist_get(hashes, i);
			crypt_sm3crypt_rn(buf, l, hash->salt, hash->saltlen, output, sizeof(output), scratch, sizeof(scratch));
			//char *res = crypt(buf, hash->salt);
			char *res = output;
			if(!inline_strcmp(res+5+hash->saltlen+1, hash->hash)) {
				fprintf(pot, "%s$%s:%s\n", hash->salt, hash->hash, buf);
				fflush(pot);
				printf("%s:%s\n", hash->user, buf);
				fflush(stdout);
				sblist_delete(hashes, i);
				++cracks;
			} else ++i;
		}
	}
	if(pot != stderr) fclose(pot);
	printf("cracked %u hashes\n", cracks);
	return 0;
}
