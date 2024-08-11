#include <crypt.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(int argc, char**argv) {
	unsigned cnt;
	printf("%s\n", crypt(argv[1], "$sm3$H/2J94Lsy1c2JozO"));
	return 0;
	//printf("%s\n", crypt(argv[1], "$sm3$rounds=80000"));
}
