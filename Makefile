SB= sblist.c sblist_delete.c

-include config.mak

all: sm3

gen: gen.c
	gcc gen.c -O0 -g3 -o gen -I $(XCRYPT)/include -L $(XCRYPT)/lib/ -lxcrypt -static

sm3: crypt-cracker.c crypt-sm3.c alg-sm3.c config.mak
	gcc $< $(SB) $(CFLAGS) -o $@ -static $(LDFLAGS)
