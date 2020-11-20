CC=gcc
CFLAGS=-Wall

all: cert parser_win parser_openssl potsum oidlist

cert: cert.o
	$(CC) cert.o -o cert -lcrypto

parser_win: parser_win.o
	$(CC) parser_win.o -o parser_win

parser_openssl: parser_openssl.o
	$(CC) parser_openssl.o -o parser_openssl -lcrypto

potsum: potlib.o potsum.o potread.o potwrite.o potlist.o xmalloc.o progname.o closeout.o fwriteerror.o

oidlist: oidlist.o potlib.o potread.o potlist.o xmalloc.o progname.o closeout.o fwriteerror.o

clean:
	rm -f *.o cert parser_win parser_openssl potsum oidlist
