CC=gcc
CFLAGS=-Wall

all: cert parser potsum oidlist

cert: cert.o
	$(CC) cert.o -o cert -lcrypto

parser: parser.o
	$(CC) parser.o -o parser

potsum: potlib.o potsum.o potread.o potwrite.o potlist.o xmalloc.o progname.o closeout.o fwriteerror.o

oidlist: oidlist.o potlib.o potread.o potlist.o xmalloc.o progname.o closeout.o fwriteerror.o

clean:
	rm -f *.o cert parser potsum oidlist
