LDFLAGS=-lcrypto -lssl -lpthread -g -lpq
CXXFLAGS=-g
CXXFLAGS= -std=gnu++11 -D_REENTRANT
BNOBJB= bn_pair.o zzn2.o zzn12a.o zzn4.o ecn2.o big.o zzn.o ecn.o base64.o oe-m.o aoe-m.o

EXE= DblpTest

EXE: ${EXE}

DblpTest.o: DblpTest.cpp
	g++ -I /usr/include/postgresql -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c DblpTest.cpp -o DblpTest.o

DblpTest: ${BNOBJB} DblpTest.o
	g++ -o DblpTest ${BNOBJB} DblpTest.o miracl.a ${LDFLAGS}

oe-m.o: oe-m.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c oe-m.cpp -o oe-m.o -g

aoe-m.o: aoe-m.cpp
	g++ -I /usr/include/postgresql -I -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c aoe-m.cpp -o aoe-m.o -g


all: ${EXE}

clean:
	rm -f ${BNOBJB} ${EXE} DblpTest.o
