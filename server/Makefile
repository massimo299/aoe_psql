CC ?= gcc
CXX ?= g++

CFLAGS = -o0 -g
CXXFLAGS = 00 -g
CXXFLAGS = -std=gnu++11 -D_REENTRANT -fpic

OBJ = aoe_server.o ApplyPTokenServer.o ApplyPTokenServer.so
OBJS = bn_pair.o zzn2.o zzn12a.o zzn4.o ecn2.o big.o zzn.o ecn.o oe-m.o

LDFLAGS=-lpthread -lpq

all:
	make compile

compile:
	make $(OBJS) $(OBJ)

oe-m.o: oe-m.cpp
	$(CXX) -fpic -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c oe-m.cpp -o oe-m.o

ApplyPTokenServer.o: ApplyPTokenServer.cpp
	$(CXX) -fpic -c -I/usr/include/postgresql/9.3/server/ -I/usr/include/postgresql/9.3/server/utils/ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128  -o ApplyPTokenServer.o ApplyPTokenServer.cpp

aoe_server.o: aoe_server.cpp
	$(CXX) -fpic -I/usr/include/postgresql/ -I/usr/include/postgresql/9.3/server -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c aoe_server.cpp -o aoe_server.o -g

ApplyPTokenServer.so: $(OBJS) ApplyPTokenServer.o
	$(CXX) -shared -o ApplyPTokenServer.so $(OBJS) aoe_server.o ApplyPTokenServer.o miracl.a $(LDFLAGS)

clean:
	rm -rf $(OBJ) $(OBJS) *.dSYM
