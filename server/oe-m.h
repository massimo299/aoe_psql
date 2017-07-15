#include "pairing_3.h"

class OEBMsk{
public:
	
	Big w1,w2,f1,f2;
public:
	OEBMsk(Big w1_, Big w2_, Big f1_, Big f2_){
		w1=w1_;
		w2=w2_;
		f1=f1_;
		f2=f2_;
	};
	OEBMsk(){
	};
};

class OEMsk{
public:
	G1 g;
	G2 g2;
	Big omega, *Delta1, *Delta2;
	OEBMsk ***bmsk;
public:
	OEMsk(G1 g_, G2 g2_, Big o, Big *D1, Big *D2, OEBMsk ***bm){
		g=g_;
		g2=g2_;
		omega=o;
		Delta1=D1;
		Delta2=D2;
		bmsk=bm;
	};
};

class OEBCt{
public:
	G1 ct1, ct2;
public:
	OEBCt(G1 ct1_, G1 ct2_){
		ct1=ct1_;
		ct2=ct2_;
	};
};

class OECt{
public:
	G1 A, B;
	OEBCt ***ct;
	GT C;
public:
	OECt(G1 g, G1 g1, OEBCt ***c){
		A=g;
		B=g1;
		ct=c;
	};
	OECt(G1 g, G1 g1, OEBCt ***c, GT C_){
		A=g;
		B=g1;
		ct=c;
		C=C_;
	};
};

class OEBKey{
public:
	G2 k1, k2;
public:
	OEBKey(G2 k1_, G2 k2_){
		k1=k1_;
		k2=k2_;
	};
};

class OEKey{
public:
	G2 KA, KB;
	OEBKey ***key;
public:
	OEKey(G2 A, G2 B, OEBKey ***k){
		KA=A;
		KB=B;
		key=k;
	};
};

class OE{
public:
	int len;
	PFC *pfc;
	miracl *mip;
	Big order;
public:
	OEMsk *Setup();
	OEMsk *Setup(G1, G2, Big, Big *, Big *);
	OECt *PEncrypt(OEMsk *, Big *);
	OECt *MEncrypt(OEMsk *, Big *, GT);
	OECt *MEncrypt(OEMsk *, Big *, Big, Big, GT);
	OEKey *PKeyGen(OEMsk *, Big *);
	OEKey *MKeyGen(OEMsk *, Big *);
	OEKey *MKeyGen(OEMsk *, Big *, Big, Big);
	bool PDecrypt(OECt *, OEKey *);
	GT MDecrypt(OECt *, OEKey *);
	OE(int l, PFC *p, miracl * m, Big o){
		len=l;
		pfc=p;
		mip=m;
		order=o;
		
	};
private:
	OEBMsk *BasicSetup(Big, Big, Big);
	OEBCt *BasicEncrypt(OEBMsk *, Big *, Big, Big, Big, Big, G1);
	OEBKey *BasicKeyGen(OEBMsk *, Big *, Big, Big, Big, G2);
};
