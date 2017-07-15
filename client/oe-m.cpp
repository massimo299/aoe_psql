#include "pairing_3.h"
#include "oe-m.h"

OEBMsk *
OE::BasicSetup(Big o, Big d1, Big d2){

	OEBMsk *bmsk;
	Big w1,w2,f1,f2;
	
	pfc->random(w1);
	pfc->random(f1);
	pfc->random(f2);
	w2=moddiv(o+modmult(d2,w1,order),d1,order);

	bmsk = new OEBMsk(w1,w2,f1,f2);
	return bmsk;
}

OEMsk *
OE::Setup(){

	OEMsk *msk;
	Big omega, *Delta1, *Delta2;
	Delta1 = new Big[2];
	Delta2 = new Big[2];
	G1 g;
	G2 g2;
	OEBMsk ***bmsk = new OEBMsk**[len];
	
	pfc->random(omega);
	pfc->random(Delta1[0]);
	pfc->random(Delta1[1]);
	pfc->random(Delta2[0]);
	pfc->random(Delta2[1]);
	pfc->random(g);
	pfc->random(g2);

	for(int i=0;i<len;i++){
		bmsk[i] = new OEBMsk*[2];
		bmsk[i][0] = BasicSetup(omega,Delta1[0],Delta1[1]);
		bmsk[i][1] = BasicSetup(omega,Delta2[0],Delta2[1]);
	}

	msk = new OEMsk(g,g2,omega,Delta1,Delta2,bmsk);
	return msk;
}

OEMsk *
OE::Setup(G1 g, G2 g2, Big omega, Big *Delta1, Big *Delta2){

	OEMsk *msk;
	OEBMsk ***bmsk = new OEBMsk**[len];

	for(int i=0;i<len;i++){
		bmsk[i] = new OEBMsk*[2];
		bmsk[i][0] = BasicSetup(omega,Delta1[0],Delta1[1]);
		bmsk[i][1] = BasicSetup(omega,Delta2[0],Delta2[1]);
	}

	msk = new OEMsk(g,g2,omega,Delta1,Delta2,bmsk);
	return msk;
}

OEBCt *
OE::BasicEncrypt(OEBMsk *bmsk, Big *D, Big x, Big s1, Big s2, Big t, G1 g){
	
	OEBCt *ct;
	G1 ct1,ct2;
	Big c1,c2;

	c1 = modmult(bmsk->w1,s1,order)+modmult(bmsk->f1,s2,order)+modmult(D[0],modmult(x,t,order),order);
	c2 = modmult(bmsk->w2,s1,order)+modmult(bmsk->f2,s2,order)+modmult(D[1],modmult(x,t,order),order);
	ct1=pfc->mult(g,c1);
	ct2=pfc->mult(g,c2);

	ct = new OEBCt(ct1,ct2);
	return ct;
}

OECt *
OE::PEncrypt(OEMsk *msk, Big *X){

	OECt *ct;
	OEBCt ***bct = new OEBCt**[len];
	Big s1,s2,s3,s4;
	G1 g_1, g1_1;

	pfc->random(s1);
	pfc->random(s2);
	pfc->random(s3);
	pfc->random(s4);

	for(int i=0;i<len;i++){
		bct[i] = new OEBCt*[2];
		bct[i][0]=BasicEncrypt(msk->bmsk[i][0],msk->Delta1,X[i],s1,s2,s3,msk->g);
		bct[i][1]=BasicEncrypt(msk->bmsk[i][1],msk->Delta2,X[i],s1,s2,s4,msk->g);
	}
	g_1 = pfc->mult(msk->g,s2);
	g1_1 = pfc->mult(msk->g,modmult(msk->omega,s1,order));

	ct = new OECt(g_1,g1_1,bct);
	return ct;
}

OECt *
OE::MEncrypt(OEMsk *msk, Big *X, GT M){

	OECt *ct;
	OEBCt ***bct = new OEBCt**[len];
	Big s1,s2,s3,s4;
	G1 g_1, g1_1;

	pfc->random(s1);
	pfc->random(s2);
	pfc->random(s3);
	pfc->random(s4);

	for(int i=0;i<len;i++){
		bct[i] = new OEBCt*[2];
		bct[i][0]=BasicEncrypt(msk->bmsk[i][0],msk->Delta1,X[i],s1,s2,s3,msk->g);
		bct[i][1]=BasicEncrypt(msk->bmsk[i][1],msk->Delta2,X[i],s1,s2,s4,msk->g);
	}

	g_1 = pfc->mult(msk->g,s2);
	g1_1 = pfc->mult(msk->g,modmult(msk->omega,s1,order));
	GT tmpgt = pfc->pairing(msk->g2,msk->g);
	GT C0 = pfc->power(tmpgt,s2);
	GT C = M*C0;
	ct = new OECt(g_1,g1_1,bct,C);

	return ct;
}

OECt *
OE::MEncrypt(OEMsk *msk, Big *X, Big s3, Big s4, GT M){

	OECt *ct;
	OEBCt ***bct = new OEBCt**[len];
	Big s1,s2;
	G1 g_1, g1_1;

	pfc->random(s1);
	pfc->random(s2);

	for(int i=0;i<len;i++){
		bct[i] = new OEBCt*[2];
		bct[i][0]=BasicEncrypt(msk->bmsk[i][0],msk->Delta1,X[i],s1,s2,s3,msk->g);
		bct[i][1]=BasicEncrypt(msk->bmsk[i][1],msk->Delta2,X[i],s1,s2,s4,msk->g);
	}

	g_1 = pfc->mult(msk->g,s2);
	g1_1 = pfc->mult(msk->g,modmult(msk->omega,s1,order));
	GT tmpgt = pfc->pairing(msk->g2,msk->g);
	GT C0 = pfc->power(tmpgt,s2);
	GT C = M*C0;

	ct = new OECt(g_1,g1_1,bct,C);
	return ct;
}

OEBKey *
OE::BasicKeyGen(OEBMsk *bmsk, Big *D, Big y, Big lambda, Big r, G2 g2){
	
	OEBKey *k;
	G2 k1,k2;
	Big bk1,bk2;

	bk1 = modmult(modmult(lambda,y,order),bmsk->w2,order)-modmult(D[1],r,order);
	bk2 = modmult(D[0],r,order)-modmult(modmult(lambda,y,order),bmsk->w1,order);

	k1 = pfc->mult(g2,bk1);
	k2 = pfc->mult(g2,bk2);

	k = new OEBKey(k1,k2);
	return k;
}

OEKey *
OE::PKeyGen(OEMsk *msk, Big *Y){
	
	OEKey *k;
	OEBKey ***bk = new OEBKey**[len];
	Big lambda1,lambda2,r[len],phi[len],kb=0;
	G2 KA, KB;

	pfc->random(lambda1);
	pfc->random(lambda2);

	OEBMsk *bmsk1, *bmsk2;
	for(int i=0;i<len;i++){
		bk[i] = new OEBKey*[2];
		pfc->random(r[i]);
		pfc->random(phi[i]);
		bmsk1 = msk->bmsk[i][0];
		bmsk2 = msk->bmsk[i][1];

		bk[i][0] = BasicKeyGen(bmsk1,msk->Delta1,Y[i],lambda1,r[i],msk->g2);
		bk[i][1] = BasicKeyGen(bmsk2,msk->Delta2,Y[i],lambda2,phi[i],msk->g2);
		KA = KA+pfc->mult(bk[i][0]->k1,-bmsk1->f1);
		KA = KA+pfc->mult(bk[i][0]->k2,-bmsk1->f2);
		KA = KA+pfc->mult(bk[i][1]->k1,-bmsk2->f1);
		KA = KA+pfc->mult(bk[i][1]->k2,-bmsk2->f2);
		kb += -(r[i]+phi[i])%order;
	}
	KB = pfc->mult(msk->g2,kb);

	k = new OEKey(KA,KB,bk);
	return k;
}

OEKey *
OE::MKeyGen(OEMsk *msk, Big *Y){
	
	OEKey *k;
	OEBKey ***bk = new OEBKey**[len];
	Big lambda1,lambda2,r[len],phi[len],kb=0;
	G2 KA, KB;
	KA=msk->g2;

	pfc->random(lambda1);
	pfc->random(lambda2);

	OEBMsk *bmsk1, *bmsk2;
	for(int i=0;i<len;i++){
		bk[i] = new OEBKey*[2];
		pfc->random(r[i]);
		pfc->random(phi[i]);
		bmsk1 = msk->bmsk[i][0];
		bmsk2 = msk->bmsk[i][1];

		bk[i][0] = BasicKeyGen(bmsk1,msk->Delta1,Y[i],lambda1,r[i],msk->g2);
		bk[i][1] = BasicKeyGen(bmsk2,msk->Delta2,Y[i],lambda2,phi[i],msk->g2);
		KA = KA+pfc->mult(bk[i][0]->k1,-bmsk1->f1);
		KA = KA+pfc->mult(bk[i][0]->k2,-bmsk1->f2);
		KA = KA+pfc->mult(bk[i][1]->k1,-bmsk2->f1);
		KA = KA+pfc->mult(bk[i][1]->k2,-bmsk2->f2);
		kb += -(r[i]+phi[i])%order;
	}
	KB = pfc->mult(msk->g2,kb);

	k = new OEKey(KA,KB,bk);
	return k;
}

OEKey *
OE::MKeyGen(OEMsk *msk, Big *Y, Big lambda1, Big lambda2){
	
	OEKey *k;
	OEBKey ***bk = new OEBKey**[len];
	Big r[len],phi[len],kb=0;
	G2 KA, KB;
	KA=msk->g2;

	OEBMsk *bmsk1, *bmsk2;
	for(int i=0;i<len;i++){
		bk[i] = new OEBKey*[2];
		pfc->random(r[i]);
		pfc->random(phi[i]);
		bmsk1 = msk->bmsk[i][0];
		bmsk2 = msk->bmsk[i][1];

		bk[i][0] = BasicKeyGen(bmsk1,msk->Delta1,Y[i],lambda1,r[i],msk->g2);
		bk[i][1] = BasicKeyGen(bmsk2,msk->Delta2,Y[i],lambda2,phi[i],msk->g2);
		KA = KA+pfc->mult(bk[i][0]->k1,-bmsk1->f1);
		KA = KA+pfc->mult(bk[i][0]->k2,-bmsk1->f2);
		KA = KA+pfc->mult(bk[i][1]->k1,-bmsk2->f1);
		KA = KA+pfc->mult(bk[i][1]->k2,-bmsk2->f2);
		kb += -(r[i]+phi[i])%order;
	}
	KB = pfc->mult(msk->g2,kb);

	k = new OEKey(KA,KB,bk);
	return k;
}

bool
OE::PDecrypt(OECt *ct, OEKey *key){

	G2 **left=new G2* [4*len+2];
	G1 **right=new G1* [4*len+2];

	left[0]=&key->KA; right[0]=&ct->A;
	left[1]=&key->KB; right[1]=&ct->B;
	int j=2;
	for (int i=0;i<len;i++)
	{
		left[j]=&key->key[i][0]->k1;
		right[j]=&ct->ct[i][0]->ct1;
		j++;
		left[j]=&key->key[i][0]->k2;
		right[j]=&ct->ct[i][0]->ct2;
		j++;
		left[j]=&key->key[i][1]->k1;
		right[j]=&ct->ct[i][1]->ct1;
		j++;
		left[j]=&key->key[i][1]->k2;
		right[j]=&ct->ct[i][1]->ct2;
		j++;
	}

	GT res=pfc->multi_pairing(4*len+2,left,right);

	if(res==(GT)1)
		return true;
	else
		return false;
}

GT
OE::MDecrypt(OECt *ct, OEKey *key){

	G2 **left=new G2* [4*len+2];
	G1 **right=new G1* [4*len+2];

	left[0]=&key->KA; right[0]=&ct->A;
	left[1]=&key->KB; right[1]=&ct->B;
	int j=2;
	for (int i=0;i<len;i++)
	{
		left[j]=&key->key[i][0]->k1;
		right[j]=&ct->ct[i][0]->ct1;
		j++;
		left[j]=&key->key[i][0]->k2;
		right[j]=&ct->ct[i][0]->ct2;
		j++;
		left[j]=&key->key[i][1]->k1;
		right[j]=&ct->ct[i][1]->ct1;
		j++;
		left[j]=&key->key[i][1]->k2;
		right[j]=&ct->ct[i][1]->ct2;
		j++;
	}

	GT res=ct->C/pfc->multi_pairing(4*len+2,left,right);
	
	delete[] left;
	delete[] right;

	return res;
}
