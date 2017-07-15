#include <fstream>
#include <sstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <limits>
#include "pairing_3.h"
#include "base64.h"
#include "aoe-m.h"
#include <sys/timeb.h>
#include <pthread.h>
#include <queue> 
#include <algorithm>

//#include "ApplyPTokenServer.h"

//#define VERBOSE

int
SecureSelect::getMilliCount(){
	timeb tb;
	ftime(&tb);
	int nCount = tb.millitm + (tb.time & 0xfffff) * 1000;
	return nCount;
}

int
SecureSelect::getMilliSpan(int nTimeStart){
	int nSpan = getMilliCount() - nTimeStart;
	if(nSpan < 0)
		nSpan += 0x100000 * 1000;
	return nSpan;
}

OEMsk **
AOE::Setup(){

	OEMsk **msks = new OEMsk*[n+1];
	
	pfc->random(omega);
	pfc->random(ab1[0]); pfc->random(ab1[1]);
	pfc->random(ab2[0]); pfc->random(ab2[1]);

	pfc->random(g); pfc->random(g2);

	oe = new OE(l+1,pfc,mip,order);
	msks[0] = oe->Setup(g,g2,omega,ab1,ab2);

	oe->len = k+1;
	for(int i=1;i<=n;i++)
		msks[i] = oe->Setup(g,g2,omega,ab1,ab2);

	return msks;

}

OECt **
AOE::Encrypt(OEMsk **msks, Big *X0, Big **X, GT *M){

	Big y, z1, z2;
	OECt ** cts = new OECt*[n+1];

	pfc->random(y);
	pfc->random(z1); pfc->random(z2);
	
	X0[l]=y;
	oe->len=l+1;
	cts[0] = oe->MEncrypt(msks[0],X0,z1,z2,(GT)1);

	oe->len=k+1;
	for(int i=1;i<=n;i++){
		X[i-1][0]=y;
		cts[i] = oe->MEncrypt(msks[i],X[i-1],z1,z2,M[i-1]);
	}

	return cts;
}

OEKey *
AOE::PKeyGen(OEMsk **msks, Big *Y){

	Y[l]=0;
	oe->len=l+1;

	return oe->MKeyGen(msks[0],Y);
}

GT
AOE::PDecrypt(OECt *C0, OEKey *pkey){

	oe->len=l+1;

	return oe->MDecrypt(C0,pkey);
}

OEKey **
AOE::MKeyGen(OEMsk **msks, Big *Y, Big *Yj, int j){

	OEKey **keys = new OEKey*[2];
	Big lambda1, lambda2;

	pfc->random(lambda1);
	pfc->random(lambda2);

	Y[l]=1;
	oe->len=l+1;
	keys[0] = oe->MKeyGen(msks[0],Y,lambda1,lambda2);

	Yj[0]=-1;
	oe->len=k+1;
	keys[1] = oe->MKeyGen(msks[j],Yj,lambda1,lambda2);

	return keys;
}

OEKey **
AOE::MKeyGen(OEMsk **msks, Big *Y, Big **Yj, vector<string> sel_params){

	OEKey **keys = new OEKey*[sel_params.size()+1];
	Big lambda1, lambda2;

	pfc->random(lambda1);
	pfc->random(lambda2);

	Y[l]=1;
	oe->len=l+1;
	keys[0] = oe->MKeyGen(msks[0],Y,lambda1,lambda2);

	oe->len=k+1;
	int j;
	for(int i=0;i<sel_params.size();i++){
		istringstream(sel_params.at(i)) >> j;
		Yj[i][0]=-1;
		keys[i+1] = oe->MKeyGen(msks[j],Yj[i],lambda1,lambda2);
	}

	return keys;
}

GT 
AOE::MDecrypt(OECt **cts, OEKey **keys, int j){

	GT res1,res2;

	oe->len=l+1;
	res1 = oe->MDecrypt(cts[0],keys[0]);

	oe->len=k+1;
	res2 = oe->MDecrypt(cts[j],keys[1]);

	return res1*res2;
}

OEMsk **
AOENoise::RSetup(){
	return aoe->Setup();
}

OECt **
AOENoise::EncryptRow(OEMsk **msks, Big *A, GT *M, int rand_lim){

	Big X0[l+1], *X[n];
	Big r = rand()%rand_lim+1;

	X0[n]=r;
	for(int i=0;i<n;i++){
		X0[i] = A[i];
		X0[n+i+1] = modmult(r,A[i],order);

		X[i] = new Big[k+1];
		X[i][0]=0;
		X[i][1]=1;
		X[i][2]=i+1;
	}
	X0[l-1]=1;

	OECt** ct = aoe->Encrypt(msks,X0,X,M);

	for(int i=0;i<n;i++)
		delete[] X[i];
	return ct;
}

OEKey *
AOENoise::PKeyGen(OEMsk **msks, Big *Q, int rand_lim){

	Big Y0[l+1], R[n];
	Big r = rand()%rand_lim+1;

	Y0[l-1] = 0;
	Y0[n]=0;
	for(int i=0;i<n;i++){
		if(Q[i]==0)
			R[i] = 0;
		else
			pfc->random(R[i]);
		Y0[i] = -modmult(r,R[i],order);
		Y0[n] = Y0[n] - modmult(R[i],Q[i],order);
		Y0[n+i+1] = R[i];
		Y0[l-1] = Y0[l-1] + modmult(R[i],Q[i],order);
	}
	Y0[l-1] = modmult(r,Y0[l-1],order);

	return aoe->PKeyGen(msks,Y0);
}

OEKey **
AOENoise::MKeyGen(OEMsk **msks, Big *Q, int j, int rand_lim){

	Big Y0[l+1], R[n], Yj[k+1];
	Big r;
	if(rand_lim!=0)
		r = rand()%rand_lim+1;
	else
		r = Big(0);

	Y0[l-1] = 0;
	for(int i=0;i<n;i++){
		if(Q[i]==0)
			R[i] = 0;
		else
			pfc->random(R[i]);
		Y0[i] = -modmult(r,R[i],order);
		Y0[n] = Y0[n] - modmult(R[i],Q[i],order);
		Y0[n+i+1] = R[i];
		Y0[l-1] = Y0[l-1] + modmult(R[i],Q[i],order);
	}
	Y0[l-1] = modmult(r,Y0[l-1],order);

	Yj[0]=0;
	Yj[1]=j;
	Yj[2]=-1;

	return aoe->MKeyGen(msks,Y0,Yj,j);
}

OEKey **
AOENoise::MKeyGen(OEMsk **msks, Big *Q, vector<string> sel_params, int rand_lim){

	Big **Yj;
	Yj = new Big*[sel_params.size()];
	
	Big Y0[l+1], R[n];
	Big r;
	if(rand_lim!=0)
		r = rand()%rand_lim+1;
	else
		r = Big(0);

	Y0[l-1] = 0;
	for(int i=0;i<n;i++){
		if(Q[i]==0)
			R[i] = 0;
		else
			pfc->random(R[i]);
		Y0[i] = -modmult(r,R[i],order);
		Y0[n] = Y0[n] - modmult(R[i],Q[i],order);
		Y0[n+i+1] = R[i];
		Y0[l-1] = Y0[l-1] + modmult(R[i],Q[i],order);
	}
	Y0[l-1] = modmult(r,Y0[l-1],order);

	int j;
	for(int i=0;i<sel_params.size();i++){
		Yj[i] = new Big[k+1];
		istringstream(sel_params.at(i)) >> j;
		Yj[i][0]=0;
		Yj[i][1]=j;
		Yj[i][2]=-1;
	}

	return aoe->MKeyGen(msks,Y0,Yj,sel_params);
}

/**
 * Write all the n+1 master keys in fname.
 */
void
SecureSelect::saveMsks(string fname, OEMsk **msks)
{
	ofstream outputFile;
	outputFile.open(fname);

	/** Write n (number of columns) */
	outputFile << n << endl;

	/** Write aoen parameters */
	outputFile << aoen->aoe->omega << endl << aoen->aoe->ab1[0] << endl << aoen->aoe->ab1[1] << endl;
	outputFile << aoen->aoe->ab2[0] << endl << aoen->aoe->ab2[1] << endl << aoen->aoe->g << endl << aoen->aoe->g2 << endl;

	/** Write msks parameters */
	OEBMsk *bmsk;
	for(int i=0;i<l+1;i++){
		bmsk = msks[0]->bmsk[i][0];
		outputFile << bmsk->w1 << endl << bmsk->w2 << endl << bmsk->f1 << endl << bmsk->f2 << endl;
		bmsk = msks[0]->bmsk[i][1];
		outputFile << bmsk->w1 << endl << bmsk->w2 << endl << bmsk->f1 << endl << bmsk->f2 << endl;
	}
	for(int i=1;i<n+1;i++)
		for(int j=0;j<k+1;j++){
			bmsk = msks[i]->bmsk[j][0];
			outputFile << bmsk->w1 << endl << bmsk->w2 << endl << bmsk->f1 << endl << bmsk->f2 << endl;
			bmsk = msks[i]->bmsk[j][1];
			outputFile << bmsk->w1 << endl << bmsk->w2 << endl << bmsk->f1 << endl << bmsk->f2 << endl;
		}

	outputFile.close();	
}

/**
 * Get the key file name in input.
 *
 * Create n+1 master keys
 * and store them in a file called key_name.
 */
void
SecureSelect::KeyGen(string key_name){
	#ifdef VERBOSE
	int start = getMilliCount();
	#endif
	msks = aoen->RSetup();
	#ifdef VERBOSE
	int milliSecondsElapsed = getMilliSpan(start);
	cout << "\tSetup exec time " << milliSecondsElapsed << endl;
	#endif
	saveMsks(key_name,msks);
}

/**
 * Load a previously created key, stored in key_name.
 *
 * Put it in msks variable and return true if everything is ok.
 */
bool
SecureSelect::LoadKey(string key_name){

	/* Check if key file exists */
	if (!ifstream(key_name)){
		cout << "Key file doesn't exist" << endl;
		return false;
	}

	ifstream inputFile(key_name);

	/* Get n (number of columns) */
	inputFile >> n;
	l=2*n+2;
	k=2;

	/* Get aoen parameters and set them */
	miracl* mip=get_mip();
	time_t seed;
	time(&seed);
	irand((long)seed);
	Big order=pfc->order();
	aoen = new AOENoise(n,pfc,mip,order);
	inputFile >> aoen->aoe->omega; inputFile >> aoen->aoe->ab1[0]; inputFile >> aoen->aoe->ab1[1];
	inputFile >> aoen->aoe->ab2[0]; inputFile >> aoen->aoe->ab2[1]; inputFile >> aoen->aoe->g; inputFile >> aoen->aoe->g2;
	aoen->aoe->oe = new OE(l+1,pfc,mip,order);

	/* Get msks parameters and set them */
	msks = new OEMsk*[n+1];
	/* First key paramters */
	OEBMsk ***bmsk = new OEBMsk**[l+1];
	Big w1,w2,f1,f2;
	for(int i=0;i<l+1;i++){
		bmsk[i] = new OEBMsk*[2];
		inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
		bmsk[i][0] = new OEBMsk(w1,w2,f1,f2);
		inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
		bmsk[i][1] = new OEBMsk(w1,w2,f1,f2);
	}
	msks[0] = new OEMsk(aoen->aoe->g,aoen->aoe->g2,aoen->aoe->omega,aoen->aoe->ab1,aoen->aoe->ab2,bmsk);
	/* All others n keys paramters */
	for(int j=1;j<n+1;j++){
		OEBMsk ***bmsk = new OEBMsk**[k+1];
		for(int i=0;i<k+1;i++){
			bmsk[i] = new OEBMsk*[2];
			inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
			bmsk[i][0] = new OEBMsk(w1,w2,f1,f2);
			inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
			bmsk[i][1] = new OEBMsk(w1,w2,f1,f2);
		}
		msks[j] = new OEMsk(aoen->aoe->g,aoen->aoe->g2,aoen->aoe->omega,aoen->aoe->ab1,aoen->aoe->ab2,bmsk);
	}

	inputFile.close();
	return true;
}

vector<string> &
split(const string &s, char delim, vector<string> &elems) {
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

/**
 * Split s by delim.
 * Return a vector with all the resulting strings.
 */
vector<string>
split(const string &s, char delim) {
    vector<string> elems;
    split(s, delim, elems);
    return elems;
}

/**
 * Get an entire row and the number of columns.
 * If the row has the correct length return it in array with a column in every cell.
 */
string *
SecureSelect::create_row(string line, int len)
{
	vector<string> cells = split(line,'#');
	
	/** Row length check */
	if(len!=cells.size()){
		cout << "Incorrect row length" << endl;
		return NULL;
	}

	string *row = new string[len];
	for(int i=0;i<len;i++){
		row[i] = cells.at(i);
	}
	return row;
}

/**
 * Write the ciphertexts for a row in outputFile.
 */
void
SecureSelect::save_cts(ofstream *outputFile, OECt **cts)
{

	(*outputFile) << n << endl;
	(*outputFile) << l << endl;
	(*outputFile) << k << endl;

	OECt *t;
	/** Save ciphertext of length l(+1) */
	t = cts[0];
	(*outputFile) << t->A << endl << t->B << endl;
	for(int i=0;i<l+1;i++){
		(*outputFile) << t->ct[i][0]->ct1 << endl << t->ct[i][0]->ct2 << endl;
		(*outputFile) << t->ct[i][1]->ct1 << endl << t->ct[i][1]->ct2 << endl;
	}
	(*outputFile) << t->C << endl;

	/** Save ciphertexts of length k(+1) */
	for(int i=1;i<n+1;i++){
		t = cts[i];
		(*outputFile) << t->A << endl << t->B << endl;
		for(int j=0;j<k+1;j++){
			(*outputFile) << t->ct[j][0]->ct1 << endl << t->ct[j][0]->ct2 << endl;
			(*outputFile) << t->ct[j][1]->ct1 << endl << t->ct[j][1]->ct2 << endl;
		}
		(*outputFile) << t->C << endl;
	}

}

/**
 * Put the ciphertexts for a row in a string.
 */
string
SecureSelect::string_cts(OECt **cts)
{
	stringstream ct;

	ct << n << endl;
	ct << l << endl;
	ct << k << endl;

	OECt *t;
	/** Save ciphertext of length l(+1) */
	t = cts[0];
	ct << t->A << endl << t->B << endl;
	for(int i=0;i<l+1;i++){
		ct << t->ct[i][0]->ct1 << endl << t->ct[i][0]->ct2 << endl;
		ct << t->ct[i][1]->ct1 << endl << t->ct[i][1]->ct2 << endl;
	}
	ct << t->C << endl;

	/** Save ciphertexts of length k(+1) */
	for(int i=1;i<n+1;i++){
		t = cts[i];
		ct << t->A << endl << t->B << endl;
		for(int j=0;j<k+1;j++){
			ct << t->ct[j][0]->ct1 << endl << t->ct[j][0]->ct2 << endl;
			ct << t->ct[j][1]->ct1 << endl << t->ct[j][1]->ct2 << endl;
		}
		ct << t->C << endl;
	}

	return ct.str();
}

/**
 * Create and return the sha256 for str.
 */
string
SecureSelect::stdsha256(const string str)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);

	string tmp((const char*)hash);
	return tmp;
}

/**
 * Encode Msg with base64_encode,
 * write the result at the end of file fname.
 */
void
SecureSelect::append_enc_cell_file(string fname, const unsigned char *Msg, int elength)
{
	ofstream outputFile;
	outputFile.open(fname, ios::app);
	string encoded = base64_encode(Msg,elength);
	outputFile << encoded << endl;
	outputFile.close();	
}

/**
 * Create an aes 128bit key from M,
 * extend Msg and encrypt the resulting string by using aes_cbc from openssl library,
 * append the result at the end of file fname.
 */
void
SecureSelect::encMsg(GT M, string Msg, string fname)
{
	char aes_key_char[128/8];

	// original method
//	Big aes_key_big = pfc->hash_to_aes_key(M);
//	aes_key_char << aes_key_big;

	// to use when 'hash_to_aes_key' gives segmentation fault
	stringstream ss; ss << M;
	string s = ss.str().substr(6,16);
	for (int i=0;i<16;i++) aes_key_char[i] = s[i];

	/** Encrypt using openssl cbc */
	/** init vector */
	unsigned char iv_enc[AES_BLOCK_SIZE];
	for(int i=0;i<AES_BLOCK_SIZE;i++)
		iv_enc[i]=0;

	/** Create sha256 for Msg and add first 128 bit at the end of it */
	string sha = stdsha256(Msg);
	sha = base64_encode((const unsigned char*)sha.c_str(),sha.size());
	sha = sha.substr(0,16);
	Msg = Msg+sha;

	size_t inputslength = Msg.size();
	const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char enc_out[encslength];
	memset(enc_out, 0, sizeof(enc_out));

	/** Execute aes-cbc-128 */
	AES_KEY enc_key;
	AES_set_encrypt_key((const unsigned char *)aes_key_char, 128, &enc_key);
	AES_cbc_encrypt((const unsigned char *)Msg.c_str(), enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);

	append_enc_cell_file(fname,enc_out, encslength);

}

string
SecureSelect::encMsg(GT M, string Msg)
{
	char aes_key_char[128/8];

	// original method
//	Big aes_key_big = pfc->hash_to_aes_key(M);
//	aes_key_char << aes_key_big;

	// to use when 'hash_to_aes_key' gives segmentation fault
	stringstream ss; ss << M;
	string s = ss.str().substr(6,16);
	for (int i=0;i<16;i++) aes_key_char[i] = s[i];

	/** Encrypt using openssl cbc */
	/** init vector */
	unsigned char iv_enc[AES_BLOCK_SIZE];
	for(int i=0;i<AES_BLOCK_SIZE;i++)
		iv_enc[i]=0;

	/** Create sha256 for Msg and add first 128 bit at the end of it */
	string sha = stdsha256(Msg);
	sha = base64_encode((const unsigned char*)sha.c_str(),sha.size());
	sha = sha.substr(0,16);
	Msg = Msg+sha;

	size_t inputslength = Msg.size();
	const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char enc_out[encslength];
	memset(enc_out, 0, sizeof(enc_out));

	/** Execute aes-cbc-128 */
	AES_KEY enc_key;
	AES_set_encrypt_key((const unsigned char *)aes_key_char, 128, &enc_key);
	AES_cbc_encrypt((const unsigned char *)Msg.c_str(), enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);

	return base64_encode(enc_out,encslength);

}

/**
 * Get the name of the file that contains one or more rows (rows_name),
 * the name of the file in which the encrypted rows will be written (enctable_name)
 * and rand_lim, that is the maximum limit for the noise parameter.
 *
 * Encrypt every row, write ciphertexts and encrypted cells in different files.
 *
 */
void
SecureSelect::EncryptRows(string rows_name, string enctable_name, int rand_lim){

	/* Check if rows file exists */
	if (!ifstream(rows_name)){
		cout << "Rows file doesn't exist" << endl;
		return;
	}

	fstream inputFile(rows_name);
	string line, *row, cell;
	hash<string> hash_fn;
	size_t str_hash;
	Big X0[n];
	OECt **cts;
	GT M[n];
	G1 tmpg1;
	G2 tmpg2;
	
	/* Set encrypted rows file name */
	string rows_enc_msgs = enctable_name+"_enc_msgs";

	/* Set ciphertexts file name */
	string rows_enc_ct = enctable_name+"_enc_ct";

	ofstream rows_cts;
	rows_cts.open(rows_enc_ct, ios::app);
	/* Read file row by row */
	int row_num=0;
	while (getline(inputFile, line)){
		row=create_row(line,n);

		if(row!=NULL){
			/* Create X0 attribute */
			for(int i=0;i<n;i++){
				cell = row[i];
		   		str_hash = hash_fn(cell);
				X0[i]=str_hash;
			}
			/* Create n M keys (random) to use as aes key, encrypt and store the row */
			for(int i=0;i<n;i++){
				pfc->random(tmpg1); pfc->random(tmpg2);
				M[i] = pfc->pairing(tmpg2,tmpg1);
				encMsg(M[i],row[i],rows_enc_msgs);
			}
			/* Encrypt the n keys and write them in the file */
			#ifdef VERBOSE
			cout << "\tEncrypting row " << row_num+1 << " with n=" << n << endl;
			int start = getMilliCount();
			#endif
			cts = aoen->EncryptRow(msks,X0,M, rand_lim);
			#ifdef VERBOSE
			int milliSecondsElapsed = getMilliSpan(start);
			cout << "\tEncrypting row time: " << milliSecondsElapsed << endl;
			#endif
			
			save_cts(&rows_cts, cts);

			row_num++;
		}
		else
			return;
	}
	rows_cts.close();
	inputFile.close();
}

/**
 * Load the ciphertext for a row stored in inputFile,
 * return the loaded ciphertext.
 */
OECt **
SecureSelect::load_ct(ifstream *inputFile){

	OECt **cts = new OECt*[n+1];

	int n_,l_,k_;
	(*inputFile) >> l_; (*inputFile) >> k_;

	/** Load ciphertext of length l(+1) */
	G1 A,B;
	OEBCt ***bct = new OEBCt**[l+1];
	G1 bct1,bct2;
	GT C;

	(*inputFile) >> A;
	(*inputFile) >> B;
	for(int i=0;i<l+1;i++){
		bct[i] = new OEBCt*[2];
		(*inputFile) >> bct1; (*inputFile) >> bct2;
		bct[i][0] = new OEBCt(bct1,bct2);
		(*inputFile) >> bct1; (*inputFile) >> bct2;
		bct[i][1] = new OEBCt(bct1,bct2);
	}
	(*inputFile) >> C;

	cts[0] = new OECt(A,B,bct,C);

	/** Load ciphertexts of length k(+1) */
	for(int j=1;j<n+1;j++){
		bct = new OEBCt**[k+1];
		(*inputFile) >> A;
		(*inputFile) >> B;
		for(int i=0;i<k+1;i++){
			bct[i] = new OEBCt*[2];
			(*inputFile) >> bct1; (*inputFile) >> bct2;
			bct[i][0] = new OEBCt(bct1,bct2);
			(*inputFile) >> bct1; (*inputFile) >> bct2;
			bct[i][1] = new OEBCt(bct1,bct2);
		}
		(*inputFile) >> C;

		cts[j] = new OECt(A,B,bct,C);
	}

	return cts;
}

/**
 * Load the ciphertext for the row number row_num stored in inputFile,
 * return the loaded ciphertext.
 */
OECt **
SecureSelect::load_ct(fstream *inputFile, int row_num){

	OECt **cts = new OECt*[n+1];

	int cts_size = 10+(l*4)+(4*n*k)+(7*n);
	GotoLine(*inputFile, (row_num*(cts_size)));

	int n_,l_,k_;
	(*inputFile) >> n_;
	(*inputFile) >> l_; (*inputFile) >> k_;

	/** Load ciphertext of length l(+1) */
	G1 A,B;
	OEBCt ***bct = new OEBCt**[l+1];
	G1 bct1,bct2;
	GT C;

	(*inputFile) >> A;
	(*inputFile) >> B;
	for(int i=0;i<l+1;i++){
		bct[i] = new OEBCt*[2];
		(*inputFile) >> bct1; (*inputFile) >> bct2;
		bct[i][0] = new OEBCt(bct1,bct2);
		(*inputFile) >> bct1; (*inputFile) >> bct2;
		bct[i][1] = new OEBCt(bct1,bct2);
	}
	(*inputFile) >> C;

	cts[0] = new OECt(A,B,bct,C);

	/** Load ciphertexts of length k(+1) */
	for(int j=1;j<n+1;j++){
		bct = new OEBCt**[k+1];
		(*inputFile) >> A;
		(*inputFile) >> B;
		for(int i=0;i<k+1;i++){
			bct[i] = new OEBCt*[2];
			(*inputFile) >> bct1; (*inputFile) >> bct2;
			bct[i][0] = new OEBCt(bct1,bct2);
			(*inputFile) >> bct1; (*inputFile) >> bct2;
			bct[i][1] = new OEBCt(bct1,bct2);
		}
		(*inputFile) >> C;

		cts[j] = new OECt(A,B,bct,C);
	}

	return cts;
}

/**
 * Load the ciphertext for a row passed by s_cts,
 * return the loaded ciphertext.
 */
OECt **
SecureSelect::load_ct(string s_cts){

	OECt **cts = new OECt*[n+1];

	stringstream ss; ss << s_cts;
	
	int n_,l_,k_;
	ss >> n_;
	ss >> l_; ss >> k_;

	/** Load ciphertext of length l(+1) */
	G1 A,B;
	OEBCt ***bct = new OEBCt**[l+1];
	G1 bct1,bct2;
	GT C;

	ss >> A;
	ss >> B;
	for(int i=0;i<l+1;i++){
		bct[i] = new OEBCt*[2];
		ss >> bct1; ss >> bct2;
		bct[i][0] = new OEBCt(bct1,bct2);
		ss >> bct1; ss >> bct2;
		bct[i][1] = new OEBCt(bct1,bct2);
	}
	ss >> C;

	cts[0] = new OECt(A,B,bct,C);

	/** Load ciphertexts of length k(+1) */
	for(int j=1;j<n+1;j++){
		bct = new OEBCt**[k+1];
		ss >> A;
		ss >> B;
		for(int i=0;i<k+1;i++){
			bct[i] = new OEBCt*[2];
			ss >> bct1; ss >> bct2;
			bct[i][0] = new OEBCt(bct1,bct2);
			ss >> bct1; ss >> bct2;
			bct[i][1] = new OEBCt(bct1,bct2);
		}
		ss >> C;

		cts[j] = new OECt(A,B,bct,C);
	}

	return cts;
}

/**
 * Get a query file name,
 * read the first line of the file, that contains the select parameters,
 * split the line and return it.
 */
vector<string>
SecureSelect::get_select_params(string fname)
{
	fstream inputFile(fname);
	string line;
	
	/** The first line contains column numbers to select */
	getline(inputFile,line);
	vector<string> sel_params = split(line,'#');

	inputFile.close();
	return sel_params;
}

/**
 * From the query file name fname read each line and
 * create the attribute useful for token generation.
 *
 * Return the created attribute Y.
 */
Big *
SecureSelect::create_query_attribute(string fname){

	Big *Y = new Big[n];
	fstream inputFile(fname);
	string line;

	/** The first line contains colum numbers to select (already loaded) */
	getline(inputFile,line);

	hash<string> hash_fn;
	size_t str_hash;
	/** These are the 'where' parameters */
	for(int i=0;i<n;i++){
		getline(inputFile,line);
		if(inputFile.eof()&&i<n-1){
			cout << "Query doesn't respect row size" << endl;
			return NULL;
		}
		if(line.size()>0){
		   	str_hash = hash_fn(line);
			Y[i]=str_hash;
		}
		else
			Y[i] = 0;
	}

	inputFile.close();
	return Y;
}

fstream&
SecureSelect::GotoLine(fstream& file, unsigned int num)
{
    file.seekg(std::ios::beg);
    for(int i=0; i < num; ++i){
        file.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    return file;
}

ifstream&
SecureSelect::GotoLine(ifstream& file, unsigned int num)
{
    file.seekg(std::ios::beg);
    for(int i=0; i < num; ++i){
        file.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    return file;
}

/**
 * Read and return line number lnum from file fname.
 */
string
SecureSelect::read_line_from_file(int lnum, string fname)
{
	string line;
	fstream inputFile(fname);
	GotoLine(inputFile, lnum);
	getline(inputFile,line);
	inputFile.close();

	return line;
}

/**
 * Get an aes key (M) and a message (Msg),
 * retrieve the real key from M and decrypt Msg.
 *
 * Return the decryption result if the sha256 from Msg conicide with the original one, an empty string othewise.
 */
string
SecureSelect::decMsg(GT M, string Msg){

	char aes_key_char[128/8];

	// original method
//	Big aes_key_big = pfc->hash_to_aes_key(M);
//	aes_key_char << aes_key_big;

	// to use when 'hash_to_aes_key' gives segmentation fault
	stringstream ss; ss << M;
	string s = ss.str().substr(6,16);
	for (int i=0;i<16;i++) aes_key_char[i] = s[i];

	/** Decrypt using openssl */
	/* init vector */
	unsigned char iv_dec[AES_BLOCK_SIZE];
	for(int i=0;i<AES_BLOCK_SIZE;i++)
		iv_dec[i]=0;

	const size_t encslength = Msg.size();
	size_t inputslength = ((encslength/AES_BLOCK_SIZE)*AES_BLOCK_SIZE)-AES_BLOCK_SIZE;
	unsigned char *dec_out = new unsigned char[encslength];
	memset(dec_out, 0, sizeof(dec_out));

	AES_KEY dec_key;
	AES_set_decrypt_key((const unsigned char *)aes_key_char, 128, &dec_key);
	AES_cbc_encrypt((const unsigned char *)Msg.c_str(), dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);

	/** Check with sha256 if the decryption were good */
	string sha_msg((const char *)dec_out);
	delete dec_out;
	int sm_size = sha_msg.size();
	if(sm_size<16)
		return "";
	string original_sha = sha_msg.substr(sm_size-16,16);
	string dec_msg = sha_msg.substr(0,sm_size-16);
	string new_sha = stdsha256(dec_msg);
	new_sha = base64_encode((const unsigned char*)new_sha.c_str(),new_sha.size());
	new_sha = new_sha.substr(0,16);
	if(original_sha.compare(new_sha)==0)
		return dec_msg;
	else
		return "";
}

/**
 * Write key of length len in fname.
 */
void
SecureSelect::save_token(OEKey *key, string fname, int len, int cell){

	ofstream outputFile;
	outputFile.open(fname);

	if(cell==0)
		outputFile << n << endl;
	else
		outputFile << cell << endl;

	outputFile << key->KA << endl;
	outputFile << key->KB << endl;

	for(int i=0;i<len;i++){
		outputFile << key->key[i][0]->k1 << endl; outputFile << key->key[i][0]->k2 << endl;
		outputFile << key->key[i][1]->k1 << endl; outputFile << key->key[i][1]->k2 << endl;
	}

	outputFile.close();
}

/**
 * Write key of length len in a string and return it.
 */
string
SecureSelect::string_token(OEKey *key, int len){

	stringstream outputString;

	outputString << key->KA << endl;
	outputString << key->KB << endl;

	for(int i=0;i<len;i++){
		outputString << key->key[i][0]->k1 << endl; outputString << key->key[i][0]->k2 << endl;
		outputString << key->key[i][1]->k1 << endl; outputString << key->key[i][1]->k2 << endl;
	}

	return outputString.str();
}

/**
 * Retrieve key of lenght len from string.
 */
OEKey *
SecureSelect::token_from_string(string skey, int len){

	OEKey *key;
	stringstream inputString(skey);

	G2 KA, KB, k1, k2;
	OEBKey ***bk = new OEBKey**[len];

	inputString >> KA;
	inputString >> KB;

	for(int i=0;i<len;i++){
		bk[i] = new OEBKey*[2];

		inputString >> k1; inputString >> k2;
		bk[i][0] = new OEBKey(k1,k2);

		inputString >> k1; inputString >> k2;
		bk[i][1] = new OEBKey(k1,k2);
	}

	key = new OEKey(KA,KB,bk);

	return key;
}

/**
 * Get a query file name (query_name) and rand_lim.
 *
 * Generate a predicate token and a message token for every select parameters.
 *
 * Save the created tokens in files.
 */
int
SecureSelect::GenToken(string query_name, int rand_lim){

	/* Get column numbers to select */
	vector<string> sel_params = get_select_params(query_name);
	if(sel_params.size()==0){
		cout << "No select parameters found" << endl;
		return 0;
	}

	/* Create attribute from the query */
	Big *Y = create_query_attribute(query_name);
	if(Y==NULL)
		return 0;

	OEKey *pkey;
	OEKey **mkey;

	#ifdef VERBOSE
	int start = getMilliCount();
	#endif

	/* Predicate key generation */
	pkey = aoen->PKeyGen(msks,Y,rand_lim);

	#ifdef VERBOSE
	int milliSecondsElapsed = getMilliSpan(start);
	cout << "\tPredicate key generation time: " << milliSecondsElapsed << endl;
	#endif

	/* Message keys generation */
	int j;
	for(int i=0;i<sel_params.size();i++){
		istringstream(sel_params.at(i)) >> j;
		if(!(j>=1 && j<=n)){
			cout << "Cell" << j << " doesn't exist (there are " << n << " cells)" << endl;
			return 0;
		}
	}
	
	#ifdef VERBOSE
	start = getMilliCount();
	#endif
	
	mkey = aoen->MKeyGen(msks,Y,sel_params,0);
	
	#ifdef VERBOSE
	milliSecondsElapsed = getMilliSpan(start);
	cout << "\tMessage keys generation time: " << milliSecondsElapsed << endl;
	#endif

	string ptok_file = query_name+"_ptok";
	string mtok_file = query_name+"_mtok";

	int query_num = 0;
	stringstream ss;
	ss << mtok_file << query_num;
	string res = ss.str();

	save_token(pkey, ptok_file, l+1, 0);
	save_token(mkey[0],mtok_file+"_l",l+1,0);
	for(int i=1;i<sel_params.size()+1;i++){
		istringstream(sel_params.at(i-1)) >> j;
		save_token(mkey[i],res+"_k",k+1,j);

		query_num++;
		stringstream ss;
		ss << mtok_file << query_num;
		res = ss.str();
	}

	return 1;
}

/**
 * Initialise length and curve parameters.
 */
void
SecureSelect::set_parameters(string fname){

	fstream inputFile(fname);
	string line;
	
	/** The first line contains the number of columns */
	inputFile >> n;
	l = n*2+2;
	k = 2;

	miracl* mip=get_mip();
	time_t seed;
	time(&seed);
	irand((long)seed);
	Big order=pfc->order();
	aoen = new AOENoise(n,pfc,mip,order);
	aoen->aoe->oe = new OE(l+1,pfc,mip,order);

	inputFile.close();
}

/**
 * Read token stored in fname and return it.
 */
OEKey *
SecureSelect::load_token(string fname, int len){

	OEKey *key;
	ifstream inputFile(fname);

	int n;
	G2 KA, KB, k1, k2;
	OEBKey ***bk = new OEBKey**[len];

	inputFile >> n;
	inputFile >> KA;
	inputFile >> KB;

	for(int i=0;i<len;i++){
		bk[i] = new OEBKey*[2];

		inputFile >> k1; inputFile >> k2;
		bk[i][0] = new OEBKey(k1,k2);

		inputFile >> k1; inputFile >> k2;
		bk[i][1] = new OEBKey(k1,k2);
	}

	key = new OEKey(KA,KB,bk);

	inputFile.close();
	return key;
}

/**
 * Read token stored in fname and return it.
 * The last parameter is the column for whom the token was generated.
 */
OEKey *
SecureSelect::load_token(string fname, int len, vector<int> &sel_par){

	OEKey *key;
	ifstream inputFile(fname);

	int n;
	G2 KA, KB, k1, k2;
	OEBKey ***bk = new OEBKey**[len];

	inputFile >> n;
	sel_par.push_back(n);
	inputFile >> KA;
	inputFile >> KB;

	for(int i=0;i<len;i++){
		bk[i] = new OEBKey*[2];

		inputFile >> k1; inputFile >> k2;
		bk[i][0] = new OEBKey(k1,k2);

		inputFile >> k1; inputFile >> k2;
		bk[i][1] = new OEBKey(k1,k2);
	}

	key = new OEKey(KA,KB,bk);

	inputFile.close();
	return key;
}

/**
 * Get a token file name (query_name) and the database name (db_name).
 *
 * Execute the query for the desiderd database
 * and return all the founded results in a vector.
 */
vector<string>
SecureSelect::ApplyToken(string query_name,string db_name){

	vector<int> sel_params;

	set_parameters(query_name+"_ptok");

	vector<string> results;

	/* Set name for ciphertexts and messages in db */
	string db_enc_ct = db_name+"_enc_ct";
	int row_num=0;

	OECt **cts;
	GT r;
	string db_enc_msgs = db_name+"_enc_msgs";
	string encoded,decoded;

	/* Predicate key loading */
	OEKey *pkey;
	pkey = load_token(query_name+"_ptok", l+1);

	/* Enumerate the message keys */
	string mtok = query_name+"_mtok";
	int tok_num=0;
	stringstream ss2;
	ss2 << mtok << tok_num << "_k";
	string tok_res = ss2.str();
	while(ifstream(tok_res)){
		tok_num++;
		stringstream ss;
		ss << mtok << tok_num << "_k";
		tok_res = ss.str();
	}

	/* Message keys loading */
	OEKey **mkey[tok_num];

	OEKey *mkey_l = load_token(mtok+"_l", l+1);

	for(int i=0;i<tok_num;i++){
		stringstream ss;
		ss << mtok << i;
		string tok_res = ss.str();

		mkey[i] = new OEKey*[2];
		mkey[i][0] = mkey_l;
		mkey[i][1] = load_token(tok_res+"_k", k+1, sel_params);
	}

	ifstream db_cts(db_enc_ct);
	int n_;
	while(db_cts >> n_){
		if(n!=n_){
			cout << "Db's parameters different from key's" << endl;
			return results;
		}

		cts = load_ct(&db_cts);
		if(cts==NULL) return results;

		#ifdef VERBOSE
		int start = getMilliCount();
		#endif

		r = aoen->aoe->PDecrypt(cts[0],pkey);

		#ifdef VERBOSE
		int milliSecondsElapsed = getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		if(r==(GT)1){ /* Row match query */
			/* Decryption for every element in sel_params */
			for(int i=0;i<tok_num;i++){
				#ifdef VERBOSE
				start = getMilliCount();
				#endif

				r = aoen->aoe->MDecrypt(cts,mkey[i],sel_params.at(i));

				#ifdef VERBOSE
				milliSecondsElapsed = getMilliSpan(start);
				cout << "\tMessage decryption time: " << milliSecondsElapsed << endl;
				#endif

				encoded = read_line_from_file(sel_params.at(i)-1+(row_num*n),db_enc_msgs);
				decoded = base64_decode(encoded);
				string tmp = decMsg(r, decoded);

				if(tmp.compare("")!=0) results.push_back(tmp);
			}
		}

		row_num++;

	}
	db_cts.close();

	return results;
}

/**
 * Get a token file name (query_name), the database name (db_name) and the results name (res_name).
 *
 * Execute the ptoken for the desiderd database
 * and save the number of all the founded rows in a file (res_name).
 */
int
SecureSelect::ApplyPToken(string query_name,string db_name, string res_name){

	set_parameters(query_name+"_ptok");

	/* Set name for ciphertexts and messages in db */
	string db_enc_ct = db_name+"_enc_ct";
	int row_num=0;

	OECt **cts;
	GT dec_res;
	string db_enc_msgs = db_name+"_enc_msgs";
	string encoded,decoded;

	/* Predicate key loading */
	OEKey *pkey;
	pkey = load_token(query_name+"_ptok", l+1);

	ifstream db_cts(db_enc_ct);
	int n_, res_num=0;
	ofstream results;
	results.open(res_name);
	while(db_cts >> n_){
		if(n!=n_){
			cout << "Db's parameters different from key's" << endl;
			return -1;
		}

		cts = load_ct(&db_cts);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			return -1;
		}

		#ifdef VERBOSE
		int start = getMilliCount();
		#endif

		dec_res = aoen->aoe->PDecrypt(cts[0],pkey);

		#ifdef VERBOSE
		int milliSecondsElapsed = getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		if(dec_res==(GT)1){ /* Row match query */
			results << row_num << endl;
			res_num++;
		}

		row_num++;

	}
	results.close();
	db_cts.close();

	return res_num;
}

/**
 * Get a token file name (query_name), the database name (db_name) and the results name (res_name).
 *
 * Execute the mtoken for all the rows in res_name
 * and return all the founded results in a vector.
 */
vector<string>
SecureSelect::ApplyMToken(string query_name,string db_name, string res_name){

	vector<int> sel_params;
	vector<string> results;
	OECt **cts;
	GT dec_key;
	string encoded,decoded;

	set_parameters(query_name+"_mtok_l");

	/* Set name for ciphertexts and messages in db */
	string db_enc_ct = db_name+"_enc_ct";
	string db_enc_msgs = db_name+"_enc_msgs";

	/* Enumerate the message keys */
	string mtok = query_name+"_mtok";
	int tok_num=0;
	stringstream ss2;
	ss2 << mtok << tok_num << "_k";
	string tok_res = ss2.str();
	while(ifstream(tok_res)){
		tok_num++;
		stringstream ss;
		ss << mtok << tok_num << "_k";
		tok_res = ss.str();
	}

	/* Message keys loading */
	OEKey **mkey[tok_num];

	OEKey *mkey_l = load_token(mtok+"_l", l+1);

	for(int i=0;i<tok_num;i++){
		stringstream ss;
		ss << mtok << i;
		string tok_res = ss.str();

		mkey[i] = new OEKey*[2];
		mkey[i][0] = mkey_l;
		mkey[i][1] = load_token(tok_res+"_k", k+1, sel_params);
	}

	ifstream res_file(res_name);
	int row_num;
	fstream db_cts(db_enc_ct);
	while(res_file >> row_num){
		cts = load_ct(&db_cts, row_num);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			return results;
		}

		/* Decryption for every element in sel_params */
		for(int i=0;i<tok_num;i++){
			#ifdef VERBOSE
			int start = getMilliCount();
			#endif

			dec_key = aoen->aoe->MDecrypt(cts,mkey[i],sel_params.at(i));

			#ifdef VERBOSE
			int milliSecondsElapsed = getMilliSpan(start);
			cout << "\tMessage decryption time: " << milliSecondsElapsed << endl;
			#endif

			encoded = read_line_from_file(sel_params.at(i)-1+(row_num*n),db_enc_msgs);
			decoded = base64_decode(encoded);
			string tmp = decMsg(dec_key, decoded);

			if(tmp.compare("")!=0) results.push_back(tmp);
		}
	}
	db_cts.close();
	res_file.close();
	return results;
}

struct thread_data{
	int  thread_id;
	int num_threads;
	int num_lines;
	string rows_name;
	string db_enc_ct;
	string db_enc_msgs;
	vector<int> sel_params;
	vector<string>sel_par;
	int tok_num;
	string res_name;
	OEMsk **msks;
	int rand_lim;
	OEKey *pkey;
	OEKey ***mkey;
	OEKey **mkey2;
	SecureSelect *sec_sel;
	vector<string> results;
	pthread_t to_wait_thread;
	vector<int> *res_oids;
	vector<int> to_delete;
	string table_name;
	PGconn *conn;
	string host;
};

void *encryptRowsThread(void *threadarg)
{
	PFC pfc(AES_SECURITY);
	OECt ** ct;
	int err = -1, ok = 1;
	struct thread_data *my_data;

	my_data = (struct thread_data *) threadarg;
	int tid = my_data->thread_id;
	int n = my_data->sec_sel->n;

	int starting_row = ((my_data->num_lines/my_data->num_threads)*tid);
	string line, *row, cell;
	hash<string> hash_fn;
	size_t str_hash;
	Big X0[n];
	GT M[n];
	G1 tmpg1;
	G2 tmpg2;

	ifstream rows(my_data->rows_name);
	int n_, row_num=starting_row;
	int l=2*n+2, k=2;
	my_data->sec_sel->GotoLine(rows, starting_row);

	AOENoise *aoen = new AOENoise(n,&pfc,get_mip(),pfc.order());
	aoen->aoe->omega = my_data->sec_sel->aoen->aoe->omega;
	aoen->aoe->ab1[0] = my_data->sec_sel->aoen->aoe->ab1[0]; aoen->aoe->ab1[1] = my_data->sec_sel->aoen->aoe->ab1[1];
	aoen->aoe->ab2[0] = my_data->sec_sel->aoen->aoe->ab2[0]; aoen->aoe->ab2[1] = my_data->sec_sel->aoen->aoe->ab2[1];
	aoen->aoe->g = my_data->sec_sel->aoen->aoe->g; aoen->aoe->g2 = my_data->sec_sel->aoen->aoe->g2;
	aoen->aoe->oe = new OE(l+1,&pfc,get_mip(),pfc.order());

	string ct_t = my_data->db_enc_ct;
	string msgs_t = my_data->db_enc_msgs;
	ct_t = ct_t+to_string(tid);
	msgs_t = msgs_t+to_string(tid);
	ofstream rec(ct_t);
	ofstream rem(msgs_t);
	/* Read file row by row */
	for(int i=0;i<(my_data->num_lines/my_data->num_threads);i++){
		getline(rows, line);
		row=my_data->sec_sel->create_row(line,n);

		if(row!=NULL){
			/* Create X0 attribute */
			for(int j=0;j<n;j++){
				cell = row[j];
		   		str_hash = hash_fn(cell);
				X0[j]=str_hash;
			}
			/* Create n M keys (random) to use as aes key, encrypt and store the row */
			for(int j=0;j<n;j++){
				pfc.random(tmpg1); pfc.random(tmpg2);
				M[j] = pfc.pairing(tmpg2,tmpg1);
				rem << my_data->sec_sel->encMsg(M[j],row[j]) << endl;
			}
			/* Encrypt the n keys and write them in the file */
			#ifdef VERBOSE
			cout << "Thread id: " << tid << " Encrypting row " << row_num+1 << " with n=" << n << endl;
			int start = my_data->sec_sel->getMilliCount();
			#endif
			ct = aoen->EncryptRow(my_data->msks,X0,M, my_data->rand_lim);
			my_data->sec_sel->save_cts(&rec, ct);
			#ifdef VERBOSE
			int milliSecondsElapsed = my_data->sec_sel->getMilliSpan(start);
			cout << "Thread id: " << tid << " Encrypting row time: " << milliSecondsElapsed << endl;
			#endif
			my_data->sec_sel->delete_cts(ct);
			delete[] row;
			row_num++;
		}
		else{
			cout << "Error while reading a row" << endl;
			pthread_exit(&err);
		}
	}
	rows.close();
	rec.close();
	rem.close();

	delete aoen;
	pthread_exit(&ok);
}

void
SecureSelect::delete_cts(OECt **cts){
	for(int i=0;i<l+1;i++){
		delete cts[0]->ct[i][0];
		delete cts[0]->ct[i][1];
		delete cts[0]->ct[i];
	}
	delete cts[0]->ct;
	delete cts[0];
	for(int i=1;i<n+1;i++){
		for(int j=0;j<k+1;j++){
			delete cts[i]->ct[j][0];
			delete cts[i]->ct[j][1];
			delete cts[i]->ct[j];
		}
		delete cts[i]->ct;
		delete cts[i];
	}
	delete cts;
}

void
SecureSelect::delete_msk(OEMsk **msks){
	for(int i=0;i<l+1;i++){
		delete msks[0]->bmsk[i][0]; delete msks[0]->bmsk[i][1];
		delete msks[0]->bmsk[i];
	}
	delete msks[0]->bmsk;
	delete msks[0];
	for(int j=1;j<n+1;j++){
		for(int i=0;i<k+1;i++){
			delete msks[j]->bmsk[i][0]; delete msks[j]->bmsk[i][1];
			delete msks[j]->bmsk[i];
		}
		delete msks[j]->bmsk;
		delete msks[j];
	}
	delete msks;
}

/**
 * Multi-thread version of EncryptRows.
 *
 * num_threads is the number of threads in which the encryption will be divided.
 */
void
SecureSelect::EncryptRowsMT(string rows_name, string enctable_name, int rand_lim, int num_threads){

	/* Check if rows file exists */
	if (!ifstream(rows_name)){
		cout << "Rows file doesn't exist" << endl;
		return;
	}

	/* Counting the number of rows */
	fstream rows(rows_name);
	string line;
	int num_lines = 0;
	while(getline(rows,line))
		num_lines++;
	rows.close();
	int remaining_lines = num_lines%num_threads;
	num_lines = num_lines-remaining_lines;

	int rc;
	pthread_t threads[num_threads];
	pthread_attr_t attr;
	void *status;
	struct thread_data td[num_threads];

	/* Set encrypted rows file name */
	string rows_enc_msgs = enctable_name+"_enc_msgs";

	/* Set ciphertexts file name */
	string rows_enc_ct = enctable_name+"_enc_ct";

	/* Initialize and set thread joinable */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* Execute threads */
	for(int i=0;i<num_threads;i++){
		#ifdef VERBOSE
		cout << "EncryptRowsMT() : creating thread, " << i << endl;
		#endif

		td[i].thread_id = i;
		td[i].num_threads = num_threads;
		td[i].num_lines = num_lines;
		td[i].rows_name = rows_name;
		td[i].db_enc_ct = rows_enc_ct;
		td[i].db_enc_msgs = rows_enc_msgs;
		td[i].msks = msks;
		td[i].rand_lim = rand_lim;
		if(i>0) td[i].to_wait_thread = threads[i-1];
		td[i].sec_sel = this;
		rc = pthread_create(&threads[i], NULL, encryptRowsThread, (void *)&td[i] );
		if (rc){
			cout << "Error:unable to create thread," << rc << endl;
			return ;
		}
	}

	/* Free attribute and wait for threads results */
	pthread_attr_destroy(&attr);

	for(int i=0; i < num_threads; i++ ){
		rc = pthread_join(threads[i], &status);
		if (rc){
			cout << "Error:unable to join," << rc << endl;
			return ;
		}
		int err = *(int *) status;
		if(err == -1)
			return ;
	}

	/* Concatenate ciphertexts and messages in one single file respectively */
	string ct_tid, msgs_tid;
	ofstream rec(rows_enc_ct, ios::app);
	ofstream rem(rows_enc_msgs, ios::app);
	for(int i=0; i<num_threads; i++){
		ct_tid = rows_enc_ct+to_string(i);
		msgs_tid = rows_enc_msgs+to_string(i);
		ifstream ct_t(ct_tid);
		ifstream msgs_t(msgs_tid);
		rec << ct_t.rdbuf();
		rem << msgs_t.rdbuf();
		ct_t.close();
		msgs_t.close();
		remove(ct_tid.c_str());
		remove(msgs_tid.c_str());
	}
	rem.close();

	/* Encrypting reamining lines */
	if(remaining_lines>0){
		ifstream rows(rows_name);
		GotoLine(rows, num_lines);
		string *row, cell;
		OECt **cts;
		hash<string> hash_fn;
		size_t str_hash;
		Big X0[n];
		GT M[n];
		G1 tmpg1;
		G2 tmpg2;
		int row_num = num_lines;
		for(int i=0;i<remaining_lines;i++){
			getline(rows,line);
			row=create_row(line,n);

			if(row!=NULL){
				/* Create X0 attribute */
				for(int i=0;i<n;i++){
					cell = row[i];
			   		str_hash = hash_fn(cell);
					X0[i]=str_hash;
				}
				/* Create n M keys (random) to use as aes key, encrypt and store the row */
				for(int i=0;i<n;i++){
					pfc->random(tmpg1); pfc->random(tmpg2);
					M[i] = pfc->pairing(tmpg2,tmpg1);
					encMsg(M[i],row[i], rows_enc_msgs);
				}
				/* Encrypt the n keys and write them in the file */
				#ifdef VERBOSE
				cout << "\tEncrypting row " << row_num+1 << " with n=" << n << endl;
				int start = getMilliCount();
				#endif
				cts = aoen->EncryptRow(msks,X0,M, rand_lim);
				#ifdef VERBOSE
				int milliSecondsElapsed = getMilliSpan(start);
				cout << "\tEncrypting row time: " << milliSecondsElapsed << endl;
				#endif

				save_cts(&rec, cts);
				delete_cts(cts);
				delete[] row;
				row_num++;
			}
			else{
				cout << "Error while reading a row" << endl;
				return;
			}
		}
	}

	rec.close();
}

void *applyPTokenThread(void *threadarg)
{
	PFC pfc(AES_SECURITY);
	vector<int> *results = new vector<int>;
	int err = -1;
	struct thread_data *my_data;

	my_data = (struct thread_data *) threadarg;
	int tid = my_data->thread_id;

	int starting_row = ((my_data->num_lines/my_data->num_threads)*tid);
	OECt **cts;
	GT dec_res;

	int n = my_data->sec_sel->n;

	ifstream db_cts(my_data->db_enc_ct);
	int n_, row_num=starting_row;
	int l=2*n+2, k=2;
	my_data->sec_sel->GotoLine(db_cts, starting_row*(10+4*l+4*n*k+7*n));

	while(row_num<((my_data->num_lines/my_data->num_threads)*(tid+1))){
		db_cts >> n_;
		if(n!=n_){
			cout << "Db's parameters different from key's" << endl;
			
			pthread_exit(&err);
		}
		#ifdef VERBOSE
		cout << "Thread id: " << tid << " Row: " << row_num+1 << endl;
		#endif

		cts = my_data->sec_sel->load_ct(&db_cts);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			pthread_exit(&err);
		}

		#ifdef VERBOSE
		int start = my_data->sec_sel->getMilliCount();
		#endif

		dec_res = my_data->sec_sel->aoen->aoe->PDecrypt(cts[0],my_data->pkey);

		#ifdef VERBOSE
		int milliSecondsElapsed = my_data->sec_sel->getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		my_data->sec_sel->delete_cts(cts);
		if(dec_res==(GT)1) /* Row match query */
			results->push_back(row_num);

		row_num++;
	}
	db_cts.close();

	pthread_exit(results);
}

void
SecureSelect::delete_key(OEKey *key, int len){
	for(int i=0;i<len;i++){
		delete key->key[i][0];
		delete key->key[i][1];
		delete key->key[i];
	}
	delete key->key;
	delete key;
}

/**
 * Multi-thread version of ApplyPToken.
 *
 * num_threads is the number of threads in which the decryption will be divided.
 */
int
SecureSelect::ApplyPTokenMT(string query_name,string db_name, string res_name, int num_threads){

	set_parameters(query_name+"_ptok");

	/* Set name for ciphertexts in db */
	string db_enc_ct = db_name+"_enc_ct";
	int res_num = 0;

	/* Predicate key loading */
	OEKey *pkey;
	pkey = load_token(query_name+"_ptok", l+1);

	/* Counting number of rows in the db */
	ifstream db_enc_msgs(db_name+"_enc_msgs");
	string line;
	int num_lines = 0;
	while(getline(db_enc_msgs,line))
		num_lines++;
	db_enc_msgs.close();
	num_lines = num_lines/n;
	int remaining_lines = num_lines%num_threads;
	num_lines = num_lines-remaining_lines;

	int rc;
	pthread_t threads[num_threads];
	pthread_attr_t attr;
	void *status;
	struct thread_data td[num_threads];

	/* Initialize and set thread joinable */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* Execute threads */
	for(int i=0;i<num_threads;i++){
		#ifdef VERBOSE
		cout << "ApplyPTokenMT() : creating thread, " << i << endl;
		#endif

		td[i].thread_id = i;
		td[i].num_threads = num_threads;
		td[i].num_lines = num_lines;
		td[i].db_enc_ct = db_enc_ct;
		td[i].res_name = res_name;
		td[i].pkey = pkey;
		td[i].sec_sel = this;
		rc = pthread_create(&threads[i], NULL, applyPTokenThread, (void *)&td[i] );
		if (rc){
			cout << "Error:unable to create thread," << rc << endl;
			return -1;
		}
	}

	/* Free attribute and wait for threads results */
	ofstream results(res_name);
	pthread_attr_destroy(&attr);
	for(int i=0; i < num_threads; i++ ){
		rc = pthread_join(threads[i], &status);
		if (rc){
			cout << "Error:unable to join," << rc << endl;
			return -1;
		}
		int err = *(int *) status;
		if(err == -1)
			return -1;

		vector<int> *res_thread = (vector<int> *) status;
		res_num += res_thread->size();
		for(int j=0;j<res_thread->size();j++)
			results << res_thread->at(j) << endl;

		delete res_thread;
		#ifdef VERBOSE
		cout << "Main: completed thread id :" << i ;
		cout << "  exiting with " << res_thread->size() << " results" << endl;
		#endif
	}

	/* Apply ptoken on remaining lines */
	ifstream db_cts(db_enc_ct);
	GotoLine(db_cts, (num_lines)*(10+4*l+4*n*k+7*n));
	int n_;
	OECt **cts;
	GT dec_res;
	for(int i=0;i<remaining_lines;i++){
		db_cts >> n_;
		if(n!=n_){
			cout << "Db's parameters different from key's" << endl;
			
			return res_num;
		}
		#ifdef VERBOSE
		cout << "Thread id: Main Row: " << num_lines+1+i << endl;
		#endif

		cts = load_ct(&db_cts);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			return res_num;
		}

		#ifdef VERBOSE
		int start = getMilliCount();
		#endif

		dec_res = aoen->aoe->PDecrypt(cts[0],pkey);

		#ifdef VERBOSE
		int milliSecondsElapsed = getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		delete_cts(cts);

		if(dec_res==(GT)1){ /* Row match query */
			results << num_lines+i << endl;
			res_num++;
		}

	}
	db_cts.close();

	results.close();

	delete_key(pkey,l+1);

	return res_num;
}

void *applyMTokenThread(void *threadarg){
	PFC pfc(AES_SECURITY);
	vector<string> *results = new vector<string>;
	int err = -1;
	struct thread_data *my_data;

	my_data = (struct thread_data *) threadarg;
	int tid = my_data->thread_id;

	int starting_line = ((my_data->num_lines/my_data->num_threads)*tid);
	OECt **cts;
	GT dec_key;
	string encoded, decoded;

	ifstream res_file(my_data->res_name);
	my_data->sec_sel->GotoLine(res_file,starting_line);
	int line_num = starting_line;
	fstream db_cts(my_data->db_enc_ct);
	int row_num;
	while(line_num<((my_data->num_lines/my_data->num_threads)*(tid+1))){
		res_file >> row_num;
		cts = my_data->sec_sel->load_ct(&db_cts, row_num);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			pthread_exit(&err);
		}

		#ifdef VERBOSE
		cout << "Thread id: " << tid << " Row: " << row_num+1 << " Line: " << line_num+1 << endl;
		#endif

		/* Decryption for every element in sel_params */
		for(int i=0;i<my_data->tok_num;i++){
			#ifdef VERBOSE
			int start = my_data->sec_sel->getMilliCount();
			#endif

			dec_key = my_data->sec_sel->aoen->aoe->MDecrypt(cts,my_data->mkey[i],my_data->sel_params.at(i));

			#ifdef VERBOSE
			int milliSecondsElapsed = my_data->sec_sel->getMilliSpan(start);
			cout << "\tMessage decryption time: " << milliSecondsElapsed << endl;
			#endif

			encoded = my_data->sec_sel->read_line_from_file(my_data->sel_params.at(i)-1+(row_num*(my_data->sec_sel->n)),my_data->db_enc_msgs);
			decoded = base64_decode(encoded);
			string tmp = my_data->sec_sel->decMsg(dec_key, decoded);

			if(tmp.compare("")!=0)
				results->push_back(tmp);
		}
		line_num++;
		my_data->sec_sel->delete_cts(cts);
	}
	db_cts.close();
	res_file.close();

	pthread_exit(results);
}

/**
 * Multi-thread version of ApplyMToken.
 *
 * num_threads is the number of threads in which the decryption will be divided.
 */
vector<string>
SecureSelect::ApplyMTokenMT(string query_name,string db_name, string res_name, int num_threads){

	set_parameters(query_name+"_mtok_l");

	vector<int> sel_params;
	vector<string> results;
	string encoded,decoded;

	/* Set name for ciphertexts and messages in db */
	string db_enc_ct = db_name+"_enc_ct";
	string db_enc_msgs = db_name+"_enc_msgs";

	/* Enumerate the message keys */
	string mtok = query_name+"_mtok";
	int tok_num=0;
	stringstream ss2;
	ss2 << mtok << tok_num << "_k";
	string tok_res = ss2.str();
	while(ifstream(tok_res)){
		tok_num++;
		stringstream ss;
		ss << mtok << tok_num << "_k";
		tok_res = ss.str();
	}

	/* Message keys loading */
	OEKey **mkey[tok_num];

	OEKey *mkey_l = load_token(mtok+"_l", l+1);

	for(int i=0;i<tok_num;i++){
		stringstream ss;
		ss << mtok << i;
		string tok_res = ss.str();

		mkey[i] = new OEKey*[2];
		mkey[i][0] = mkey_l;
		mkey[i][1] = load_token(tok_res+"_k", k+1, sel_params);
	}

	/* Counting number of rows in the results file */
	ifstream res_f(res_name);
	string line;
	int num_res = 0;
	while(getline(res_f,line))
		num_res++;
	res_f.close();
	int remaining_res = num_res%num_threads;
	num_res = num_res-remaining_res;

	int rc;
	pthread_t threads[num_threads];
	pthread_attr_t attr;
	void *status;
	struct thread_data td[num_threads];

	// Initialize and set thread joinable
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* Execute threads */
	for(int i=0;i<num_threads;i++){
		#ifdef VERBOSE
		cout << "ApplyPTokenMT() : creating thread, " << i << endl;
		#endif

		td[i].thread_id = i;
		td[i].num_threads = num_threads;
		td[i].num_lines = num_res;
		td[i].db_enc_ct = db_enc_ct;
		td[i].db_enc_msgs = db_enc_msgs;
		td[i].sel_params = sel_params;
		td[i].tok_num = tok_num;
		td[i].res_name = res_name;
		td[i].mkey = mkey;
		td[i].sec_sel = this;
		rc = pthread_create(&threads[i], NULL, applyMTokenThread, (void *)&td[i] );
		if (rc){
			cout << "Error:unable to create thread," << rc << endl;
			return results;
		}
	}

	/* Free attribute and wait for threads results */
	pthread_attr_destroy(&attr);
	for(int i=0; i < num_threads; i++ ){
		rc = pthread_join(threads[i], &status);
		if (rc){
			cout << "Error:unable to join," << rc << endl;
			return results;
		}
		int err = *(int *) status;
		if(err == -1)
			return results;

		vector<string> *res_thread = (vector<string> *) status;
		results.insert(results.end(), res_thread->begin(), res_thread->end());

		delete res_thread;
		#ifdef VERBOSE
		cout << "Main: completed thread id :" << i ;
		cout << "  exiting with " << res_thread->size() << " results" << endl;
		#endif
	}

	/* Apply mtoken on remaining lines */
	fstream db_cts(db_enc_ct);
	ifstream res_file(res_name);
	GotoLine(res_file, num_res);
	OECt **cts;
	GT dec_key;
	int row_num;
	for(int j=0;j<remaining_res;j++){
		res_file >> row_num;

		cts = load_ct(&db_cts, row_num);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			return results;
		}

		#ifdef VERBOSE
		cout << "Thread id: Main Row: " << num_res+1+j << endl;
		#endif

		/* Decryption for every element in sel_params */
		for(int i=0;i<tok_num;i++){
			#ifdef VERBOSE
			int start = getMilliCount();
			#endif

			dec_key = aoen->aoe->MDecrypt(cts,mkey[i],sel_params.at(i));

			#ifdef VERBOSE
			int milliSecondsElapsed = getMilliSpan(start);
			cout << "\tMessage decryption time: " << milliSecondsElapsed << endl;
			#endif

			encoded = read_line_from_file(sel_params.at(i)-1+(row_num*n),db_enc_msgs);
			decoded = base64_decode(encoded);
			string tmp = decMsg(dec_key, decoded);

			if(tmp.compare("")!=0)
				results.push_back(tmp);
		}
		delete_cts(cts);
	}

	for(int i=0;i<tok_num;i++){
		delete_key(mkey[i][0], l+1);
		delete_key(mkey[i][1], k+1);
		delete mkey[i];
	}

	db_cts.close();
	res_file.close();

	return results;
}
















// PostgreSql wrapper methods

void
SecurePGconn::SecurePQconnectdb(const char *conninfo){
	conn = PQconnectdb(conninfo);
}

ConnStatusType
SecurePGconn::SecurePQstatus(){
	return PQstatus(conn);
}

char *
SecurePGconn::SecurePQerrorMessage(){
	return PQerrorMessage(conn);
}

void
SecurePGconn::SecurePQfinish(){
	PQfinish(conn);
}

static string trim(const std::string& str,
                 const std::string& whitespace = " ")
{
    const auto strBegin = str.find_first_not_of(whitespace);
    if (strBegin == std::string::npos)
        return ""; // no content

    const auto strEnd = str.find_last_not_of(whitespace);
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

static void removeCharsFromString( string &str, char* charsToRemove ) {
   for ( unsigned int i = 0; i < strlen(charsToRemove); ++i ) {
      str.erase( remove(str.begin(), str.end(), charsToRemove[i]), str.end() );
   }
}

string
SecureSelect::EncryptRow(vector<string> &values, string table_name, int rand_lim){

	string cell, enc_values[values.size()];
	unsigned char *enc;
	GT *M = new GT[n];
	G1 tmpg1;
	G2 tmpg2;

	hash<string> hash_fn;
	size_t str_hash;
	Big X0[n];
	OECt **cts;

	for(int i=0;i<n;i++){

		cell = values.at(i);
		/* Create X0 attribute */
		str_hash = hash_fn(cell);
		X0[i]=str_hash;

		/* Create a key (random, one for each message) to use as aes key */
		pfc->random(tmpg1); pfc->random(tmpg2);
		M[i] = pfc->pairing(tmpg2,tmpg1);
		values[i] = encMsg(M[i],cell);
	}

	/* Encrypt the keys of the row, constructing the ciphertexts */
	cts = aoen->EncryptRow(msks,X0,M, rand_lim);

	string toReturn = string_cts(cts);
	delete_cts(cts);
	return toReturn;
}

Big *
SecureSelect::create_query_attribute(vector<string> query, vector<string> columns){

	Big *Y = new Big[n];

	hash<string> hash_fn;
	size_t str_hash;
	int pos;
	for(int i=0;i<n;i++)
		Y[i] = 0;

	/** These are the 'where' parameters */
	for(int i=0;i<query.size();i+=2){
		transform(query.at(i).begin(), query.at(i).end(), query.at(i).begin(), ::tolower);
		pos = find(columns.begin(), columns.end(), query.at(i)) - columns.begin();
		str_hash = hash_fn(query.at(i+1));
		Y[pos]=str_hash;
	}

	#ifdef VERBOSE
	for(int i=0;i<n;i++)
		cout << "Y " << i << ": " << Y[i] << endl;
	#endif

	return Y;
}

OEKey **
SecureSelect::GenToken(vector<string> query, vector<string> sel_params, vector<int> isel_params, vector<string> columns, OEKey **pkey, int rand_lim){

	/* Create attribute from the query */
	Big *Y = create_query_attribute(query, columns);
	if(Y==NULL)
		return 0;

	#ifdef VERBOSE
	for(int i=0;i<sel_params.size();i++)
		cout << "Sel params " << i << ": " << isel_params[i] << endl;
	#endif

	OEKey **mkey;

	#ifdef VERBOSE
	int start = getMilliCount();
	#endif

	/* Predicate key generation */
	*pkey = aoen->PKeyGen(msks,Y,rand_lim);

	#ifdef VERBOSE
	int milliSecondsElapsed = getMilliSpan(start);
	cout << "\tPredicate key generation time: " << milliSecondsElapsed << endl;
	#endif

	vector<string> ssel_p;
	/* Message keys generation */
	int j;
	for(int i=0;i<sel_params.size();i++){
		j = isel_params[i];
		ssel_p.push_back(to_string(j));
		if(!(j>=1 && j<=n)){
			cout << "Cell " << j << " doesn't exist (there are " << n << " cells)" << endl;
			return 0;
		}
	}
	
	#ifdef VERBOSE
	start = getMilliCount();
	#endif
	
	mkey = aoen->MKeyGen(msks,Y,ssel_p,0);
	
	#ifdef VERBOSE
	milliSecondsElapsed = getMilliSpan(start);
	cout << "\tMessage keys generation time: " << milliSecondsElapsed << endl;
	#endif

	return mkey;
}

string
SecureSelect::read_field_from_db(string field, string table, int oid, PGconn *conn){
	string sql = "SELECT "+field+" FROM "+table+" WHERE oid='"+to_string(oid)+"';";
	PGresult *res = PQexec(conn,sql.c_str());    
    
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		printf("Error while selecting from row with oid %d\n", oid);
		cout << PQerrorMessage(conn);      
		PQclear(res);
		return "";
	}
        
        string to_return = PQgetvalue(res, 0, 0);
	PQclear(res);

	return to_return;
}

vector<string>
SecureSelect::ApplyToken(string table_name, OEKey *pkey, OEKey **mkey, PGconn *conn, vector<string> sel_params, vector<int> isel_params, vector<int> *res_oids){

	vector<string> results;

	string sql = "SELECT oid,ct FROM "+table_name+";";
	PGresult *res = PQexec(conn, sql.c_str());    
    
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		printf("Error while retrieving oids and ciphertexts\n");        
		PQclear(res);
		return results;
	}

	int rows = PQntuples(res);
	vector<int> oids;
	vector<string> string_cts;
	for(int i=0; i<rows; i++) {
		oids.push_back(atoi(PQgetvalue(res, i, 0)));
		string_cts.push_back(PQgetvalue(res, i, 1));

		#ifdef VERBOSE
		cout << "Oids " << i << ": " << oids.at(i) << endl;
//		cout << "String_cts " << i << ": " << string_cts.at(i) << endl;
		#endif
	}    

	PQclear(res);

	OECt **cts;
	GT r, dec_key;
	OEKey **mk = new OEKey*[2];
	mk[0] = mkey[0];
	string encoded,decoded;

	for(int i=0;i<string_cts.size();i++){
		cts = load_ct(string_cts[i]);
		if(cts==NULL){
			cout << "Error while loading ciphertext " << i << endl;
			return results;
		}

		#ifdef VERBOSE
		int start = getMilliCount();
		#endif

		r = aoen->aoe->PDecrypt(cts[0],pkey);

		#ifdef VERBOSE
		int milliSecondsElapsed = getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		if(r==(GT)1){ /* Row match query */
			/* Decryption for every element in sel_params */
			for(int j=0;j<isel_params.size();j++){
				#ifdef VERBOSE
				int start = getMilliCount();
				#endif

				mk[1] = mkey[j+1];
				dec_key = aoen->aoe->MDecrypt(cts,mk,isel_params.at(j));

				#ifdef VERBOSE
				int milliSecondsElapsed = getMilliSpan(start);
				cout << "\tMessage decryption time: " << milliSecondsElapsed << endl;
				#endif

				encoded = read_field_from_db(sel_params.at(j), table_name, oids[i], conn);
				if(encoded.compare("")==0){
					return results;
				}
				decoded = base64_decode(encoded);
				string tmp = decMsg(dec_key, decoded);

				if(tmp.compare("")!=0){
					results.push_back(tmp);
					res_oids->push_back(oids[i]);
				}
			}
		}
	}

	return results;
}

string
SecureSelect::ApplyPToken(string db_name, string table_name, string spkey, string len){

	string results = "";

	string connection = "user=massimo password=password dbname="+db_name;
	PGconn *conn = PQconnectdb(connection.c_str());

	string sql = "SELECT oid,ct FROM "+table_name+";";
	PGresult *res = PQexec(conn, sql.c_str());    
    
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		printf("Error while retrieving oids and ciphertexts\n");        
		PQclear(res);
		return results;
	}

	int rows = PQntuples(res);
	vector<int> oids;
	vector<string> string_cts;
	for(int i=0; i<rows; i++) {
		oids.push_back(atoi(PQgetvalue(res, i, 0)));
		string_cts.push_back(PQgetvalue(res, i, 1));

		#ifdef VERBOSE
		cout << "Oids " << i << ": " << oids.at(i) << endl;
		cout << "String_cts " << i << ": " << string_cts.at(i) << endl;
		#endif
	}    

	PQclear(res);

	OECt **cts;
	GT r, dec_key;

	OEKey *pkey = token_from_string(spkey, atoi(len.c_str()));

	for(int i=0;i<string_cts.size();i++){
		cts = load_ct(string_cts[i]);
		if(cts==NULL){
			cout << "Error while loading ciphertext " << i << endl;
			return results;
		}

		#ifdef VERBOSE
		int start = getMilliCount();
		#endif

		r = aoen->aoe->PDecrypt(cts[0],pkey);

		#ifdef VERBOSE
		int milliSecondsElapsed = getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		if(r==(GT)1){ /* Row match query */
			#ifdef VERBOSE
			cout << "row number: " << i << " oid: " << oids[i] << endl;
			#endif
			results += to_string(oids[i])+" ";
		}
	}

	return results;
}

void *applyMTokenThreadPsql(void *threadarg){
	PFC pfc(AES_SECURITY);
	vector<string> *results = new vector<string>;
	vector<int> to_delete;

	int err = -1;
	struct thread_data *my_data;

	my_data = (struct thread_data *) threadarg;
	int tid = my_data->thread_id;

	int starting_line = ((my_data->num_lines/my_data->num_threads)*tid);
	OECt **cts;
	GT dec_key;
	OEKey **mk = new OEKey*[2];
	mk[0] = my_data->mkey2[0];
	string encoded, decoded,scts;

	string user(PQuser(my_data->conn)); string pass(PQpass(my_data->conn)); string db(PQdb(my_data->conn)); string port(PQport(my_data->conn));
	string connection = "user="+user+" password="+pass+" dbname="+db+" hostaddr="+my_data->host+" port="+port;
	PGconn *conn = PQconnectdb(connection.c_str());

	int line_num = starting_line;
	int limit = ((my_data->num_lines/my_data->num_threads)*(tid+1));
	if(tid==(my_data->num_threads-1))
		limit = my_data->res_oids->size();
	while(line_num<limit){
		scts = my_data->sec_sel->read_field_from_db("ct", my_data->table_name, my_data->res_oids->at(line_num), conn);
		cts = my_data->sec_sel->load_ct(scts);

		if(scts.compare("")==0)
			pthread_exit(&err);
		#ifdef VERBOSE
		cout << "Thread id: " << tid << " Row's oid: " << my_data->res_oids->at(line_num) << " Element number: " << line_num+1 << endl;
		#endif


		/* Decryption for every element in sel_params */
		for(int j=0;j<my_data->sel_params.size();j++){
			#ifdef VERBOSE
			int start = my_data->sec_sel->getMilliCount();
			#endif

			mk[1] = my_data->mkey2[j+1];
			dec_key = my_data->sec_sel->aoen->aoe->MDecrypt(cts,mk,my_data->sel_params.at(j));

			#ifdef VERBOSE
			int milliSecondsElapsed = my_data->sec_sel->getMilliSpan(start);
			cout << "\tMessage decryption time: " << milliSecondsElapsed << endl;
			#endif

			encoded = my_data->sec_sel->read_field_from_db(my_data->sel_par.at(j), my_data->table_name, my_data->res_oids->at(line_num), conn);
			if(encoded.compare("")==0){
				pthread_exit(&err);
			}
			decoded = base64_decode(encoded);
			string tmp = my_data->sec_sel->decMsg(dec_key, decoded);

			if(tmp.compare("")!=0)
				results->push_back(tmp);
			else{
				to_delete.push_back(line_num);
				break;
			}
		}

		line_num++;
		my_data->sec_sel->delete_cts(cts);
	}
	my_data->to_delete = to_delete;
	pthread_exit(results);
}

void
SecureSelect::erase_indices(vector<int> *data, vector<int> to_delete){
	vector<int> to_return;
	for(int i=0;i<data->size();i++)
		if(!(find(to_delete.begin(), to_delete.end(), i) != to_delete.end()))
			to_return.push_back(data->at(i));
	data->clear();
	for(int i=0;i<to_return.size();i++)
		data->push_back(to_return[i]);
}

vector<string>
SecureSelect::ApplyMToken(vector<int> *res_oids, OEKey **mkey, vector<int> isel_params, PGconn *conn, string table_name, vector<string> sel_params, string host){

	vector<string> results;
	OECt **cts;
	GT dec_key;
	string encoded,decoded, scts;
	vector<int> to_delete;

	int num_lines = res_oids->size();
	int rc;
	pthread_t threads[num_threads];
	pthread_attr_t attr;
	void *status;
	struct thread_data td[num_threads];

	// Initialize and set thread joinable
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* Execute threads */
	for(int i=0;i<num_threads;i++){
		#ifdef VERBOSE
		cout << "ApplyMToken() : creating thread, " << i << endl;
		#endif

		td[i].thread_id = i;
		td[i].num_threads = num_threads;
		td[i].num_lines = num_lines;
		td[i].sel_par = sel_params;
		td[i].sel_params = isel_params;
		td[i].mkey2 = mkey;
		td[i].res_oids = res_oids;
		td[i].table_name = table_name;
		td[i].conn = conn;
		td[i].sec_sel = this;
		td[i].host = host;
		rc = pthread_create(&threads[i], NULL, applyMTokenThreadPsql, (void *)&td[i] );
		if (rc){
			cout << "Error:unable to create thread," << rc << endl;
			return results;
		}
	}

	/* Free attribute and wait for threads results */
	pthread_attr_destroy(&attr);
	for(int i=0; i < num_threads; i++ ){
		rc = pthread_join(threads[i], &status);
		if (rc){
			cout << "Error:unable to join," << rc << endl;
			return results;
		}
		int err = *(int *) status;
		if(err == -1)
			return results;

		vector<string> *res_thread = (vector<string> *) status;
		results.insert(results.end(), res_thread->begin(), res_thread->end());
		to_delete.insert(to_delete.end(), td[i].to_delete.begin(), td[i].to_delete.end());
		#ifdef VERBOSE
		cout << "Main: completed thread id :" << i ;
		cout << "  exiting with " << res_thread->size() << " results" << endl;
		#endif
		delete res_thread;
	}

	delete_key(mkey[0], l+1);
	for(int i=1;i<isel_params.size()+1;i++)
		delete_key(mkey[i], k+1);
	delete mkey;

	#ifdef VERBOSE
	cout << "to_delete size: " << to_delete.size() << endl;
	for(int i=0;i<to_delete.size();i++)
		cout << "to_delete["<<i<<"]: " << to_delete[i] << endl;
	#endif
	/* Delete each oid selected for the noise parameter match */
	erase_indices(res_oids, to_delete);

	return results;
}

/**
 * Read the column names of a given table and return them.
**/
vector<string>
SecurePGconn::get_columns(string table){

	vector<string> columns;

	// Read column names
	string sql = "select column_name from information_schema.columns where table_name='"+table+"';";

	PGresult *res = PQexec(conn, sql.c_str());    
    
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		printf("Error while retrieving column names\n");        
		PQclear(res);
        	return columns;
	}

	int rows = PQntuples(res);
	for(int i=0; i<(rows); i++) {
		string val(PQgetvalue(res,i,0));
		if(val.compare("ct")!=0){
			columns.push_back(PQgetvalue(res, i, 0));
			#ifdef VERBOSE
			cout << "Column " << columns.size() << ": " << columns.at(columns.size()-1) << endl;
			#endif
		}
	}    

	PQclear(res);

	// In psql version 9.3 the columns are retrieved in the right order,
	// in version 9.1 the order is reversed, so it need to be fixed
	int ver = PQserverVersion(conn);
	if(ver<90199) reverse(columns.begin(),columns.end());

	return columns;
}

SecurePGresult *
SecurePGconn::SecurePQexec(const char *command){

	/* Get instruction from sql command */
	string sql(command);
	vector<string> sql_split = split(sql,' ');
	vector<string> values;
	string inst = sql_split.at(0);
	transform(inst.begin(), inst.end(), inst.begin(), ::tolower);
	#ifdef VERBOSE
	cout << "Instruction: " << inst << endl;
	#endif

	if(inst.compare("create")==0){
		string new_sql = sql.substr(0, sql.size()-2);
		new_sql = new_sql+", CT TEXT NOT NULL) with oids;";

		#ifdef VERBOSE
		cout << "New sql: " << new_sql << endl;
		#endif

		PGresult *res = PQexec(conn,new_sql.c_str());
		return new SecurePGresult(res);

	} else if(inst.compare("insert")==0){

		string table = sql_split.at(2);
		transform(table.begin(), table.end(), table.begin(), ::tolower);
		#ifdef VERBOSE
		cout << "Table: " << table << endl;
		#endif

		map<string,string>::iterator it = tab_key.find(table);

		PGresult *res = PQprepare(conn,"",command,0,NULL);

		if(PQresultStatus(res) != PGRES_COMMAND_OK)
			return new SecurePGresult(res);

		if(it != tab_key.end()){

			string key_name = it->second;

			map<string,int>::iterator it2 = tab_randlim.find(table);
			int rand_lim = it2->second;
			
			#ifdef VERBOSE
			cout << "Rand_lim: " << rand_lim << endl;
			#endif

			ss = new SecureSelect(pfc,pfc->order(),num_threads);
			if(!ss->LoadKey(key_name))
				return NULL;

			sql_split = split(sql,'(');
			values = split(sql_split.at(1),'\'');
			vector<string> new_values;
			for(int i=0;i<values.size();i++)
				if(i%2!=0)
					new_values.push_back(values[i]);
			values = new_values;

			if(values.size() < ss->n){
				cout << "Inserted " << values.size() << " values, instead of " << ss->n << endl;
				return NULL;
			}
			for(int i=0;i<values.size();i++){
				values[i] = trim(values[i]);
				string to_remove(")';");
				removeCharsFromString(values.at(i), (char *)to_remove.c_str());
				#ifdef VERBOSE
				cout << "Original values " << i << ": " << values.at(i) << endl;
				#endif
			}
			vector <string> enc_values = *new vector<string>(values);
			string ct = ss->EncryptRow(enc_values, table, rand_lim);
			ss->delete_msk(ss->msks);
			#ifdef VERBOSE
			for(int i=0;i<values.size();i++){
				cout << "Original values " << i << ": " << values[i] << endl;
				cout << "Enc_values " << i << ": " << enc_values[i] << endl;
			}
//			cout << "Ciphertext: " << ct << endl;
			#endif

			string new_sql(sql_split[0]+"(");
			for(int i=0;i<enc_values.size();i++){
				if(i!=0)
					new_sql += ",";
				new_sql += "'"+enc_values.at(i)+"'";
			}
			new_sql += ",'"+ct+"');";
			#ifdef VERBOSE
//			cout << "New sql instruction: " << new_sql << endl;
			#endif

			res = PQexec(conn,new_sql.c_str());

			return new SecurePGresult(res);
		}

		cout << "No key associated with table: " << table << endl;
		return NULL;

	} else if(inst.compare("select")==0){

		string ssql(sql);
		string table = split(ssql.substr(ssql.find("FROM")+5),' ').at(0);
		transform(table.begin(), table.end(), table.begin(), ::tolower);
		#ifdef VERBOSE
		cout << "Table: " << table << endl;
		#endif

		map<string,string>::iterator it = tab_key.find(table);

		PGresult *res = PQprepare(conn,"",command,0,NULL);

		if(PQresultStatus(res) != PGRES_COMMAND_OK)
			return new SecurePGresult(res);

		if(it != tab_key.end()){

			string key_name = it->second;

			vector<string> columns = get_columns(table);

			ss = new SecureSelect(pfc,pfc->order(),num_threads);
			if(!ss->LoadKey(key_name))
				return NULL;

			string to_remove(" ");
			// Get fields to select
			vector<string> fields = split(ssql.substr(7,ssql.find("FROM")-8),',');
			for(int i=0;i<fields.size();i++){
				removeCharsFromString(fields.at(i), (char *)to_remove.c_str());
				#ifdef VERBOSE
				cout << "Field " << i << ": " << fields.at(i) << endl;
				#endif
			}

			// Get where clauses
			size_t found = ssql.find("WHERE");
			string after_where = ssql.substr(found+6);

			vector<string> where_clauses;
			string clause;
			vector<string> wclause;
			found = 1;
			to_remove = " ';";
			vector<string> value_split;
			while(found != string::npos){
				found = after_where.find("AND");

				clause = after_where.substr(0,found);

				wclause = split(clause,'=');
				removeCharsFromString(wclause.at(0), (char *)to_remove.c_str());
				value_split = split(wclause.at(1),'\'');
				if(value_split.size()>2)
					wclause[1] = value_split.at(1);
				else
					wclause[1] = value_split.at(0);
				where_clauses.insert(where_clauses.end(), wclause.begin(), wclause.end());

				after_where = after_where.substr(found+3);
			}

			#ifdef VERBOSE
			for(int i=0;i<where_clauses.size();i++)
				cout << "Where " << i << ": " << where_clauses.at(i) << endl;
			#endif

			map<string,int>::iterator it2 = tab_randlim.find(table);
			int rand_lim = it2->second;

			vector<int> isel_params;
			/** These are the 'where' parameters */
			int pos;
			for(int i=0;i<fields.size();i++){
				transform(fields.at(i).begin(), fields.at(i).end(), fields.at(i).begin(), ::tolower);
				pos = find(columns.begin(), columns.end(), fields.at(i)) - columns.begin();
				isel_params.push_back(pos+1);
			}

			OEKey *pkey;
			OEKey **mkey = ss->GenToken(where_clauses, fields, isel_params, columns, &pkey,rand_lim);

			res = PQexec(conn,command);
			SecurePGresult *sres = new SecurePGresult(res);

			string str_pkey =  ss->string_token(pkey,ss->l+1);


// Local method for the PToken application
//			string s_oids = ss->ApplyPToken(dbname, table, str_pkey, to_string(ss->l+1));
// Method from the C library "ApplyPTokenServer.h"
//			string s_oids(ApplyPTokenServer(dbname.c_str(), table.c_str(), str_pkey.c_str(), to_string(ss->n).c_str()));
// Call to the UDF's server function "ApplyPTokenServer"
			PGresult *res2;
			string user(PQuser(conn));
			string pass(PQpass(conn));
			string apt_q = "SELECT ApplyPTokenServer('"+user+"','"+pass+"','"+dbname+"','"+table+"','"+str_pkey+"','"+to_string(ss->n)+"');";
//			res2 = PQexec(conn, apt_q.c_str());
			if(PQsendQuery(conn, apt_q.c_str())==0){
				cout << "PQsendQuery PQerror message: " << PQerrorMessage(conn) << endl;
				return NULL;
			}
			while(PQisBusy(conn)==1)
				PQconsumeInput(conn);
			res2 = PQgetResult(conn);
			if (PQresultStatus(res2) != PGRES_TUPLES_OK){
				cout << "Server error result status: " << PQresStatus(PQresultStatus(res2)) << endl;
				cout << "PQerror message: " << PQerrorMessage(conn) << endl;
				return NULL;
			}
			string s_oids(PQgetvalue(res2, 0, 0));
			#ifdef VERBOSE
			cout << "Result ApplyPToken " << s_oids << endl;
			#endif

			if(s_oids.compare("")==0){
				return sres;
			}
			vector<string> oids = split(s_oids,' ');
			if(oids[0].find("Error")==0){
				cout << oids[0] << endl;
				return NULL;
			}
			for(int i=0;i<oids.size();i++)
				sres->res_oids.push_back(atoi(oids[i].c_str()));
			vector<string> query_results = ss->ApplyMToken(&(sres->res_oids), mkey, isel_params, conn, table, fields, host);
			ss->delete_msk(ss->msks);
			#ifdef VERBOSE
			cout << "ApplyMToken result size: " << query_results.size() << endl;
			for(int i=0;i<query_results.size();i++)
				cout << "Result " << i+1 << ": " << query_results.at(i) << endl;
			#endif

			sres->sel_par_num = fields.size();
			sres->results = query_results;
			return sres;
		}
		cout << "No key associated with table: " << table << endl;
		return NULL;
	} else if(inst.compare("drop")==0){
		PGresult *res = PQexec(conn,command);
		return new SecurePGresult(res);
	} else if(inst.compare("delete")==0){

		string table = sql_split.at(2);
		transform(table.begin(), table.end(), table.begin(), ::tolower);
		#ifdef VERBOSE
		cout << "Table: " << table << endl;
		#endif

		map<string,string>::iterator it = tab_key.find(table);

		PGresult *res = PQprepare(conn,"",command,0,NULL);

		if(PQresultStatus(res) != PGRES_COMMAND_OK)
			return new SecurePGresult(res);

		if(it != tab_key.end()){

			string key_name = it->second;

			vector<string> columns = get_columns(table);

//			ss = new SecureSelect(pfc,pfc->order(),num_threads);
//			if(!ss->LoadKey(key_name))
//				return NULL;

			string ssql(sql);
			size_t found = ssql.find("WHERE");
			string after_where = ssql.substr(found+6);
			string first_wfield = split(after_where,'=').at(0);
			string to_remove = " ";
			removeCharsFromString(first_wfield, (char *)to_remove.c_str());

			string sql_select = "SELECT "+first_wfield+" "+sql.substr(7);

			#ifdef VERBOSE
			cout << "Sql: " << sql_select << endl;
			#endif

			SecurePGresult *sres_select = SecurePQexec(sql_select.c_str());

			string del_sql;
			PGresult *res2;
			SecurePGresult *sres;
			for(int i=0;i<sres_select->res_oids.size();i++){
				del_sql = "DELETE FROM "+table+" WHERE oid='"+to_string(sres_select->res_oids.at(i))+"';";
				res2 = PQexec(conn, del_sql.c_str());
        
				if (PQresultStatus(res2) != PGRES_COMMAND_OK){
					sres = new SecurePGresult(res2);
					return sres;
				}
				    
				PQclear(res2);
			}

			sres = new SecurePGresult(res);
			return sres;
		}
		cout << "No key associated with table: " << table << endl;
		return NULL;
	} else
		return NULL;
}

ExecStatusType
SecurePGconn::SecurePQresultStatus(const SecurePGresult *res){
	return PQresultStatus(res->res);
}

void
SecurePGconn::SecurePQclear(SecurePGresult *res){
	PQclear(res->res);
}

int
SecurePGconn::SecurePQntuples(const SecurePGresult *res){
	return ((res->results.size())/(res->sel_par_num));
}

char *
SecurePGconn::SecurePQgetvalue(const SecurePGresult *res, int row_number, int column_number){
	return (char *)res->results.at((row_number*(res->sel_par_num))+column_number).c_str();
}

void
SecurePGconn::associate_key_randlim (string table, string key_name, int rand_lim){
	tab_key[table] = key_name;
	tab_randlim[table] = rand_lim;
	
	#ifdef VERBOSE
	map<string,string>::iterator it = tab_key.find(table);
	if(it != tab_key.end())
		cout << "Pair " << it->first << " " << it->second << " inserted" << endl;
	map<string,int>::iterator it2 = tab_randlim.find(table);
	if(it2 != tab_randlim.end())
		cout << "Pair " << it2->first << " " << it2->second << " inserted" << endl;
	#endif
}

