#include "pairing_3.h"
#include "oe-m.h"
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif
const char *ApplyPToken_Server(const char *user, const char *pass, const char *db_name, const char *table_name, const char *spkey, const char *n);
#ifdef __cplusplus
}
#endif

/**
 * \brief The amortized orthogonal encryption class.
 *
 * It uses orthogonal encryption basic class (OE) to provide methods to:
 * create master keys;
 * encrypt messages (of the group target type GT) with vectors of attributes (type Big);
 * generate predicate and message tokens for specified vectors of attributes;
 * apply the tokens to decrypt the messages.
 */
class AOEServer{
public:
	int n,l,k;
	PFC *pfc;
	miracl *mip;
	Big order;
	OE *oe;
public:
	GT PDecrypt(OECt *, OEKey *);
	/** \brief Class constructor
	 *
	 * n_,l_ and k_ are the values of the three parameters for the amortized technique,
	 * m is the pointer to a miracl object instance,
	 * p is the curve, o its order
	 */
	AOEServer(int n_, int l_, int k_, PFC *p, miracl * m, Big o){
		n=n_;
		l=l_;
		k=k_;
		pfc=p;
		mip=m;
		order=o;
		oe = new OE(l+1,pfc,mip,order);
	};
	~AOEServer(){
		delete oe;
	};
};

/**
 * \brief The amortized orthogonal encryption class with noise.
 *
 * Extends the functionalities of the class AOE by adding a random noise parameter
 * to the encryption and token generation steps.
 * The system returns true in predicate decryption operations if:
 * the token is generated with a good vector of attributes;
 * the noise parameter used during decryption match the one used in encryption.
 */
class AOENoiseServer{
public:
	int n,l,k;
	AOEServer *aoes;
	PFC *pfc;
	Big order;
public:
	/** \brief Class constructor
	 *
	 * m is the number of columns per row,
	 * mi is the pointer to a miracl object instance,
	 * p is the curve, o its order
	 */
	AOENoiseServer(int m, PFC *p, miracl *mi, Big o){
		n=m;
		l=2*m+2;
		k=2;
		pfc=p;
		order=o;
		aoes = new AOEServer(n,l,k,pfc,mi,order);
	};
	~AOENoiseServer(){
		delete aoes;
	};
};

class SecureSelectServer{
public:
	AOENoiseServer *aoens; /**< This is needed to execute orthogonal encryption operations. */
	int n; /**< Number of columns. */
	int l; /**< Length of the principal attribute. */
	int k; /**< Lenght of the attribute for every column. */
	PFC *pfc; /**< Pairing-friendly curve object. */
	Big order; /**< Number of elements on the curve. */
public:
	OECt **load_ct(string);
	OEKey *token_from_string(string, int);
	int getMilliCount();
	int getMilliSpan(int);
	void delete_cts(OECt **);
	SecureSelectServer(int m, PFC *pfc_, Big order_){
		n=m;
		l=2*m+2;
		k=2;
		pfc=pfc_;
		miracl* mip=get_mip();
		time_t seed;
		time(&seed);
		irand((long)seed);
		order=order_;
		aoens = new AOENoiseServer(m,pfc,mip,order);
	}
};
