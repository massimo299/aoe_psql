#include <vector>
#include <queue> 

#include "pairing_3.h"
#include "oe-m.h"

#include <libpq-fe.h>
#include <map>

/**
 * \brief The amortized orthogonal encryption class.
 *
 * It uses orthogonal encryption basic class (OE) to provide methods to:
 * create master keys;
 * encrypt messages (of the group target type GT) with vectors of attributes (type Big);
 * generate predicate and message tokens for specified vectors of attributes;
 * apply the tokens to decrypt the messages.
 */
class AOE{
public:
	int n,l,k;
	PFC *pfc;
	miracl *mip;
	Big order, omega, ab1[2], ab2[2];
	OE *oe;
	G1 g;
	G2 g2;
public:
	OEMsk **Setup();
	OECt **Encrypt(OEMsk **, Big *, Big **,GT *);
	OEKey *PKeyGen(OEMsk **, Big *);
	OEKey **MKeyGen(OEMsk **, Big *, Big *, int);
	OEKey **MKeyGen(OEMsk **, Big *, Big **, vector<string>);
	GT PDecrypt(OECt *, OEKey *);
	GT MDecrypt(OECt **, OEKey **, int);
	/** \brief Class constructor
	 *
	 * n_,l_ and k_ are the values of the three parameters for the amortized technique,
	 * m is the pointer to a miracl object instance,
	 * p is the curve, o its order
	 */
	AOE(int n_, int l_, int k_, PFC *p, miracl * m, Big o){
		n=n_;
		l=l_;
		k=k_;
		pfc=p;
		mip=m;
		order=o;
	};
	~AOE(){
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
class AOENoise{
public:
	int n,l,k;
	AOE *aoe;
	PFC *pfc;
	Big order;
public:
	OEMsk **RSetup();
	OECt **EncryptRow(OEMsk **, Big *, GT *, int);
	OEKey *PKeyGen(OEMsk **, Big *, int);
	OEKey **MKeyGen(OEMsk **, Big *, int, int);
	OEKey **MKeyGen(OEMsk **, Big *, vector<string>, int);
	/** \brief Class constructor
	 *
	 * m is the number of columns per row,
	 * mi is the pointer to a miracl object instance,
	 * p is the curve, o its order
	 */
	AOENoise(int m, PFC *p, miracl *mi, Big o){
		n=m;
		l=2*m+2;
		k=2;
		pfc=p;
		order=o;
		aoe = new AOE(n,l,k,pfc,mi,order);
	};
	~AOENoise(){
		delete aoe;
	};
};

/**
 * \brief The secure select main class.
 *
 * It is useful for data owners and readers.
 * This class can be used to generate a master keys, encrypt tables and execute queries on them.
 */
class SecureSelect{
public:
	AOENoise *aoen; /**< This is needed to execute orthogonal encryption operations. */
	int n; /**< Number of columns. */
	int l; /**< Length of the principal attribute. */
	int k; /**< Lenght of the attribute for every column. */
	OEMsk **msks; /**< Contains the n+1 master keys. */
	PFC *pfc; /**< Pairing-friendly curve object. */
	Big order; /**< Number of elements on the curve. */
	int num_threads; /**< Number of threads to be used during the postgresql token application phases. */
public:
	void KeyGen(string);
	bool LoadKey(string);
	string EncryptRow(vector<string> &, string, int);
	void EncryptRows(string, string, int);
	void EncryptRowsMT(string, string, int, int);
	int GenToken(string, int);
	OEKey **GenToken(vector<string>, vector<string>, vector<int>, vector<string>, OEKey **, int);
	vector<string> ApplyToken(string, string);
	int ApplyPToken(string, string, string);
	int ApplyPTokenMT(string, string, string, int);
	vector<string> ApplyToken(string, OEKey *, OEKey **, PGconn *, vector<string>, vector<int>, vector<int> *);
	string ApplyPToken(string, string, string, string);
	vector<string> ApplyMToken(string, string, string);
	vector<string> ApplyMTokenMT(string, string, string, int);
	ifstream &GotoLine(ifstream&, unsigned int);
	OECt **load_ct(ifstream *);
	OECt **load_ct(fstream *, int);
	OECt **load_ct(string);
	int getMilliCount();
	int getMilliSpan(int);
	string read_line_from_file(int, string);
	string encMsg(GT, string);
	string decMsg(GT M, string Msg);
	string *create_row(string, int);
	void save_cts(ofstream *, OECt **);
	void delete_cts(OECt **);
	void delete_msk(OEMsk **);
	void delete_key(OEKey *, int);
	string string_token(OEKey *, int);
	OEKey *token_from_string(string, int);
	vector<string> ApplyMToken(vector<int> *, OEKey **, vector<int>, PGconn *, string, vector<string>, string);
	string read_field_from_db(string, string, int, PGconn *);

	/** \brief Class constructor
	 *
	 * m is the number of columns per row,
	 * pfc_ is the curve, order_ its order.
	 */
	SecureSelect(int m, PFC *pfc_, Big order_){
		n=m;
		l=2*m+2;
		k=2;
		pfc=pfc_;
		miracl* mip=get_mip();
		time_t seed;
		time(&seed);
		irand((long)seed);
		order=order_;
		aoen = new AOENoise(m,pfc,mip,order);
	}
	SecureSelect(int m, PFC *pfc_, Big order_, int num_threads_){
		n=m;
		l=2*m+2;
		k=2;
		pfc=pfc_;
		miracl* mip=get_mip();
		time_t seed;
		time(&seed);
		irand((long)seed);
		order=order_;
		num_threads=num_threads_;
		aoen = new AOENoise(m,pfc,mip,order);
	}
	SecureSelect(PFC *pfc_, Big order_){
		pfc=pfc_;
		order=order_;
	}
	SecureSelect(PFC *pfc_, Big order_, int num_threads_){
		pfc=pfc_;
		order=order_;
		num_threads=num_threads_;
	}
private:
	void saveMsks(string, OEMsk **);
	void encMsg(GT, string, string);
	string stdsha256(const string);
	void append_enc_cell_file(string, const unsigned char *, int);
	fstream &GotoLine(fstream&, unsigned int);
	Big *create_query_attribute(string);
	Big *create_query_attribute(vector<string>, vector<string>);
	vector<string> get_select_params(string);
	void save_token(OEKey *, string, int, int);
	void set_parameters(string);
	OEKey *load_token(string, int);
	OEKey *load_token(string, int, vector<int>&);
	string string_cts(OECt **);
	void erase_indices(vector<int> *, vector<int>);
};

/**
 * Wrapper for postgresql database result object.
 */
class SecurePGresult{
public:
	PGresult *res;
	int sel_par_num;
	vector<string> results;
	vector<int> res_oids;
public:
	SecurePGresult(PGresult *r){
		res = r;
	}
};

/**
 * Wrapper for postgresql database connection object.
 * It allows the operations described by the public methods.
 */
class SecurePGconn{
public:
	PGconn *conn;
private:
	SecureSelect *ss;
	PFC *pfc;
	string path;
	map<string,string> tab_key;
	map<string,int> tab_randlim;
	string dbname;
	int num_threads;
	string host;
public:
	void SecurePQconnectdb(const char *conninfo);
	ConnStatusType SecurePQstatus();
	char *SecurePQerrorMessage();
	void SecurePQfinish();
	SecurePGresult *SecurePQexec(const char *command);
	ExecStatusType SecurePQresultStatus(const SecurePGresult *res);
	void SecurePQclear(SecurePGresult *res);
	int SecurePQntuples(const SecurePGresult *res);
	char *SecurePQgetvalue(const SecurePGresult *res, int row_number, int column_number);
	void associate_key_randlim (string, string, int);
	SecurePGconn(PFC *_pfc, string dbn, int num_threads_, string host_){
		pfc = _pfc;
		path = "";
		dbname=dbn;
		num_threads=num_threads_;
		host=host_;
	}
private:
	vector<string> get_columns(string table);
	vector<int> get_rowids(string table);
};
