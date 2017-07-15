#include "aoe_server.h"
#include <libpq-fe.h>
#include <vector>
#include <sstream>
#include <sys/timeb.h>
#include <pthread.h>

//#define VERBOSE
#define NUM_THREADS 4

int
SecureSelectServer::getMilliCount(){
	timeb tb;
	ftime(&tb);
	int nCount = tb.millitm + (tb.time & 0xfffff) * 1000;
	return nCount;
}

int
SecureSelectServer::getMilliSpan(int nTimeStart){
	int nSpan = getMilliCount() - nTimeStart;
	if(nSpan < 0)
		nSpan += 0x100000 * 1000;
	return nSpan;
}

GT
AOEServer::PDecrypt(OECt *C0, OEKey *pkey){

	oe->len=l+1;

	return oe->MDecrypt(C0,pkey);
}

/**
 * Retrieve key of lenght len from string.
 */
OEKey *
SecureSelectServer::token_from_string(string skey, int len){

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
 * Load the ciphertext for a row passed by s_cts,
 * return the loaded ciphertext.
 */
OECt **
SecureSelectServer::load_ct(string s_cts){

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

void
SecureSelectServer::delete_cts(OECt **cts){
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









struct thread_data{
	int  thread_id;
	int num_threads;
	int num_lines;
	SecureSelectServer *sec_sel;
	vector<string> string_cts;
	vector<int> oids;
	OEKey *pkey;
};

int
get_rows_number(PGconn *conn, string table_name){
	string sql = "SELECT COUNT(*) FROM "+table_name+";";
	PGresult *res = PQexec(conn, sql.c_str());    
    
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {      
		PQclear(res);
		return -1;
	}    
	int to_return = atoi(PQgetvalue(res, 0, 0));  
	PQclear(res);
	return to_return;
}

void *applyPTokenThreadPsql(void *threadarg){
	PFC pfc(AES_SECURITY);
	vector<string> *results = new vector<string>;

	int err = -1;
	struct thread_data *my_data;

	my_data = (struct thread_data *) threadarg;
	int tid = my_data->thread_id;

	int starting_line = ((my_data->num_lines/my_data->num_threads)*tid);
	int line_num = starting_line;
	int limit = ((my_data->num_lines/my_data->num_threads)*(tid+1));
	if(tid==(my_data->num_threads-1))
		limit = my_data->string_cts.size();
	OECt **cts;
	GT r;

	while(line_num<limit){
		cts = my_data->sec_sel->load_ct(my_data->string_cts[line_num]);
		if(cts==NULL)
			pthread_exit(&err);

		#ifdef VERBOSE
		int start = my_data->sec_sel->getMilliCount();
		#endif

		r = my_data->sec_sel->aoens->aoes->PDecrypt(cts[0],my_data->pkey);

		#ifdef VERBOSE
		int milliSecondsElapsed = my_data->sec_sel->getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		my_data->sec_sel->delete_cts(cts);
		if(r==(GT)1){ /* Row match query */
			#ifdef VERBOSE
			cout << "row number: " << line_num << " oid: " << my_data->oids[line_num] << endl;
			#endif
			results->push_back(to_string(my_data->oids[line_num]));
		}
		line_num++;
	}
	pthread_exit(results);
}

const char *
ApplyPToken_Server(const char *user, const char *pass, const char *db_name, const char *table_name, const char *spkey, const char *n){
	string results = "";

	mr_init_threading();
	PFC pfc(AES_SECURITY);
	SecureSelectServer *ss = new SecureSelectServer(atoi(n),&pfc,pfc.order());
	string us(user);
	string pas(pass);
	string db(db_name);
	string table(table_name);
	string spk(spkey);
	string connection = "user="+us+" password="+pas+" dbname="+db;
	PGconn *conn = PQconnectdb(connection.c_str());

	string sql = "SELECT oid,ct FROM "+table+";";
	PGresult *res = PQexec(conn, sql.c_str());    
    
	if (PQresultStatus(res) != PGRES_TUPLES_OK) { 
		results += "Error while retrieving oids and ciphertexts\n";
		PQclear(res);
		return results.c_str();
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

	OEKey *pkey = ss->token_from_string(spk, ss->l+1);

	int num_lines = get_rows_number(conn,table);
	if(num_lines<0){
		results += "Error while counting the number of rows in "+table+"\n";
		return results.c_str();
	}

	int rc;
	pthread_t threads[NUM_THREADS];
	pthread_attr_t attr;
	void *status;
	struct thread_data td[NUM_THREADS];

	// Initialize and set thread joinable
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* Execute threads */
	for(int i=0;i<NUM_THREADS;i++){
		#ifdef VERBOSE
		cout << "ApplyPTokenServer() : creating thread, " << i << endl;
		#endif

		td[i].thread_id = i;
		td[i].num_threads = NUM_THREADS;
		td[i].num_lines = num_lines;
		td[i].sec_sel = ss;
		td[i].string_cts = string_cts;
		td[i].oids = oids;
		td[i].pkey = pkey;
		rc = pthread_create(&threads[i], NULL, applyPTokenThreadPsql, (void *)&td[i] );
		if (rc){
			results += "Error:unable to create thread,"+to_string(rc)+"\n";
			return results.c_str();
		}
	}

	/* Free attribute and wait for threads results */
	pthread_attr_destroy(&attr);
	for(int i=0; i < NUM_THREADS; i++ ){
		rc = pthread_join(threads[i], &status);
		if (rc){
			results += "Error:unable to join,"+to_string(rc)+"\n";
			return results.c_str();
		}
		int err = *(int *) status;
		if(err == -1){
			results += "Error during execution of thread "+to_string(i)+"\n";
			return results.c_str();
		}

		vector<string> *res_thread = (vector<string> *) status;
		for(int j=0;j<res_thread->size();j++)
			results += res_thread->at(j)+" ";
		#ifdef VERBOSE
		cout << "Main: completed thread id :" << i ;
		cout << "  exiting with " << res_thread->size() << " results" << endl;
		#endif
		delete res_thread;
	}













	

//	OECt **cts;
//	GT r;

//	for(int i=0;i<string_cts.size();i++){
//		cts = ss->load_ct(string_cts[i]);
//		if(cts==NULL){
//			results += "Error while loading ciphertext "+to_string(i)+"\n";
//			return results.c_str();
//		}

//		#ifdef VERBOSE
//		int start = ss->getMilliCount();
//		#endif

//		r = ss->aoens->aoes->PDecrypt(cts[0],pkey);

//		#ifdef VERBOSE
//		int milliSecondsElapsed = ss->getMilliSpan(start);
//		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
//		#endif

//		if(r==(GT)1){ /* Row match query */
//			#ifdef VERBOSE
//			cout << "row number: " << i << " oid: " << oids[i] << endl;
//			#endif
//			results += to_string(oids[i])+" ";
//		}
//	}

	return results.c_str();
}
