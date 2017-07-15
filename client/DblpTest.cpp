#include <iostream>
#include <chrono>
#include <string>
#include <sstream>
#include <fstream>

#include "pairing_3.h"
#include "aoe-m.h"

#include <sys/timeb.h>

#include <libpq-fe.h>

int
getMilliCount(){
	timeb tb;
	ftime(&tb);
	int nCount = tb.millitm + (tb.time & 0xfffff) * 1000;
	return nCount;
}

int
getMilliSpan(int nTimeStart){
	int nSpan = getMilliCount() - nTimeStart;
	if(nSpan < 0)
		nSpan += 0x100000 * 1000;
	return nSpan;
}

vector<string> &
split_(const string &s, char delim, vector<string> &elems) {
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
split_(const string &s, char delim) {
    vector<string> elems;
    split_(s, delim, elems);
    return elems;
}

void do_exit(SecurePGconn *conn, SecurePGresult *res) {
    
    fprintf(stderr, "%s\n", conn->SecurePQerrorMessage());    

    conn->SecurePQclear(res);
    conn->SecurePQfinish();
    
    exit(1);
}

void insert_rows(string fname, string table, SecurePGconn *conn){
	string line;
	ifstream inputFile(fname);
	vector<string> cells;
	string sql;
	SecurePGresult *res;
	while(getline(inputFile, line)){
		sql = "INSERT INTO "+table+" VALUES(";
		cells = split_(line,'#');
		sql += "'"+cells[0]+"'";
		for(int i=1;i<cells.size();i++)
			sql += ",'"+cells[i]+"'";
		sql += ");";

//		int start = getMilliCount();
		res = conn->SecurePQexec(sql.c_str());
//		int milliSecondsElapsed = getMilliSpan(start);
//		cout << endl << "\texecution time... " << milliSecondsElapsed << endl;
		if(res != NULL){
			if (conn->SecurePQresultStatus(res) != PGRES_COMMAND_OK)
				do_exit(conn, res);		    
			conn->SecurePQclear(res);
		}
	}
}

main(int argc, char *argv[]){

	/** Check the number of parameters */
	if (argc < 3) {
		/** Tell the user how to run the program */
		cerr << "Usage: " << argv[0] << " table operation" << endl;
        	return 1;
	}

	// Initializations
	mr_init_threading();
	PFC *pfc = new PFC(AES_SECURITY); // Pairing-friendly curve

	int m=17;
	int num_threads = 4;
	string table(argv[1]);
	string operation(argv[2]);
	if(operation.compare("insert")==0 && argc < 4){
		/** Tell the user how to run the program */
		cerr << "Usage for insert operations: " << argv[0] << " table operation rows_fname" << endl;
   		return 1;
	}

	SecureSelect *ss = new SecureSelect(m,pfc,pfc->order(),num_threads); // SecureSelect object
	string key_name = table+"_key";
	if (!ifstream(key_name))
		ss->KeyGen(key_name); // create a key to encrypt tables with m columns

	string host = "127.0.0.1";
	SecurePGconn *conn = new SecurePGconn(pfc, "testdb", num_threads, host);
	string conn_str = "user=massimo password=experiments dbname=testdb hostaddr="+host+" port=5432";
	conn->SecurePQconnectdb(conn_str.c_str());

	if (conn->SecurePQstatus() == CONNECTION_BAD) {
		fprintf(stderr, "Connection to database failed: %s\n", conn->SecurePQerrorMessage());
		    
		conn->SecurePQfinish();
		exit(1);
	}

	int rand_lim = 100;
	conn->associate_key_randlim(table,key_name, rand_lim); // associate the created key with the table 'dblp'

	SecurePGresult *res;

	// Create table Dblp with its 17 columns
	if(operation.compare("create")==0){
		cout << "Creating table " << table << "..."; flush(cout);
		int start = getMilliCount();
		string sql = "CREATE TABLE "+table+"(Author TEXT NOT NULL,Title TEXT NOT NULL,Booktitle TEXT NOT NULL,Year TEXT NOT NULL,Ee TEXT NOT NULL,Pages TEXT NOT NULL,Crossref TEXT NOT NULL,Editor TEXT NOT NULL,Title2 TEXT NOT NULL,Booktitle2 TEXT NOT NULL,Year2 TEXT NOT NULL,Url TEXT NOT NULL,Publisher TEXT NOT NULL,Volume TEXT NOT NULL,Series TEXT NOT NULL,Isbn TEXT NOT NULL,Crossref2 TEXT NOT NULL);";
		res = conn->SecurePQexec(sql.c_str());
		int milliSecondsElapsed = getMilliSpan(start);
		cout << endl << "\texecution time... " << milliSecondsElapsed << endl;
		
		if (conn->SecurePQresultStatus(res) != PGRES_COMMAND_OK)
			do_exit(conn, res);
					    
		conn->SecurePQclear(res);
		cout << "done!" << endl;
	}

	// Insert rows from rows_fname into table
	if(operation.compare("insert")==0){
		string rows_fname(argv[3]);
		cout << "Inserting rows from " << rows_fname << "..."; flush(cout);
		insert_rows(rows_fname, table, conn);
		cout << "done!" << endl;
	}

	// Select operation
	if(operation.compare("select")==0){
		cout << "Executing Select operation on "+table+"..."; flush(cout);
		int start = getMilliCount();
		string sql = "SELECT Editor FROM "+table+" WHERE Author='Petra Ludewig';";
		res = conn->SecurePQexec(sql.c_str());
		int milliSecondsElapsed = getMilliSpan(start);
		cout << endl << "\texecution time... " << milliSecondsElapsed << endl;

		if(res != NULL){
			if (conn->SecurePQresultStatus(res) != PGRES_TUPLES_OK) {
				printf("No data retrieved\n");        
				conn->SecurePQclear(res);
				conn->SecurePQfinish();
				exit(1);
			}
			int rows = conn->SecurePQntuples(res);
			if(rows == 0)
				cout << "No result found" << endl;
			else{
				cout << "Select: " << rows << " results" << endl;
				for(int i=0; i<rows; i++)
					printf("%d: %s\n", i+1, conn->SecurePQgetvalue(res, i, 0));
			}
			conn->SecurePQclear(res);
			cout << "done!" << endl;
		}
	}

	// Drop table
	if(operation.compare("drop")==0){
		cout << "Dropping table " << table << "..."; flush(cout);
		string sql = "DROP TABLE "+table+";";
		res = conn->SecurePQexec(sql.c_str());
		if (conn->SecurePQresultStatus(res) != PGRES_COMMAND_OK)
			do_exit(conn, res);
					    
		conn->SecurePQclear(res);
		cout << "done!" << endl;
	}

	conn->SecurePQfinish();

}
