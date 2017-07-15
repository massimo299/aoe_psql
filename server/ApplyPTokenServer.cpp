#include "aoe_server.h"
extern "C"{
#include "postgres.h"
#include <string.h>
#include "fmgr.h"
#include <stdio.h>
#include "builtins.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif
}
/* Convert text* to char* */
extern "C"{
char *text_to_char(text *t){
	size_t len = VARSIZE(t)-VARHDRSZ;
	char *c = (char *)palloc(len+1);
	memcpy(c, VARDATA(t), len);
	c[len] = 0;
	return c;
}


PG_FUNCTION_INFO_V1(ApplyPTokenServer);

Datum
ApplyPTokenServer(PG_FUNCTION_ARGS){
	const char *user = text_to_char(PG_GETARG_TEXT_P(0));
	const char *pass = text_to_char(PG_GETARG_TEXT_P(1));
	const char *db_name = text_to_char(PG_GETARG_TEXT_P(2));
	const char *table_name = text_to_char(PG_GETARG_TEXT_P(3));
	const char *spkey = text_to_char(PG_GETARG_TEXT_P(4));
	const char *len = text_to_char(PG_GETARG_TEXT_P(5));

	PG_RETURN_TEXT_P(cstring_to_text(ApplyPToken_Server(user, pass, db_name, table_name, spkey, len)));
}
}
