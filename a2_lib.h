#ifndef A2LIB_H_
#define A2LIB_H_
int kv_store_create(char* name);
int kv_store_write(char* key, char* value);
int hash_func(char* word);
char* kv_store_read(char* key);
char** kv_store_read_all(char* key);
int kv_store_delete_db();
#endif // A2LIB_H_
