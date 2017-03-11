#include<stdlib.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#define NUMBER_OF_PODS 256
#define ENTRIES_PER_POD 256
#define MAX_NUMBER_KEYS 256
#define KEYSIZE 32
#define VALUESIZE 256
#define DB_NAME_SIZE 20

// TODO: MAKE WRITE COUNT SHARED SO DIFFERENT PROCESSES DON'T OVERWRITE THINGS


/* 1ST:	STRUCTS */

typedef struct pair    /* This will represent a key-value pair  */
{
	char key[KEYSIZE];
	char value[VALUESIZE];
}pair;

typedef struct pod
{
	int writeIndx;
	pair pairs[ENTRIES_PER_POD];
}pod;

typedef struct store    /* This will represent a 2d matrix of key-value pairs  */
{
	pod pods[NUMBER_OF_PODS];

}store;

typedef struct keyread_count    /* This is for the reader, will keep track of the index of the last read pair with key k  */
{
	char key[KEYSIZE];
	int lastOffs;
}keyread_count;
/* ^^NOTE: TA told me to do it this way,
ideally I would make it dynamically grow to support more keys, but I'm keeping it simple.*/



/* 2ND:	OUR BELOVED GLOBAL OBJECTS */

char dbname[DB_NAME_SIZE];
int db_fd = 0;
store *shared_store_addr;
keyread_count keycount[MAX_NUMBER_KEYS];

/* TODO: semaphores */


/* 3RD:	FUNCTION IMPLEMENTATIONS  */

int kv_store_create(char* name)
{
	/* Get the name globally accessible...*/
	strcpy(dbname, name);

	/* create the shared memory object  */
	db_fd = shm_open(dbname, O_CREAT|O_RDWR,S_IRWXU);

	/* Compute total byte size of the key-value store,
	   and define the shared memory size to be that  */
	shared_store_addr = mmap(NULL, sizeof(store), PROT_READ | PROT_WRITE, MAP_SHARED, db_fd, 0);
	ftruncate(db_fd, 0);
	ftruncate(db_fd, sizeof(store));
	close(db_fd);

	/* Now instantiate an empty store struct and dump it in, then free it */
	store *ogStore = malloc(sizeof(store));
	memcpy(shared_store_addr, ogStore, sizeof(store));
	free(ogStore);
	return 0;
}


/* Next, a function to write two strings as a keyval pair,
	mmap() lets us access the shared database from the context of THIS process's address space
	we hash the supplied key so that we write to the correct pod of the shared database */
int kv_store_write(char* key, char* value)
{
	/* First we hash the key to obtain the desired pod index */
	int keyhash = hash_func(key);
	printf("Hash of key:\t%d\n",keyhash);

	pod* thisKeysPod = &(shared_store_addr -> pods[keyhash]);


	char* keydest = thisKeysPod -> pairs[thisKeysPod->writeIndx].key;
	char* valdest = thisKeysPod -> pairs[thisKeysPod->writeIndx].value;

	strcpy(keydest, key);
	strcpy(valdest, value);

	return 0;
}

/* Hash function for the keys */
int hash_func(char* word)
{
	int hashAddress = 5381;
	int counter;
	for(counter = 0; word[counter]!='\0'; counter++)
	{
		hashAddress = ((hashAddress << 5) + hashAddress) + word[counter];
	}
	return hashAddress % NUMBER_OF_PODS < 0 ? -hashAddress % NUMBER_OF_PODS : hashAddress % NUMBER_OF_PODS;
}


char* kv_store_read(char* key)
{
	char* retbuff = malloc(VALUESIZE*sizeof(char));	// returns pointer to char[VALUESIZE] on heap

	/* First we want to find the key in the key count table to see where in the pod to go  */
	int i = 0;
	while(strlen(keycount[i].key) != 0 && i < MAX_NUMBER_KEYS)
	{
		if (strcmp(keycount[i].key, key) == 0)	// if we find the key, use the offset at i
		{
			goto RIGHT_i_FOUND;	// apologies for the goto...
		}
		i++;
	}
	if(i == MAX_NUMBER_KEYS)			// we cycle through max no keys without finding it
	{
		printf("E:\t Key not found, and there's already %d keys so I can't keep track of more.\n", MAX_NUMBER_KEYS);
		return NULL;
	}
	else	// initialize new key with count 0
	{
		strcpy(keycount[i].key, key);
		keycount[i].lastOffs = -1;	// so the next offset is 0
	}

	RIGHT_i_FOUND:
	/* From this point on we're sure i indexes the correct key in the table,
	....whether it was already there or just created  */
	printf("Key found in index table, will now search for value\n");

	int newOffs = keycount[i].lastOffs + 1;	// we'll start one after the last offset

	/* Next, we hash to key to find the right pod, and cycle through it looking for next pair  */
	int keyhash = hash_func(key);
	int zeroIfSame;
	while(newOffs < ENTRIES_PER_POD)
	{
		pod* thisKeysPodAddr = &(shared_store_addr->pods[keyhash]);
		// if the one we find is the right key
		zeroIfSame = strcmp(thisKeysPodAddr -> , key);
		if(zeroIfSame == 0)
		{
			// fill the return buffer with found value
			strcpy(retbuff, shared_store_addr -> pods[keyhash][newOffs].value);
			keycount[i].lastOffs = newOffs;
			break;
		}
		newOffs++;
	}
	if(strlen(retbuff) == 0)
	{
		printf("E:\t no new value found for key:\t %s", key);
		return NULL;
	}
	else
	{
		return retbuff;
	}
}

char** kv_store_read_all(char *key)
{
	/* TODO: call read(key) until dup value obtained? */
}

//char** kv_store_read_all(char* key){}

int kv_delete_db()
{
	close(db_fd);
	munmap(shared_store_addr,sizeof(store));
	if (shm_unlink(dbname) == -1)
		return -1;
	// TODO: delete named semaphores
	printf("Deleted database:\t%s\n",dbname);
	return 0;
}

int test_rw(char *testkey, char *testval)
{
	printf("----------Testing R/W into database:\t%s----------------\n", dbname);
	printf("Will now try to write\t key:\t %s\t value:\t%s\n",testkey,testval);
	printf("store size:\t%d\n",sizeof(store));

	kv_store_write(testkey,testval);

	char *read = kv_store_read(testkey);

	printf("Read value:\t%s for key:\t%s\n",read, testkey);

	if(strcmp(read, testval) == 0)
	{
		printf("successfully found same value!\n\n");
	}
	else
	{
		printf("nuuu\n");
	}

	free(read);
	return 0;
}

int main(int argc, char** argv)
{
	kv_store_create("sharedb");
	test_rw(argv[1],argv[2]);
}


