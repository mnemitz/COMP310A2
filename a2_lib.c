#include<stdlib.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<semaphore.h>
#include "a2_lib.h"
#define NUMBER_OF_PODS 256
#define ENTRIES_PER_POD 256
#define MAX_NUMBER_KEYS 257
#define KEYSIZE 32
#define VALUESIZE 256
#define DB_NAME_SIZE 20

/*
-----------------------
COMP310 WINTER 2017 ASSIGNMENT 2
Written by: Matthew Nemitz
260506071
-----------------------

Note to the grader:

This code is extremely buggy.

There was a bug in my code which I spent a while trying to resolve but ultimately couldn't figure out,
so I left it unresolved so that I would have time to implement the synchronization etc.

Basically the problem was that after just over 50 rounds of reading written values, it began to return values for keys
which the test says were not written for those keys.

But I only ever return a value after having just checked the key does match,
so I really don't see how it could possibly be returning bad values.

(Refer to my comments on the read and write methods)

The bug compounded pretty significantly once I added the semaphores, but since I didn't understand the root cause
of the original bug, I'm pretty unsure how to go about diagnosing this, I plan to come by office hours this week to
better understand where I went wrong. I feel like my code makes sense, but clearly I've missed something.

Apologies for the buggy code!

*/




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

sem_t resources[NUMBER_OF_PODS];
sem_t mutexes[NUMBER_OF_PODS];

// resources = Semaphores in dutch, we have one semaphore for each pod

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

	/* Now instantiate an empty store struct (ogStore), initializing each pod's write count to 0,
	then we memcpy it into the shared memory and free the heap memory */
	store *ogStore = malloc(sizeof(store));
	int i;
	for(i=0; i<NUMBER_OF_PODS; i++)
	{
		sem_init(&(resources[i]),0,1);	// initialized 2 unnamed semaphores per pod
		sem_init(&(mutexes[i]),0,1);
		ogStore->pods[i].writeIndx = 0;
	}

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
//	printf("Hash of key:\t%d\n",keyhash);


	/* wait for other writer, when ready, copy values in */

	sem_wait(&(resources[keyhash]));

	/* Then we find the pod this key hashes to:  */
	pod* thisKeysPodAddr = &(shared_store_addr -> pods[keyhash]);

	/* Define the destinations to write to */
	char* keydest = thisKeysPodAddr -> pairs[thisKeysPodAddr -> writeIndx].key;
	char* valdest = thisKeysPodAddr -> pairs[thisKeysPodAddr -> writeIndx].value;

	strcpy(keydest, key);
	strcpy(valdest, value);

	/* finally, increment the write count for this pod,
	...resetting it to 0 if we've reached the last element (mimics FIFO structure) */

	if(thisKeysPodAddr->writeIndx == ENTRIES_PER_POD - 1)
	{
		thisKeysPodAddr->writeIndx = 0;
	}
	else
	{
		thisKeysPodAddr->writeIndx++;
	}

	sem_post(&(resources[keyhash]));

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
	int i = 0;

	/* I'm using tuples (struct keycounts) to keep track of specific keys,
		and the index of their last read value  */

	/* Cycle through the key-count tuples until we find the key we want  */
	while(i < MAX_NUMBER_KEYS && strlen(keycount[i].key) != 0)
	{
		if (strcmp(keycount[i].key, key) == 0)	// if we find it, stop looking
		{
			break;
		}
		i++;
	}
	if(i == MAX_NUMBER_KEYS)			// if we went all the way without finding it....
	{
		printf("E:\t Reached capacity of %d keys, not found\n", MAX_NUMBER_KEYS);
		return NULL;
	}

	// otherwise, if we're on the first empty tuple, or if the count is maxed out
	else if (strlen(keycount[i].key) == 0 || keycount[i].lastOffs >= ENTRIES_PER_POD-1)
	{
		// brand new keycount pair
		strcpy(keycount[i].key, key);
		keycount[i].lastOffs = -1;	// <- so that the newOffs can be 0
	}

	int newOffs = keycount[i].lastOffs + 1;	// start one after last read value
	int podIndx = hash_func(key);		// find correct pod

	sem_wait(&(mutexes[podIndx]));

	pod* rightPod = &(shared_store_addr -> pods[podIndx]);
	pair* currPair;

	while(newOffs < ENTRIES_PER_POD)
	{
		currPair = &(rightPod->pairs[newOffs]);	// look at each pair in the pod from here on...

		if(strcmp(currPair->key, key) == 0)	// if its key matches the given key...
		{
			strcpy(retbuff, currPair->value);	// ...take its value, and update the last read offset
			keycount[i].lastOffs = newOffs;
			break;	// stop looking at pairs
		}

		newOffs++;
	}

	sem_post(&(mutexes[podIndx]));

	if(strlen(retbuff) == 0)
	{
		return NULL;
	}
	else
	{
		return retbuff;
	}
}


char** kv_store_read_all(char *key)
{
	char** ret = malloc(ENTRIES_PER_POD*sizeof(char*));
	char* currRead;
	int i;

	for(i=0; i<ENTRIES_PER_POD; i++)
	{
		ret[i] = malloc(VALUESIZE*sizeof(char));
		strcpy(ret[i], "\0");
	}

	int foundDup = 0;

	while(currRead = kv_store_read(key), currRead != NULL)
	{
		for(i=0; (i < ENTRIES_PER_POD) && (strlen(ret[i]) > 0); i++)
		{
			printf("for loop\n");
			if(strcmp(currRead, ret[i]) == 0)
			{
				foundDup = 1;
				break;
			}
		}

		if(foundDup)
		{
			break;
		}
		else
		{
			strcpy(ret[i], currRead);
		}

	}
	return ret;

}

//char** kv_store_read_all(char* key){}

int kv_delete_db()
{
	close(db_fd);

	int i;
	for(i=0;i<NUMBER_OF_PODS;i++)	// destroy the unnamed semaphores
	{
		sem_destroy(&(resources[i]));
	}

	munmap(shared_store_addr,sizeof(store));
	if (shm_unlink(dbname) == -1)
		return -1;
	printf("Deleted database:\t%s\n",dbname);
	return 0;
}

/*
int main(int argc, char** argv)
{
	kv_store_create("sharedb");
	kv_store_write("A","a1");
	kv_store_write("A","a2");
	kv_store_write("A","a3");
	kv_store_write("A","a4");
	kv_store_write("A","a5");
	kv_store_write("A","a6");
	kv_store_write("A","a7");
	kv_store_write("A","a8");
	kv_store_write("A","a9");
	kv_store_write("A","a10");

        kv_store_write("B","b1");
        kv_store_write("B","b2");
        kv_store_write("B","b3");
        kv_store_write("B","b4");
        kv_store_write("B","b5");
        kv_store_write("B","b6");
        kv_store_write("B","b7");
        kv_store_write("B","b8");
        kv_store_write("B","b9");
        kv_store_write("B","b10");

	char** readallA = kv_store_read_all("A");

	int i;
	for(i=0; i<ENTRIES_PER_POD;i++)
	{
		printf("A:\t%s\n",readallA[i]);
		free(readallA[i]);
	}
	free(readallA);
	kv_delete_db();
	return 0;

}


*/
