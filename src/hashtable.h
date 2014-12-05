#ifndef __HASHTABLE
#define __HASHTABLE

struct hashtable_node
{
	uint32_t k;
	void* v;
	struct hashtable_node* next;
};
typedef struct hashtable_node* hashtable_node_t;

struct hashtable {
	uint32_t size;
	uint32_t capacity;
	hashtable_node_t buckets[INIT_CAP];
};

typedef struct hashtable* hashtable_t;


// Hash function for a uint32 ip addr
uint32_t hash_address(uint32_t address);

void* hashtable_get(hashtable_t tbl, uint32_t key);

int hashtable_contains(hashtable_t tbl,uint32_t comp);

int hashtable_size(hashtable_t tbl);

int hashtable_free(hashtable_t tbl);

int hashtable_add(hashtable_t tbl, uint32_t key, void* val);


#endif