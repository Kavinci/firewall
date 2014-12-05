#include "hashtable.h"

uint32_t hash_address(uint32_t address)
{
	uint32_t result = 0;
	int counter;
	uint8_t* byte = (uint8_t*)(&address);

	for (counter = 0; counter < 3; counter++)
		result ^= byte[counter];

	return result % 65521;
}

hashtable_t hashtable_init()
{
	hashtable_t tbl = (hashtable_t)malloc(sizeof(struct hashtable));
	int i;
	tbl->size = 0;
	tbl->capacity = INIT_CAP;
	for(i = 0; i < INIT_CAP; i++)
		tbl->buckets[i] = NULL;
	return tbl;
}

void* hashtable_get(hashtable_t tbl, uint32_t key) {
	uint32_t hash = key % tbl->capacity;
	hashtable_node_t curr = tbl->buckets[hash];
	while(curr != NULL) {
		if(curr->k == key) {
			return curr->v;
		}
		curr = curr->next;
	}
	return NULL;
}

int hashtable_contains(hashtable_t tbl,uint32_t comp) {
	return (hashtable_get(tbl, comp) != NULL);
}

int hashtable_size(hashtable_t tbl) {
	if(tbl == NULL) 
		return -1;
	else
		return tbl->size;
}

int hashtable_free(hashtable_t tbl) {
	int i;
	hashtable_node_t prev = NULL;
	hashtable_node_t curr;

	if(tbl == NULL) {
	printf("Null table as input to free\n");
	return -1;
	}

	for(i = 0;i<tbl->capacity;i++) {
	prev = NULL;
	curr = tbl->buckets[i];
	while(curr != NULL) {
		prev = curr;
		curr = curr->next;
		free(prev);
	}
	}
	free(tbl);
	return 0;
}

int hashtable_add_no_rehash(hashtable_t tbl, uint32_t key, void* val){
	uint32_t hash = hash_address(key) % tbl->capacity;
	hashtable_node_t to_add = (hashtable_node_t)malloc(sizeof(struct hashtable_node));

	if(to_add == NULL){
		printf("There was a problem allocating a new spot in the hashtable");
		return -1;
	}

	to_add->ip = key;
	to_add->data = val;
	to_add->next = NULL;

	if(tbl->buckets[hash] == NULL)
		tbl->buckets[hash] = to_add;
	else{
		hashtable_node_t last = get_last_in_seq(tbl->buckets[hash]);
		last->next = to_add;
	}
	++tbl->size;
	return 0;
}

int hashtable_add(hashtable_t tbl, uint32_t key, void* val){

	if(!hashtable_contains(tbl, key)){
		if((1.0 + tbl->size) / (tbl->capacity) > LOAD_FACTOR){
			hashtable_t old_table = tbl;
			int i;
			tbl = (hashtable_t)malloc(sizeof(struct hashtable));
			tbl->size = 0;
			tbl->capacity = 2*old_table->capacity;
			for(i = 0; i < tbl->capacity; i++)
				tbl->buckets[i] = NULL;

			for(i = 0; i < old_table->capacity; i++){
				hashtable_node_t node = old_table->buckets[i];
				hashtable_node_t temp;
				while(node != NULL){
					hashtable_add_no_rehash(tbl, node->ip, node->data);
					temp = node->next;
					free(node);
					node = temp;
				}
			}
			free(old_table);
		}
		return hashtable_add_no_rehash(tbl, key, val);
	}
	printf("Address already exists\n");
	return -2;
}