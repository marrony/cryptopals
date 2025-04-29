#ifndef HASHSET_H
#define HASHSET_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "allocator.h"

typedef struct {
  Byte_Buffer key;
  bool occupied;
} HashSet_Entry;

typedef size_t (*HashSet_Hash_Fn)(Byte_Buffer);
typedef bool (*HashSet_Equal_Fn)(Byte_Buffer, Byte_Buffer);
typedef void (*HashSet_Free_Fn)(Allocator*, Byte_Buffer);

typedef struct {
  Allocator* alloc;
  HashSet_Entry* table;
  size_t capacity;
  size_t size;

  HashSet_Hash_Fn hash_key;
  HashSet_Equal_Fn equal_key;
  HashSet_Free_Fn free_key;
} HashSet;

HashSet* hashset_create(Allocator* alloc, size_t capacity, HashSet_Hash_Fn hash_key,
    HashSet_Equal_Fn equal_key, HashSet_Free_Fn free_key);
void hashset_destroy(HashSet* hashset);
size_t hashset_probe_index(size_t hash, size_t i, size_t capacity);
bool hashset_put(HashSet* hashset, Byte_Buffer key);
bool hashset_contains(HashSet* hashset, Byte_Buffer key);
bool hashset_remove(HashSet* hashset, Byte_Buffer key);
bool hashset_resize(HashSet* hashset, size_t new_capacity);

#endif // HASHSET_H

#ifdef HASHSET_IMPLMENTATION

#ifndef HASHSET_IMPLMENTATION_C
#define HASHSET_IMPLMENTATION_C

HashSet* hashset_create(Allocator* alloc, size_t capacity, HashSet_Hash_Fn hash_key,
    HashSet_Equal_Fn equal_key, HashSet_Free_Fn free_key) {
  Byte_Buffer hashset_buffer = ALLOC(alloc, sizeof(HashSet));
  Byte_Buffer table_buffer = ALLOC(alloc, capacity * sizeof(HashSet_Entry));

  HashSet* hashset = (HashSet*)hashset_buffer.ptr;

  hashset->alloc = alloc;
  hashset->table = (HashSet_Entry*)table_buffer.ptr;
  hashset->capacity = capacity;
  hashset->size = 0;

  hashset->hash_key = hash_key;
  hashset->equal_key = equal_key;
  hashset->free_key = free_key;

  return hashset;
}

void hashset_destroy(HashSet* hashset) {
  for (size_t i = 0; i < hashset->capacity; i++) {
    HashSet_Entry* entry = hashset->table + i;

    if (entry->occupied) {
      if (hashset->free_key != NULL)
        hashset->free_key(hashset->alloc, entry->key);
    }
  }

  Byte_Buffer table_buffer = { .ptr = (uint8_t*)hashset->table, .len = hashset->capacity*sizeof(HashSet_Entry) };
  FREE(hashset->alloc, table_buffer);

  Byte_Buffer hashset_buffer = { .ptr = (uint8_t*)hashset, .len = sizeof(HashSet) };
  FREE(hashset->alloc, hashset_buffer);
}

size_t hashset_probe_index(size_t hash, size_t i, size_t capacity) {
  return (hash + i) % capacity;
}

bool hashset_put(HashSet* hashset, Byte_Buffer key) {
  float factor = (float)(hashset->size + 1) / (float)hashset->capacity;

  if (factor > 0.7 && !hashset_resize(hashset, hashset->capacity * 2)) {
    return false;
  }

  size_t hash = hashset->hash_key(key);

  for (size_t i = 0; i < hashset->capacity; i++) {
    size_t index = hashset_probe_index(hash, i, hashset->capacity);
    HashSet_Entry* entry = hashset->table + index;

    if (!entry->occupied) {
      entry->key = key;
      entry->occupied = true;
      hashset->size += 1;
      return true;
    } else if (hashset->equal_key(entry->key, key)) {
      return false;
    }
  }

  return false;
}

bool hashset_contains(HashSet* hashset, Byte_Buffer key) {
  size_t hash = hashset->hash_key(key);

  for (size_t i = 0; i < hashset->capacity; i++) {
    size_t index = hashset_probe_index(hash, i, hashset->capacity);
    HashSet_Entry* entry = hashset->table + index;

    if (!entry->occupied) {
      break;
    }

    if (entry->occupied && hashset->equal_key(entry->key, key)) {
      return true;
    }
  }

  return false;
}

bool hashset_remove(HashSet* hashset, Byte_Buffer key) {
  size_t hash = hashset->hash_key(key);

  for (size_t i = 0; i < hashset->capacity; i++) {
    size_t index = hashset_probe_index(hash, i, hashset->capacity);
    HashSet_Entry* entry = hashset->table + index;

    if (!entry->occupied) {
      break;
    }

    if (entry->occupied && hashset->equal_key(entry->key, key)) {
      if (hashset->free_key != NULL)
        hashset->free_key(hashset->alloc, entry->key);

      entry->key = EMPTY_BYTE_BUFFER;
      entry->occupied = false;
      hashset->size -= 1;
      return true;
    }
  }

  return false;
}

bool hashset_resize(HashSet* hashset, size_t new_capacity) {
  HashSet_Entry* old_table = hashset->table;
  size_t old_capacity = hashset->capacity;

  Byte_Buffer new_table_buffer = ALLOC(hashset->alloc, new_capacity*sizeof(HashSet_Entry));

  HashSet_Entry* new_table = (HashSet_Entry*)new_table_buffer.ptr;
  if (new_table == NULL)
    return false;

  hashset->table = new_table;
  hashset->capacity = new_capacity;
  hashset->size = 0;

  for (size_t i = 0; i < old_capacity; i++) {
    HashSet_Entry* entry = old_table + i;

    if (entry->occupied)
      hashset_put(hashset, entry->key);
  }

  Byte_Buffer old_table_buffer = { .ptr = (uint8_t*)old_table, .len = old_capacity*sizeof(HashSet_Entry) };
  FREE(hashset->alloc, old_table_buffer);
  return true;
}

#endif // HASHSET_IMPLMENTATION_C

#endif // HASHSET_IMPLMENTATION
