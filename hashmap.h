#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "allocator.h"
#include "bytebuffer.h"

typedef struct {
  Byte_Buffer key;
  Byte_Buffer value;
  bool occupied;
} HashMap_Entry;

typedef size_t (*HashMap_Hash_Fn)(Byte_Buffer);
typedef bool (*HashMap_Equal_Fn)(Byte_Buffer, Byte_Buffer);
typedef void (*HashMap_Free_Fn)(Allocator*, Byte_Buffer);

typedef struct {
  Allocator* alloc;
  HashMap_Entry* table;
  size_t capacity;
  size_t size;

  HashMap_Hash_Fn hash_key;
  HashMap_Equal_Fn equal_key;
  HashMap_Free_Fn free_key;
  HashMap_Free_Fn free_value;
} HashMap;

HashMap* hashmap_create(Allocator* alloc, size_t capacity, HashMap_Hash_Fn hash_key,
    HashMap_Equal_Fn equal_key, HashMap_Free_Fn free_key, HashMap_Free_Fn free_value);
void hashmap_destroy(HashMap* hashmap);
size_t hashmap_probe_index(size_t hash, size_t i, size_t capacity);
bool hashmap_put(HashMap* hashmap, Byte_Buffer key, Byte_Buffer value);
Byte_Buffer hashmap_get(HashMap* hashmap, Byte_Buffer key);
bool hashmap_contains(HashMap* hashmap, Byte_Buffer key);
bool hashmap_remove(HashMap* hashmap, Byte_Buffer key);
bool hashmap_resize(HashMap* hashmap, size_t new_capacity);

#endif // HASHMAP_H

#ifdef HASHMAP_IMPLMENTATION

#ifndef HASHMAP_IMPLMENTATION_C
#define HASHMAP_IMPLMENTATION_C

HashMap* hashmap_create(Allocator* alloc, size_t capacity, HashMap_Hash_Fn hash_key,
    HashMap_Equal_Fn equal_key, HashMap_Free_Fn free_key, HashMap_Free_Fn free_value) {
  Byte_Buffer hashmap_buffer = ALLOC(alloc, sizeof(HashMap));
  Byte_Buffer table_buffer = ALLOC(alloc, capacity * sizeof(HashMap_Entry));

  HashMap* hashmap = (HashMap*)hashmap_buffer.ptr;

  hashmap->alloc = alloc;
  hashmap->table = (HashMap_Entry*)table_buffer.ptr;
  hashmap->capacity = capacity;
  hashmap->size = 0;

  hashmap->hash_key = hash_key;
  hashmap->equal_key = equal_key;
  hashmap->free_key = free_key;
  hashmap->free_value = free_value;

  return hashmap;
}

void hashmap_destroy(HashMap* hashmap) {
  for (size_t i = 0; i < hashmap->capacity; i++) {
    HashMap_Entry* entry = hashmap->table + i;

    if (entry->occupied) {
      if (hashmap->free_key != NULL)
        hashmap->free_key(hashmap->alloc, entry->key);

      if (hashmap->free_value != NULL)
      hashmap->free_value(hashmap->alloc, entry->value);
    }
  }

  Byte_Buffer table_buffer = { .ptr = (uint8_t*)hashmap->table, .len = hashmap->capacity*sizeof(HashMap_Entry) };
  FREE(hashmap->alloc, table_buffer);

  Byte_Buffer hashmap_buffer = { .ptr = (uint8_t*)hashmap, .len = sizeof(HashMap) };
  FREE(hashmap->alloc, hashmap_buffer);
}

size_t hashmap_probe_index(size_t hash, size_t i, size_t capacity) {
  return (hash + i) % capacity;
}

bool hashmap_resize(HashMap* hashmap, size_t new_capacity);

bool hashmap_put(HashMap* hashmap, Byte_Buffer key, Byte_Buffer value) {
  float factor = (float)(hashmap->size + 1) / (float)hashmap->capacity;

  if (factor > 0.7 && !hashmap_resize(hashmap, hashmap->capacity * 2)) {
    return false;
  }

  size_t hash = hashmap->hash_key(key);

  for (size_t i = 0; i < hashmap->capacity; i++) {
    size_t index = hashmap_probe_index(hash, i, hashmap->capacity);
    HashMap_Entry* entry = hashmap->table + index;

    if (!entry->occupied) {
      entry->key = key;
      entry->value = value;
      entry->occupied = true;
      hashmap->size += 1;
      return true;
    } else if (entry->occupied && hashmap->equal_key(entry->key, key)) {
      if (hashmap->free_value != NULL)
        hashmap->free_value(hashmap->alloc, entry->value);
      entry->value = value;
      return true;
    }
  }

  return false;
}

Byte_Buffer hashmap_get(HashMap* hashmap, Byte_Buffer key) {
  size_t hash = hashmap->hash_key(key);

  for (size_t i = 0; i < hashmap->capacity; i++) {
    size_t index = hashmap_probe_index(hash, i, hashmap->capacity);
    HashMap_Entry* entry = hashmap->table + index;

    if (!entry->occupied) {
      break;
    }

    if (entry->occupied && hashmap->equal_key(entry->key, key)) {
      return entry->value;
    }
  }

  return EMPTY_BYTE_BUFFER;
}

bool hashmap_contains(HashMap* hashmap, Byte_Buffer key) {
  return !byte_buffer_empty(hashmap_get(hashmap, key));
}

bool hashmap_remove(HashMap* hashmap, Byte_Buffer key) {
  size_t hash = hashmap->hash_key(key);

  for (size_t i = 0; i < hashmap->capacity; i++) {
    size_t index = hashmap_probe_index(hash, i, hashmap->capacity);
    HashMap_Entry* entry = hashmap->table + index;

    if (!entry->occupied) {
      break;
    }

    if (entry->occupied && hashmap->equal_key(entry->key, key)) {
      if (hashmap->free_key != NULL)
        hashmap->free_key(hashmap->alloc, entry->key);

      if (hashmap->free_value != NULL)
        hashmap->free_value(hashmap->alloc, entry->value);

      entry->key = EMPTY_BYTE_BUFFER;
      entry->value = EMPTY_BYTE_BUFFER;
      entry->occupied = false;
      hashmap->size -= 1;
      return true;
    }
  }

  return false;
}

bool hashmap_resize(HashMap* hashmap, size_t new_capacity) {
  HashMap_Entry* old_table = hashmap->table;
  size_t old_capacity = hashmap->capacity;

  Byte_Buffer new_table_buffer = ALLOC(hashmap->alloc, new_capacity*sizeof(HashMap_Entry));

  HashMap_Entry* new_table = (HashMap_Entry*)new_table_buffer.ptr;
  if (new_table == NULL)
    return false;

  hashmap->table = new_table;
  hashmap->capacity = new_capacity;
  hashmap->size = 0;

  for (size_t i = 0; i < old_capacity; i++) {
    HashMap_Entry* entry = old_table + i;

    if (entry->occupied)
      hashmap_put(hashmap, entry->key, entry->value);
  }

  Byte_Buffer old_table_buffer = { .ptr = (uint8_t*)old_table, .len = old_capacity*sizeof(HashMap_Entry) };
  FREE(hashmap->alloc, old_table_buffer);
  return true;
}

#endif // HASHMAP_IMPLMENTATION_C

#endif // HASHMAP_IMPLMENTATION
