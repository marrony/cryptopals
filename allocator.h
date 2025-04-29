#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "bytebuffer.h"

struct Allocator;

typedef Byte_Buffer (*Alloc_Fn)(struct Allocator*, size_t, const char*, size_t);
typedef void (*Free_Fn)(struct Allocator*, Byte_Buffer, const char*, size_t);
typedef size_t (*Save_Fn)(struct Allocator*, const char*, size_t);
typedef void (*Restore_Fn)(struct Allocator*, size_t, const char*, size_t);

typedef struct Allocator {
  Alloc_Fn alloc;
  Free_Fn free;
  Save_Fn save;
  Restore_Fn restore;
} Allocator;

#define ALLOC(a, n) (a)->alloc((a), (n), __FILE__, __LINE__)
#define FREE(a, b) (a)->free((a), (b), __FILE__, __LINE__)
#define SAVE(a) (a)->save((a), __FILE__, __LINE__)
#define RESTORE(a, b) (a)->restore((a), (b), __FILE__, __LINE__)

typedef struct Malloc_Allocator {
  Allocator alloc;
  size_t allocated;
} Malloc_Allocator;

typedef struct Malloc_Entry {
  size_t nbytes;
  const char* file;
  size_t line;
} Malloc_Entry;

#define MALLOC_CREATE() (Malloc_Allocator) { \
  .alloc = {                                 \
    .alloc = (Alloc_Fn)malloc_alloc,         \
    .free = (Free_Fn)malloc_free,            \
    .save = (Save_Fn)malloc_save,            \
    .restore = (Restore_Fn)malloc_restore,   \
  },                                         \
  .allocated = 0,                            \
}

Byte_Buffer malloc_alloc(Malloc_Allocator* alloc, size_t nbytes, const char* file, size_t line);
void malloc_free(Malloc_Allocator* alloc, Byte_Buffer buffer, const char* file, size_t line);
size_t malloc_save(Malloc_Allocator* alloc, const char* file, size_t line);
void malloc_restore(Malloc_Allocator* alloc, size_t allocated, const char* file, size_t line);

typedef struct Arena_Allocator {
  Allocator alloc;
  Byte_Buffer buffer;
  size_t allocated;
} Arena_Allocator;

#define ARENA_CREATE(a, s) (Arena_Allocator) { \
  .alloc = {                                   \
    .alloc = (Alloc_Fn)arena_alloc,            \
    .free = (Free_Fn)arena_free,               \
    .save = (Save_Fn)arena_save,               \
    .restore = (Restore_Fn)arena_restore,      \
  },                                           \
  .buffer = ALLOC((a), (s)),                   \
  .allocated = 0,                              \
}

#define ARENA_DESTROY(alloc, arena) FREE((alloc), (arena)->buffer)

Byte_Buffer arena_alloc(Arena_Allocator* alloc, size_t nbytes, const char* file, size_t line);
void arena_free(Arena_Allocator* alloc, Byte_Buffer buffer, const char* file, size_t line);
size_t arena_save(Arena_Allocator* alloc, const char* file, size_t line);
void arena_restore(Arena_Allocator* alloc, size_t allocated, const char* file, size_t line);

#endif // ALLOCATOR_H

#ifdef ALLOCATOR_IMPLEMENATION

#ifndef ALLOCATOR_IMPLEMENATION_C
#define ALLOCATOR_IMPLEMENATION_C

#include "bytebuffer.h"

Byte_Buffer malloc_alloc(Malloc_Allocator* alloc, size_t nbytes, const char* file, size_t line) {
  (void)file;
  (void)line;

  uint8_t* ptr = malloc(nbytes + sizeof(Malloc_Entry));
  if (ptr == NULL)
    return EMPTY_BYTE_BUFFER;

  memset(ptr, 0, nbytes + sizeof(Malloc_Entry));

  Malloc_Entry* entry = (Malloc_Entry*)ptr;

  entry->nbytes = nbytes;
  entry->file = file;
  entry->line = line;

  alloc->allocated += nbytes;

  return (Byte_Buffer) { .ptr = ptr + sizeof(Malloc_Entry), .len = nbytes };
}

void malloc_free(Malloc_Allocator* alloc, Byte_Buffer buffer, const char* file, size_t line) {
  (void)file;
  (void)line;

  void* ptr = buffer.ptr - sizeof(Malloc_Entry);
  Malloc_Entry* entry = (Malloc_Entry*)ptr;

  size_t nbytes = entry->nbytes;

  if (nbytes != buffer.len) {
    if (buffer.len < nbytes)
      fprintf(stderr, "%s:%zu warning freeing less than allocated: %zu < %zu\n", entry->file, entry->line, buffer.len, nbytes);
    else
      fprintf(stderr, "%s:%zu warning freeing more than allocated: %zu != %zu\n", entry->file, entry->line, buffer.len, nbytes);
  }

  alloc->allocated -= nbytes;
  free(ptr);
}

size_t malloc_save(Malloc_Allocator* alloc, const char* file, size_t line) {
  (void)alloc;
  (void)file;
  (void)line;
  return 0;
}

void malloc_restore(Malloc_Allocator* alloc, size_t allocated, const char* file, size_t line) {
  (void)alloc;
  (void)allocated;
  (void)file;
  (void)line;
}

Byte_Buffer arena_alloc(Arena_Allocator* alloc, size_t nbytes, const char* file, size_t line) {
  (void)file;
  (void)line;

  size_t remaining = alloc->buffer.len - alloc->allocated;

  if (nbytes > remaining)
    return EMPTY_BYTE_BUFFER;

  void* ptr = alloc->buffer.ptr + alloc->allocated;

  memset(ptr, 0, nbytes);

  alloc->allocated += nbytes;

  return (Byte_Buffer) { .ptr = ptr, .len = nbytes };
}

void arena_free(Arena_Allocator* alloc, Byte_Buffer buffer, const char* file, size_t line) {
  (void)alloc;
  (void)buffer;
  (void)file;
  (void)line;
}

size_t arena_save(Arena_Allocator* alloc, const char* file, size_t line) {
  (void)file;
  (void)line;
  return alloc->allocated;
}

void arena_restore(Arena_Allocator* alloc, size_t allocated, const char* file, size_t line) {
  (void)file;
  (void)line;
  alloc->allocated = allocated;
}

#endif // ALLOCATOR_IMPLEMENATION_C

#endif // ALLOCATOR_IMPLEMENATION
