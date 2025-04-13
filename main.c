#include <assert.h>
#include <float.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

typedef struct {
  char* ptr;
  size_t len;
} Byte_Buffer;

#define EMPTY_BYTE_BUFFER (Byte_Buffer) { .ptr = NULL, .len = 0 }

char* assert_bounds(Byte_Buffer b, size_t n, const char* file, int line) {
  if (n >= b.len) {
    fprintf(stderr, "%s:%d: Array index out of bounds. %zu >= %zu\n", file, line, n, b.len);
    exit(1);
  }
  return b.ptr+n;
}

#define AT(b, n) *(assert_bounds((b), (n), __FILE__, __LINE__))

struct Allocator;

typedef Byte_Buffer (*Alloc_Fn)(struct Allocator*, size_t, const char*, size_t);
typedef void (*Free_Fn)(struct Allocator*, Byte_Buffer, const char*, size_t);

typedef struct Allocator {
  Alloc_Fn alloc;
  Free_Fn free;
} Allocator;

#define ALLOC(a, n) (a)->alloc((a), (n), __FILE__, __LINE__)
#define FREE(a, b) (a)->free((a), (b), __FILE__, __LINE__)

typedef struct Malloc_Allocator {
  Allocator alloc;
  size_t allocated;
} Malloc_Allocator;

typedef struct Malloc_Entry {
  size_t nbytes;
  const char* file;
  size_t line;
} Malloc_Entry;

Byte_Buffer malloc_alloc(Malloc_Allocator* alloc, size_t nbytes, const char* file, size_t line) {
  (void)file;
  (void)line;

  char* ptr = malloc(nbytes + sizeof(Malloc_Entry));
  if (ptr == NULL)
    return EMPTY_BYTE_BUFFER;

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

typedef struct Arena_Allocator {
  Allocator alloc;
  Byte_Buffer buffer;
  size_t allocated;
} Arena_Allocator;

Byte_Buffer arena_allocator_alloc(Arena_Allocator* alloc, size_t nbytes, const char* file, size_t line) {
  (void)file;
  (void)line;

  size_t remaining = alloc->buffer.len - alloc->allocated;

  if (nbytes > remaining)
    return EMPTY_BYTE_BUFFER;

  void* ptr = alloc->buffer.ptr + alloc->allocated;
  alloc->allocated += nbytes;

  return (Byte_Buffer) { .ptr = ptr, .len = nbytes };
}

void arena_allocator_free(Arena_Allocator* alloc, Byte_Buffer buffer, const char* file, size_t line) {
  (void)alloc;
  (void)buffer;
  (void)file;
  (void)line;
}

#define MALLOC_CREATE() (Malloc_Allocator) { \
  .alloc = {                                 \
    .alloc = (Alloc_Fn)malloc_alloc,         \
    .free = (Free_Fn)malloc_free,            \
  },                                         \
  .allocated = 0,                            \
}

#define ARENA_CREATE(a, s) (Arena_Allocator) { \
  .alloc = {                                   \
    .alloc = (Alloc_Fn)arena_allocator_alloc,  \
    .free = (Free_Fn)arena_allocator_free,     \
  },                                           \
  .buffer = ALLOC((a), (s)),                   \
  .allocated = 0,                              \
}

#define ARENA_DESTROY(alloc, arena) FREE((alloc), (arena)->buffer)

Byte_Buffer from_cstring(Allocator* alloc, const char* cstr) {
  size_t length = strlen(cstr);

  Byte_Buffer buffer = ALLOC(alloc, length);

  if (buffer.ptr != NULL) {
    strncpy(buffer.ptr, cstr, length);
  }

  return buffer;
}

#define FROM_HEX(ch) (((ch) >= 'a' ? (ch) - 'a' + 10 : (ch) - '0') & 0x0f)
#define TO_HEX(ch)   ((ch) >= 10 ? ((ch) - 10 + 'a') : ((ch) + '0'))

Byte_Buffer hex_to_bytes(Allocator* alloc, Byte_Buffer hex) {
  size_t size = hex.len / 2;

  Byte_Buffer buffer = ALLOC(alloc, size);
  if (buffer.ptr != NULL) {
    size_t out_size = 0;

    for (size_t i = 0; i < hex.len - 1; i += 2) {
      char ch_hi = FROM_HEX(AT(hex, i+0));
      char ch_lo = FROM_HEX(AT(hex, i+1));

      AT(buffer, out_size++) = (ch_hi << 4) | ch_lo;
    }
  }

  return buffer;
}

Byte_Buffer bytes_to_hex(Allocator* alloc, Byte_Buffer bytes) {
  Byte_Buffer buffer = ALLOC(alloc, bytes.len*2);

  if (buffer.ptr != NULL) {
    size_t out_size = 0;

    for (size_t i = 0; i < bytes.len; i++) {
      char ch_hi = AT(bytes, i) >> 4;
      char ch_lo = AT(bytes, i) & 0xf;

      AT(buffer, out_size++) = TO_HEX(ch_hi);
      AT(buffer, out_size++) = TO_HEX(ch_lo);
    }
  }

  return buffer;
}

const char base64_encode[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

const char base64_encode_url[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

// |xxxxxxyy|yyyyzzzz|zzwwwwww|
Byte_Buffer bytes_to_base64(Allocator* alloc, Byte_Buffer bytes) {
  size_t bits_len = bytes.len * 8;
  size_t base64_len = (bits_len + 5) / 6;

  Byte_Buffer base64 = ALLOC(alloc, base64_len);
  if (base64.ptr != NULL) {
    size_t out_size = 0;

    for (size_t in = 0; in < bytes.len - 2; in += 3) {
      int bits = ((int)AT(bytes, in+0) << 16) | ((int)AT(bytes, in+1) << 8) | (int)AT(bytes, in+2);

      AT(base64, out_size++) = base64_encode[(bits >> 18) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 12) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 6) & 0x3f];
      AT(base64, out_size++) = base64_encode[bits & 0x3f];
    }

    if (bytes.len % 3 == 2) {
      int bits = ((int)AT(bytes, bytes.len - 2) << 16) | ((int)AT(bytes, bytes.len - 1) << 8);

      AT(base64, out_size++) = base64_encode[(bits >> 18) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 12) & 0x3f];
    }

    if (bytes.len % 3 == 1) {
      int bits = (int)AT(bytes, bytes.len - 1) << 16;

      AT(base64, out_size++) = base64_encode[(bits >> 18) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 12) & 0x3f];
    }
  }

  return base64;
}

const char base64_decode[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

const char base64_decode_url[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

// |xxxxxxyy|yyyyzzzz|zzwwwwww|
Byte_Buffer base64_to_bytes(Allocator* alloc, Byte_Buffer base64) {
  if (base64.ptr == NULL)
    return EMPTY_BYTE_BUFFER;

  size_t in_size = base64.len;

  while (in_size > 0 && AT(base64, in_size - 1) == '=')
    in_size--;

  size_t out_size = in_size * 6 / 8;
  Byte_Buffer bytes = ALLOC(alloc, out_size);

  size_t base64_index = 0;
  size_t bytes_index = 0;

  while (base64_index+3 < in_size) {
    int i0 = base64_decode[(int)AT(base64, base64_index++)];
    int i1 = base64_decode[(int)AT(base64, base64_index++)];
    int i2 = base64_decode[(int)AT(base64, base64_index++)];
    int i3 = base64_decode[(int)AT(base64, base64_index++)];

    int bits = (i0 << 18) | (i1 << 12) | (i2 << 6) | (i3 << 0);

    AT(bytes, bytes_index++) = (bits >> 16) & 0xff;
    AT(bytes, bytes_index++) = (bits >> 8) & 0xff;
    AT(bytes, bytes_index++) = (bits >> 0) & 0xff;
  }

  size_t diff = in_size - base64_index;

  if (diff == 3) {
    // |xxxxxxyy|yyyyzzzz|zz000000|
    int i0 = base64_decode[(int)AT(base64, base64_index+0)];
    int i1 = base64_decode[(int)AT(base64, base64_index+1)];
    int i2 = base64_decode[(int)AT(base64, base64_index+2)];

    int bits = (i0 << 18) | (i1 << 12) | (i2 << 6);
    
    AT(bytes, bytes_index++) = (bits >> 16) & 0xff;
    AT(bytes, bytes_index++) = (bits >> 8) & 0xff;
  }

  if (diff == 2) {
    // |xxxxxxyy|yyyy0000|00000000|
    int i0 = base64_decode[(int)AT(base64, base64_index+0)];
    int i1 = base64_decode[(int)AT(base64, base64_index+1)];

    int bits = (i0 << 18) | (i1 << 12);

    AT(bytes, bytes_index++) = (bits >> 16) & 0xff;
  }

  if (diff == 1) {
    // |xxxxxx00|00000000|00000000|
    int i0 = base64_decode[(int)AT(base64, base64_index)];

    int bits = (i0 << 18);

    AT(bytes, bytes_index++) = (bits >> 16) & 0xff;
  }

  return bytes;
}

Byte_Buffer remove_line_breaks(Byte_Buffer content) {
  if (content.ptr == NULL)
    return EMPTY_BYTE_BUFFER;

  char* end = content.ptr + content.len;

  char* src = content.ptr;
  char* dst = content.ptr;

  while (src < end && *src) {
    if (!isspace(*src)) *dst++ = *src;
    // if (*src != '\n' && *src != '\r') *dst++ = *src;
    src++;
  }

  return (Byte_Buffer) { .ptr = content.ptr, .len = dst - content.ptr };
}

Byte_Buffer fixed_xor(Allocator* alloc, Byte_Buffer bytes0, Byte_Buffer bytes1) {
  if (bytes0.len != bytes1.len)
    return EMPTY_BYTE_BUFFER;

  Byte_Buffer buffer = ALLOC(alloc, bytes0.len);
  if (buffer.ptr != NULL) {
    for (size_t i = 0; i < bytes0.len; i++) {
      AT(buffer, i) = AT(bytes0, i) ^ AT(bytes1, i);
    }
  }

  return buffer;
}

const size_t english_freq[256] = {
   ['a'] =  651738, ['b'] =  124248, ['c'] =  217339, ['d'] =  349835,
   ['e'] = 1041442, ['f'] =  197881, ['g'] =  158610, ['h'] =  492888,
   ['i'] =  558094, ['j'] =    9033, ['k'] =   50529, ['l'] =  331490,
   ['m'] =  202124, ['n'] =  564513, ['o'] =  596302, ['p'] =  137645,
   ['q'] =    8606, ['r'] =  497563, ['s'] =  515760, ['t'] =  729357,
   ['u'] =  225134, ['v'] =   82903, ['w'] =  171272, ['x'] =   13692,
   ['y'] =  145984, ['z'] =    7836, [' '] = 1918182
};

bool find_xor_key(Byte_Buffer bytes, uint8_t* key_out, size_t* score_out) {
    // int32_t frequency[256] = {0};
    // const char english[] = "How? Devise some method for \"scoring\" a piece of"
    // " English plaintext. Character frequency is a good metric. Evaluate each"
    // " output and choose the one with the best score.";
    // for (size_t i = 0; i < sizeof(english) - 1; i++) {
    //   int ch = tolower(english[i]);
    //   frequency[ch]++;
    // }

    uint8_t key = 0;
    size_t max_score = 0;

    for (int candidate = 1; candidate < 255; candidate++) {
      size_t score = 0;

      for (size_t i = 0; i < bytes.len; i++) {
        int index = tolower(AT(bytes, i) ^ candidate);
        if (index < 0 || index > 255) {
          continue;
        }

        score += english_freq[index];
        // score += frequency[index];
      }

      if (score > max_score) {
        max_score = score;
        key = candidate;
      } 
    }

    if (score_out != NULL)
      *score_out = max_score;

    if (key_out != NULL)
      *key_out = key;

    return key != 0;
}

Byte_Buffer single_key_xor(Allocator* alloc, Byte_Buffer plaintext, uint8_t key) {
  Byte_Buffer buffer = ALLOC(alloc, plaintext.len);

  if (buffer.ptr != NULL) {
    for (size_t i = 0; i < plaintext.len; i++) {
      AT(buffer, i) = AT(plaintext, i) ^ key;
    }
  }

  return buffer;
}

Byte_Buffer repeating_key_xor(Allocator* alloc, Byte_Buffer plaintext, Byte_Buffer key) {
  Byte_Buffer buffer = ALLOC(alloc, plaintext.len);

  if (buffer.ptr != NULL) {
    for (size_t i = 0; i < plaintext.len; i++) {
      AT(buffer, i) = AT(plaintext, i) ^ AT(key, i % key.len);
    }
  }

  return buffer;
}

int hamming_distance(Byte_Buffer str0, Byte_Buffer str1) {
  if (str0.len != str1.len) return -1;

  int count = 0;

  for (size_t i = 0; i < str0.len; i++) {
    if (AT(str0, i) != AT(str1, i))
      count += __builtin_popcount(AT(str0, i) ^ AT(str1, i));
  }

  return count;
}

Byte_Buffer read_entire_file(Allocator* alloc, const char* file_name) {
    FILE* fp = fopen(file_name, "r");
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    Byte_Buffer buffer = ALLOC(alloc, file_size);
    if (buffer.ptr == NULL)
      goto error;

    if (fread(buffer.ptr, sizeof(char), file_size, fp) != file_size)
      goto error;

    fclose(fp);
    return buffer;

error:
    fclose(fp);
    return EMPTY_BYTE_BUFFER;
}

// Byte_Buffer encode_aes_128_ecb(Allocator* alloc, Byte_Buffer key, Byte_Buffer data) {
//   if (key.len != 16)
//     return EMPTY_BYTE_BUFFER;
//
//   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
//
//   EVP_CIPHER_CTX_init(ctx);
//
//   EVP_CIPHER_CTX_set_padding(ctx, false);
//
//   EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (unsigned char*)key.ptr, NULL);
//
//   unsigned char buffer[1024], *pointer = buffer;
//   int outlen;
//
//   EVP_EncryptUpdate(ctx, pointer, &outlen, (unsigned char*)data.ptr, data.len);
//
//   pointer += outlen;
//   EVP_EncryptFinal_ex(ctx, pointer, &outlen);
//   pointer += outlen;
//
//   return u_string(buffer, pointer-buffer);
// }

Byte_Buffer decode_aes_128_ecb(Allocator* alloc, Byte_Buffer key, Byte_Buffer data) {
  if (key.len != 16)
    return EMPTY_BYTE_BUFFER;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  EVP_CIPHER_CTX_init(ctx);

  if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (unsigned char*)key.ptr, NULL)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  if (!EVP_CIPHER_CTX_set_padding(ctx, true)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  int block_size = EVP_CIPHER_CTX_block_size(ctx);

  Byte_Buffer out = ALLOC(alloc, data.len + block_size);
  if (out.ptr == NULL)
    return EMPTY_BYTE_BUFFER;

  unsigned char* buffer = (unsigned char*)out.ptr;
  int final_size = 0;
  int outlen = 0;

  if (!EVP_DecryptUpdate(ctx, buffer + final_size, &outlen, (unsigned char*)data.ptr, data.len)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  final_size += outlen;

  if (!EVP_DecryptFinal_ex(ctx, buffer + final_size, &outlen)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  final_size += outlen;

  assert(EVP_CIPHER_CTX_get_key_length(ctx) == 16);

  EVP_CIPHER_CTX_free(ctx);

  out.len = final_size;

  return out;
}

int main(void) {
  Malloc_Allocator mallocator = MALLOC_CREATE();
  Arena_Allocator arena = ARENA_CREATE(&mallocator.alloc, 1024*1024);

#if 0
  Allocator* alloc = &arena.alloc;
#else
  Allocator* alloc = &mallocator.alloc;
#endif

  // challenge 1
  {
    Byte_Buffer hex = from_cstring(alloc, "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    Byte_Buffer bytes = hex_to_bytes(alloc, hex);
    Byte_Buffer base64 = bytes_to_base64(alloc, bytes);

    assert(strncmp("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", base64.ptr, base64.len) == 0);

    FREE(alloc, base64);
    FREE(alloc, bytes);
    FREE(alloc, hex);
  }

  arena.allocated = 0;

  // challenge 2
  {
    Byte_Buffer hex1 = from_cstring(alloc, "1c0111001f010100061a024b53535009181c");
    Byte_Buffer hex2 = from_cstring(alloc, "686974207468652062756c6c277320657965");

    Byte_Buffer bytes1 = hex_to_bytes(alloc, hex1);
    Byte_Buffer bytes2 = hex_to_bytes(alloc, hex2);

    assert(bytes1.len == bytes2.len);

    Byte_Buffer xor = fixed_xor(alloc, bytes1, bytes2);
    Byte_Buffer hex = bytes_to_hex(alloc, xor);

    assert(strncmp("746865206b696420646f6e277420706c6179", hex.ptr, hex.len) == 0);

    FREE(alloc, hex);
    FREE(alloc, xor);
    FREE(alloc, bytes2);
    FREE(alloc, bytes1);
    FREE(alloc, hex2);
    FREE(alloc, hex1);
  }

  arena.allocated = 0;

  // challenge 3
  {
    Byte_Buffer hex = from_cstring(alloc, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    Byte_Buffer bytes = hex_to_bytes(alloc, hex);

    uint8_t key;

    assert(find_xor_key(bytes, &key, NULL));
    assert(key == 0x58);

    Byte_Buffer plaintext = single_key_xor(alloc, bytes, key);

    assert(strncmp("Cooking MC's like a pound of bacon", plaintext.ptr, plaintext.len) == 0);

    FREE(alloc, plaintext);
    FREE(alloc, bytes);
    FREE(alloc, hex);
  }

  arena.allocated = 0;

  // challenge 4
  {
    Byte_Buffer content = read_entire_file(alloc, "4.txt");

    assert(content.ptr != NULL);

    size_t max_score = 0;
    uint8_t max_key = 0;
    Byte_Buffer message = EMPTY_BYTE_BUFFER;

    size_t allocated = arena.allocated;

    char* start = content.ptr;
    char* end = content.ptr + content.len;

    while (start < end) {
      size_t remainder = end - start;

      char* find = strnstr(start, "\n", remainder);

      if (find == NULL) {
        find = end;
      }

      size_t len = find - start;

      Byte_Buffer buf = {
        .ptr = start,
        .len = len,
      };

      if (find+1 >= end) {
        break;
      }

      start = find + strspn(find, "\n\r");

      arena.allocated = allocated;

      Byte_Buffer bytes = hex_to_bytes(alloc, buf);
      size_t score;
      uint8_t key;

      if (find_xor_key(bytes, &key, &score) && score > max_score) {
        max_score = score;
        max_key = key;
        message = buf;
      }

      FREE(alloc, bytes);
    }

    assert(max_key != 0);

    Byte_Buffer bytes = hex_to_bytes(alloc, message);
    Byte_Buffer plaintext = single_key_xor(alloc, bytes, max_key);

    assert(strncmp("Now that the party is jumping\n", plaintext.ptr, plaintext.len) == 0);

    FREE(alloc, plaintext);
    FREE(alloc, bytes);
    FREE(alloc, content);
  }

  arena.allocated = 0;

  // challenge 5
  {
    const char *text = "Burning 'em, if you ain't quick and nimble\n"
       "I go crazy when I hear a cymbal";
    const char *expected = "0b3637272a2b2e63622c2e69692a2369"
                           "3a2a3c6324202d623d63343c2a262263"
                           "24272765272a282b2f20430a652e2c65"
                           "2a3124333a653e2b2027630c692b2028"
                           "3165286326302e27282f";

    Byte_Buffer plaintext = from_cstring(alloc, text);
    Byte_Buffer key = from_cstring(alloc, "ICE");

    Byte_Buffer encrypted = repeating_key_xor(alloc, plaintext, key);
    Byte_Buffer hex = bytes_to_hex(alloc, encrypted);

    assert(strncmp(expected, hex.ptr, hex.len) == 0);

    FREE(alloc, hex);
    FREE(alloc, encrypted);
    FREE(alloc, key);
    FREE(alloc, plaintext);
  }

  arena.allocated = 0;

  {
    Byte_Buffer str0 = from_cstring(alloc, "this is a test");
    Byte_Buffer str1 = from_cstring(alloc, "wokka wokka!!!");

    assert(hamming_distance(str0, str1) == 37);

    FREE(alloc, str1);
    FREE(alloc, str0);
  }

  arena.allocated = 0;

  // challenge 6
  {
    Byte_Buffer base64 = remove_line_breaks(read_entire_file(alloc, "6.txt"));
    Byte_Buffer bytes = base64_to_bytes(alloc, base64);

    assert(bytes.ptr != NULL);

    float norm_dist = FLT_MAX;
    size_t key_size = 0;

    for (size_t size = 2; size < 40; size++) {
      size_t sum = 0;
      size_t count = 0;

      for (size_t offset0 = 0; offset0 < bytes.len - size; offset0 += size) {
        Byte_Buffer str0 = { .ptr = bytes.ptr + offset0, .len = size };

        for (size_t offset1 = offset0; offset1 < bytes.len - size; offset1 += size) {
          Byte_Buffer str1 = { .ptr = bytes.ptr + offset1, .len = size };

          sum += hamming_distance(str0, str1);
          count += 1;
        }
      }

      float norm = (float)sum / (count * size);

      if (norm < norm_dist) {
        norm_dist = norm;
        key_size = size;
      }
    }

    assert(key_size == 29);

    size_t block_size = (bytes.len + key_size - 1) / key_size;

    Byte_Buffer key_block = ALLOC(alloc, key_size);
    Byte_Buffer block_alloc = ALLOC(alloc, block_size);
    size_t last_block_len = bytes.len - (key_size - 1) * block_size;
    size_t rest = key_size - (block_size - last_block_len);

    for (size_t key = 0; key < key_size; key++) {
      size_t allocated = arena.allocated;

      Byte_Buffer block = {
        .ptr = block_alloc.ptr,
        .len = key < rest ? block_alloc.len : block_alloc.len - 1,
      };

      for (size_t i = 0; i < block.len; i++) {
        size_t index = i*key_size + key;
        AT(block, i) = AT(bytes, index);
      }

      uint8_t xor_key;
      assert(find_xor_key(block, &xor_key, NULL));
      AT(key_block, key) = xor_key;

      arena.allocated = allocated;
    }

    assert(strncmp("Terminator X: Bring the noise", key_block.ptr, key_block.len) == 0);

    Byte_Buffer decrypted = repeating_key_xor(alloc, bytes, key_block);

    assert(strncmp(decrypted.ptr, "I'm back and I'm ringin' the bell\n", 33) == 0);

    FREE(alloc, decrypted);
    FREE(alloc, block_alloc);
    FREE(alloc, key_block);
    FREE(alloc, bytes);
    FREE(alloc, base64);
  }

  arena.allocated = 0;

  // challenge 7
  {
    // openssl aes-128-ecb -a -d -in 7.txt -K $(echo -n "YELLOW SUBMARINE" | xxd -ps)

    SSL_load_error_strings();

    Byte_Buffer base64 = remove_line_breaks(read_entire_file(alloc, "7.txt"));
    Byte_Buffer bytes = base64_to_bytes(alloc, base64);
    Byte_Buffer key = from_cstring(alloc, "YELLOW SUBMARINE");

    assert(bytes.ptr != NULL);

    Byte_Buffer data = decode_aes_128_ecb(alloc, key, bytes);

    assert(data.len == 2876);
    assert(strncmp(data.ptr, "I'm back and I'm ringin' the bell \n", 34) == 0);

    FREE(alloc, data);
    FREE(alloc, key);
    FREE(alloc, bytes);
    FREE(alloc, base64);
  }

  arena.allocated = 0;

  // challenge 8
  {
    Byte_Buffer content = read_entire_file(alloc, "8.txt");

    assert(content.ptr != NULL);

    size_t max_duplicates = 0;
    Byte_Buffer message = EMPTY_BYTE_BUFFER;

    char* start = content.ptr;
    char* end = content.ptr + content.len;

    size_t allocated = arena.allocated;

    while (start < end) {
      size_t remainder = end - start;

      char* find = strnstr(start, "\n", remainder);

      if (find == NULL) {
        find = end;
      }

      size_t len = find - start;

      Byte_Buffer buf = {
        .ptr = start,
        .len = len,
      };

      if (find+1 >= end) {
        break;
      }

      start = find + strspn(find, "\n\r");

      arena.allocated = allocated;

      Byte_Buffer bytes = hex_to_bytes(alloc, buf);

      size_t duplicates = 0;

      for (size_t i = 0; i < bytes.len; i += 16) {
        char* b0 = &AT(bytes, i);

        for (size_t j = i + 16; j < bytes.len; j += 16) {
          char* b1 = &AT(bytes, j);

          if (memcmp(b0, b1, 16) == 0) {
            duplicates += 1;
          }
        }
      }

      FREE(alloc, bytes);

      if (duplicates > max_duplicates) {
        max_duplicates = duplicates;
        message = buf;
      }
    }

    arena.allocated = allocated;

    assert(strncmp(message.ptr, "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283", 64) == 0);

    FREE(alloc, content);
  }

  ARENA_DESTROY(&mallocator.alloc, &arena);

  printf("Malloc Allocated: %zu\n", mallocator.allocated);

  return 0;
}

