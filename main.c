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

#include "allocator.h"
#include "bytebuffer.h"
#include "hashset.h"

Byte_Buffer from_cstring(Allocator* alloc, const char* cstr) {
  size_t length = strlen(cstr);

  Byte_Buffer buffer = ALLOC(alloc, length);

  if (buffer.ptr != NULL) {
    strncpy(buffer.cptr, cstr, length);
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
Byte_Buffer bytes_to_base64(Allocator* alloc, Byte_Buffer bytes, bool padding) {
  size_t bits_len = bytes.len * 8;
  size_t base64_len = (bits_len + 5) / 6;

  size_t padding_len = padding ? base64_len % 4 : 0;

  Byte_Buffer base64 = ALLOC(alloc, base64_len + padding_len);
  if (base64.ptr != NULL) {
    size_t out_size = 0;

    for (size_t in = 0; in < bytes.len - 2; in += 3) {
      unsigned char b0 = AT(bytes, in+0);
      unsigned char b1 = AT(bytes, in+1);
      unsigned char b2 = AT(bytes, in+2);

      unsigned int bits = ((unsigned int)b0 << 16) | ((unsigned int)b1 << 8) | (unsigned int)b2;

      AT(base64, out_size++) = base64_encode[(bits >> 18) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 12) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 6) & 0x3f];
      AT(base64, out_size++) = base64_encode[bits & 0x3f];
    }

    if (bytes.len % 3 == 2) {
      unsigned char b0 = AT(bytes, bytes.len - 2);
      unsigned char b1 = AT(bytes, bytes.len - 1);

      unsigned int bits = ((unsigned int)b0 << 16) | ((unsigned int)b1 << 8);

      AT(base64, out_size++) = base64_encode[(bits >> 18) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 12) & 0x3f];
      //AT(base64, out_size++) = base64_encode[(bits >> 6) & 0x3f];
    }

    if (bytes.len % 3 == 1) {
      unsigned char b0 = AT(bytes, bytes.len - 1);

      unsigned int bits = (unsigned int)b0 << 16;

      AT(base64, out_size++) = base64_encode[(bits >> 18) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 12) & 0x3f];
    }

    for (size_t i = 0; i < padding_len; i++)
      AT(base64, out_size++) = '=';

    assert(out_size == base64_len+padding_len);
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

  char* end = content.cptr + content.len;

  char* src = content.cptr;
  char* dst = content.cptr;

  while (src < end && *src) {
    if (!isspace(*src)) *dst++ = *src;
    // if (*src != '\n' && *src != '\r') *dst++ = *src;
    src++;
  }

  return byte_buffer_slice(content, 0, dst - content.cptr);
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

Byte_Buffer single_key_xor(Byte_Buffer buffer, Byte_Buffer plaintext, uint8_t key) {
  assert(buffer.len == plaintext.len);

  if (buffer.ptr != NULL) {
    for (size_t i = 0; i < plaintext.len; i++) {
      AT(buffer, i) = AT(plaintext, i) ^ key;
    }
  }

  return buffer;
}

Byte_Buffer repeating_key_xor(Byte_Buffer buffer, Byte_Buffer plaintext, Byte_Buffer key) {
  assert(buffer.len == plaintext.len);

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

Byte_Buffer encode_aes_128_ecb_buffer(Allocator* alloc, size_t data_len) {
  return ALLOC(alloc, data_len + 16);
}

/* Electronic Code Block */
Byte_Buffer encode_aes_128_ecb(Byte_Buffer out, Byte_Buffer key, Byte_Buffer data, bool padding) {
  if (key.len != 16)
    return EMPTY_BYTE_BUFFER;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  EVP_CIPHER_CTX_init(ctx);

  if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (unsigned char*)key.ptr, NULL)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  if (!EVP_CIPHER_CTX_set_padding(ctx, padding)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  int block_size = EVP_CIPHER_CTX_block_size(ctx);

  if (out.len < data.len + block_size) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  unsigned char* buffer = (unsigned char*)out.ptr;
  int final_size = 0;
  int outlen = 0;

  if (!EVP_EncryptUpdate(ctx, buffer + final_size, &outlen, (unsigned char*)data.ptr, data.len)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  final_size += outlen;

  outlen = 0;
  if (!EVP_EncryptFinal_ex(ctx, buffer + final_size, &outlen)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  final_size += outlen;

  assert(EVP_CIPHER_CTX_get_key_length(ctx) == 16);
  assert(block_size == 16);

  EVP_CIPHER_CTX_free(ctx);

  out.len = final_size;

  return out;
}

Byte_Buffer decode_aes_128_ecb_buffer(Allocator* alloc, size_t data_len) {
  return ALLOC(alloc, data_len + 16);
}

/* Cipher Block Chaining */
Byte_Buffer decode_aes_128_ecb(Byte_Buffer out, Byte_Buffer key, Byte_Buffer data, bool padding) {
  if (key.len != 16)
    return EMPTY_BYTE_BUFFER;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  EVP_CIPHER_CTX_init(ctx);

  if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (unsigned char*)key.ptr, NULL)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  if (!EVP_CIPHER_CTX_set_padding(ctx, padding)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  int block_size = EVP_CIPHER_CTX_block_size(ctx);

  if (out.len < data.len + block_size) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  unsigned char* buffer = (unsigned char*)out.ptr;
  int final_size = 0;
  int outlen = 0;

  if (!EVP_DecryptUpdate(ctx, buffer + final_size, &outlen, (unsigned char*)data.ptr, data.len)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  final_size += outlen;

  outlen = 0;
  if (!EVP_DecryptFinal_ex(ctx, buffer + final_size, &outlen)) {
    EVP_CIPHER_CTX_free(ctx);
    return EMPTY_BYTE_BUFFER;
  }

  final_size += outlen;

  assert(EVP_CIPHER_CTX_get_key_length(ctx) == 16);
  assert(block_size == 16);

  EVP_CIPHER_CTX_free(ctx);

  out.len = final_size;

  return out;
}

size_t align_to(size_t value, size_t align) {
  return (value + (align - 1)) & (~align + 1);
}

Byte_Buffer pkcs7(Byte_Buffer out, Byte_Buffer block) {
  size_t block_size = out.len;
  size_t padding = block.len >= block_size ? 0 : block_size - (block.len % block_size);

  memcpy(out.ptr, block.ptr, block.len);
  memset(out.ptr+block.len, (int)padding, padding);

  return out;
}

Byte_Buffer pkcs7_undo(Byte_Buffer out, Byte_Buffer block) {
  if (block.len == 0 || out.len != block.len) {
    return EMPTY_BYTE_BUFFER;
  }

  size_t padding = AT(block, block.len - 1);

  if (padding < block.len) {
    size_t count = 0;

    for (size_t i = block.len - padding; i < block.len; i++)
      count += (size_t)AT(block, i) == padding;

    if (count == padding)
      out.len = block.len - padding;
  }

  memcpy(out.ptr, block.ptr, out.len);

  return out;
}

Byte_Buffer encode_aes_128_cbc_buffer(Allocator* alloc, Byte_Buffer data) {
  return ALLOC(alloc, align_to(data.len, 16));
}

Byte_Buffer encode_aes_128_cbc(Allocator* alloc, Byte_Buffer out, Byte_Buffer key, Byte_Buffer iv, Byte_Buffer data) {
  size_t allocated = SAVE(alloc);

  Byte_Buffer prev_block = ALLOC(alloc, 16);
  memcpy(prev_block.ptr, iv.ptr, 16);

  Byte_Buffer block = ALLOC(alloc, 16);
  Byte_Buffer buffer = ALLOC(alloc, 16+16);

  size_t out_offset = 0;
  size_t in_offset = 0;
  while (in_offset < data.len) {
    size_t len = in_offset+16 < data.len ? 16 : data.len - in_offset;

    pkcs7(block, byte_buffer_slice(data, in_offset, len));
    repeating_key_xor(block, block, prev_block);
    Byte_Buffer encoded = encode_aes_128_ecb(buffer, key, block, false);

    assert(encoded.len == 16);

    memcpy(&AT(out, out_offset), encoded.ptr, encoded.len);
    out_offset += encoded.len;

    in_offset += 16;
    memcpy(prev_block.ptr, encoded.ptr, encoded.len);
  }

  RESTORE(alloc, allocated);

  FREE(alloc, buffer);
  FREE(alloc, block);
  FREE(alloc, prev_block);

  assert(out_offset == out.len);
  return out;
}

Byte_Buffer decode_aes_128_cbc_buffer(Allocator* alloc, Byte_Buffer data) {
  return ALLOC(alloc, align_to(data.len, 16));
}

Byte_Buffer decode_aes_128_cbc(Allocator* alloc, Byte_Buffer out, Byte_Buffer key, Byte_Buffer data) {
  size_t allocated = SAVE(alloc);

  Byte_Buffer prev_block = ALLOC(alloc, 16);
  memset(prev_block.ptr, 0, 16);

  Byte_Buffer block = ALLOC(alloc, 16);
  Byte_Buffer buffer = ALLOC(alloc, 16+16);

  size_t in_offset = 0;
  size_t out_offset = 0;
  while (in_offset < data.len) {
    size_t len = in_offset+16 < data.len ? 16 : data.len - in_offset;

    Byte_Buffer ciphertext = byte_buffer_slice(data, in_offset, len);
    Byte_Buffer decoded = decode_aes_128_ecb(buffer, key, ciphertext, false);

    assert(decoded.len == 16);

    repeating_key_xor(block, decoded, prev_block);

    Byte_Buffer x = pkcs7_undo(block, block);

    memcpy(&AT(out, out_offset), x.ptr, x.len);
    out_offset += x.len;

    in_offset += 16;
    memcpy(prev_block.ptr, ciphertext.ptr, ciphertext.len);
  }

  RESTORE(alloc, allocated);

  FREE(alloc, buffer);
  FREE(alloc, block);
  FREE(alloc, prev_block);

  //assert(out_offset == out.len);

  out.len = out_offset;
  return out;
}

size_t hash_blob(Byte_Buffer key) {
#if 1
  size_t hash = 0;
  for (size_t i = 0; i < key.len; i++) {
    hash = 7*hash + AT(key, i);
  }
  return hash;
#else
  size_t hash = 5381;
  for (size_t i = 0; i < key.len; i++) {
    hash = ((hash << 5) + hash) + (AT(key, i) & 0xff);
  }
  return hash;
#endif
}

bool eq_blob(Byte_Buffer a, Byte_Buffer b) {
  if (a.len != b.len) return false;
  return memcmp(a.ptr, b.ptr, b.len) == 0;
}

void free_key(Allocator* alloc, Byte_Buffer key) {
  FREE(alloc, key);
}

void free_value(Allocator* alloc, Byte_Buffer value) {
  FREE(alloc, value);
}

size_t detect_key_size(Byte_Buffer bytes) {
  float norm_dist = FLT_MAX;
  size_t key_size = 0;

  for (size_t size = 2; size < 40; size++) {
    size_t sum = 0;
    size_t count = 0;

    for (size_t offset0 = 0; offset0 < bytes.len - size; offset0 += size) {
      Byte_Buffer str0 = byte_buffer_slice(bytes, offset0, size);

      for (size_t offset1 = offset0; offset1 < bytes.len - size; offset1 += size) {
        Byte_Buffer str1 = byte_buffer_slice(bytes, offset1, size);

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

  return key_size;
}

const char* detect_encoding(Allocator* alloc, Byte_Buffer encoded, size_t block_size) {
  HashSet* set = hashset_create(alloc, 1024, hash_blob, eq_blob, NULL);

  for (size_t i = 0; i < encoded.len; i += block_size) {
    hashset_put(set, byte_buffer_slice(encoded, i, block_size));
  }

  size_t blocks_count = encoded.len / block_size;
  char* inferred_mode = set->size < blocks_count ? "ecb" : "cbc";

  hashset_destroy(set);

  return inferred_mode;
}

size_t rand_between(size_t start, size_t end) {
  return rand() % (end - start + 1) + start;
}

Byte_Buffer byte_buffer_filled(Allocator* alloc, size_t size, uint8_t byte) {
  Byte_Buffer bytes = ALLOC(alloc, size);
  memset(bytes.ptr, byte, size);
  return bytes;
}

Byte_Buffer byte_buffer_concat(Allocator* alloc, Byte_Buffer a, Byte_Buffer b) {
  Byte_Buffer data = ALLOC(alloc, a.len + b.len);
  memcpy(data.ptr, a.ptr, a.len);
  memcpy(data.ptr+a.len, b.ptr, b.len);
  return data;
}

Byte_Buffer byte_buffer_random(Allocator* alloc, size_t size) {
  Byte_Buffer bytes = ALLOC(alloc, size);
  for (size_t i = 0; i < size; i++)
    AT(bytes, i) = rand_between(0, 255);
  return bytes;
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
    Byte_Buffer base64 = bytes_to_base64(alloc, bytes, false);

    assert(strncmp("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", base64.cptr, base64.len) == 0);

    FREE(alloc, base64);
    FREE(alloc, bytes);
    FREE(alloc, hex);
  }

  RESTORE(alloc, 0);

  // challenge 2
  {
    Byte_Buffer hex1 = from_cstring(alloc, "1c0111001f010100061a024b53535009181c");
    Byte_Buffer hex2 = from_cstring(alloc, "686974207468652062756c6c277320657965");

    Byte_Buffer bytes1 = hex_to_bytes(alloc, hex1);
    Byte_Buffer bytes2 = hex_to_bytes(alloc, hex2);

    assert(bytes1.len == bytes2.len);

    Byte_Buffer xor = fixed_xor(alloc, bytes1, bytes2);
    Byte_Buffer hex = bytes_to_hex(alloc, xor);

    assert(strncmp("746865206b696420646f6e277420706c6179", hex.cptr, hex.len) == 0);

    FREE(alloc, hex);
    FREE(alloc, xor);
    FREE(alloc, bytes2);
    FREE(alloc, bytes1);
    FREE(alloc, hex2);
    FREE(alloc, hex1);
  }

  RESTORE(alloc, 0);

  // challenge 3
  {
    Byte_Buffer hex = from_cstring(alloc, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    Byte_Buffer bytes = hex_to_bytes(alloc, hex);

    uint8_t key;

    assert(find_xor_key(bytes, &key, NULL));
    assert(key == 0x58);

    Byte_Buffer plaintext = ALLOC(alloc, bytes.len);
    single_key_xor(plaintext, bytes, key);

    assert(strncmp("Cooking MC's like a pound of bacon", plaintext.cptr, plaintext.len) == 0);

    FREE(alloc, plaintext);
    FREE(alloc, bytes);
    FREE(alloc, hex);
  }

  RESTORE(alloc, 0);

  // challenge 4
  {
    Byte_Buffer content = read_entire_file(alloc, "4.txt");

    assert(content.ptr != NULL);

    size_t max_score = 0;
    uint8_t max_key = 0;
    Byte_Buffer message = EMPTY_BYTE_BUFFER;

    size_t allocated = SAVE(alloc);

    Byte_Buffer cursor = EMPTY_BYTE_BUFFER;

    while (byte_buffer_line(content, &cursor)) {
      RESTORE(alloc, allocated);

      Byte_Buffer bytes = hex_to_bytes(alloc, cursor);
      size_t score;
      uint8_t key;

      if (find_xor_key(bytes, &key, &score) && score > max_score) {
        max_score = score;
        max_key = key;
        message = cursor;
      }

      FREE(alloc, bytes);
    }

    assert(max_key != 0);

    Byte_Buffer bytes = hex_to_bytes(alloc, message);
    Byte_Buffer plaintext = ALLOC(alloc, bytes.len);
    single_key_xor(plaintext, bytes, max_key);

    assert(strncmp("Now that the party is jumping\n", plaintext.cptr, plaintext.len) == 0);

    FREE(alloc, plaintext);
    FREE(alloc, bytes);
    FREE(alloc, content);
  }

  RESTORE(alloc, 0);

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

    Byte_Buffer encrypted = ALLOC(alloc, plaintext.len);
    repeating_key_xor(encrypted, plaintext, key);
    Byte_Buffer hex = bytes_to_hex(alloc, encrypted);

    assert(strncmp(expected, hex.cptr, hex.len) == 0);

    FREE(alloc, hex);
    FREE(alloc, encrypted);
    FREE(alloc, key);
    FREE(alloc, plaintext);
  }

  RESTORE(alloc, 0);

  {
    Byte_Buffer str0 = from_cstring(alloc, "this is a test");
    Byte_Buffer str1 = from_cstring(alloc, "wokka wokka!!!");

    assert(hamming_distance(str0, str1) == 37);

    FREE(alloc, str1);
    FREE(alloc, str0);
  }

  RESTORE(alloc, 0);

  // challenge 6
  {
    Byte_Buffer content = read_entire_file(alloc, "6.txt");
    Byte_Buffer base64 = remove_line_breaks(content);
    Byte_Buffer bytes = base64_to_bytes(alloc, base64);

    assert(bytes.ptr != NULL);

    size_t key_size = detect_key_size(bytes);

    assert(key_size == 29);

    size_t block_size = (bytes.len + key_size - 1) / key_size;

    Byte_Buffer key_block = ALLOC(alloc, key_size);
    Byte_Buffer block_alloc = ALLOC(alloc, block_size);
    size_t last_block_len = bytes.len - (key_size - 1) * block_size;
    size_t rest = key_size - (block_size - last_block_len);

    for (size_t key = 0; key < key_size; key++) {
      size_t allocated = SAVE(alloc);

      Byte_Buffer block = byte_buffer_slice(block_alloc, 0, key < rest ? block_alloc.len : block_alloc.len - 1);

      for (size_t i = 0; i < block.len; i++) {
        size_t index = i*key_size + key;
        AT(block, i) = AT(bytes, index);
      }

      uint8_t xor_key;
      assert(find_xor_key(block, &xor_key, NULL));
      AT(key_block, key) = xor_key;

      RESTORE(alloc, allocated);
    }

    assert(strncmp("Terminator X: Bring the noise", key_block.cptr, key_block.len) == 0);

    Byte_Buffer decrypted = ALLOC(alloc, bytes.len);
    repeating_key_xor(decrypted, bytes, key_block);

    assert(strncmp(decrypted.cptr, "I'm back and I'm ringin' the bell\n", 33) == 0);

    FREE(alloc, decrypted);
    FREE(alloc, block_alloc);
    FREE(alloc, key_block);
    FREE(alloc, bytes);
    FREE(alloc, content);
  }

  RESTORE(alloc, 0);

  // challenge 7
  {
    // openssl aes-128-ecb -a -d -in 7.txt -K $(echo -n "YELLOW SUBMARINE" | xxd -ps)

    SSL_load_error_strings();

    Byte_Buffer content = read_entire_file(alloc, "7.txt");
    Byte_Buffer base64 = remove_line_breaks(content);
    Byte_Buffer bytes = base64_to_bytes(alloc, base64);
    Byte_Buffer key = from_cstring(alloc, "YELLOW SUBMARINE");
    Byte_Buffer buffer = ALLOC(alloc, bytes.len + 16);

    assert(bytes.ptr != NULL);

    Byte_Buffer data = decode_aes_128_ecb(buffer, key, bytes, true);

    assert(data.len == 2876);
    assert(strncmp(data.cptr, "I'm back and I'm ringin' the bell \n", 34) == 0);

    FREE(alloc, buffer);
    FREE(alloc, key);
    FREE(alloc, bytes);
    FREE(alloc, content);
  }

  RESTORE(alloc, 0);

  // challenge 8
  {
    Byte_Buffer content = read_entire_file(alloc, "8.txt");

    assert(content.ptr != NULL);

    size_t max_duplicates = 0;
    Byte_Buffer message = EMPTY_BYTE_BUFFER;

    size_t allocated = SAVE(alloc);

    Byte_Buffer cursor = EMPTY_BYTE_BUFFER;

    while (byte_buffer_line(content, &cursor)) {
      RESTORE(alloc, allocated);

      Byte_Buffer bytes = hex_to_bytes(alloc, cursor);

      HashSet* set = hashset_create(alloc, 256, hash_blob, eq_blob, NULL);

      for (size_t i = 0; i < bytes.len; i += 16) {
        hashset_put(set, byte_buffer_slice(bytes, i, 16));
      }

      size_t duplicates = bytes.len/16 - set->size;

      hashset_destroy(set);

      FREE(alloc, bytes);

      if (duplicates > max_duplicates) {
        max_duplicates = duplicates;
        message = cursor;
      }
    }

    RESTORE(alloc, allocated);

    assert(message.len == 320);
    assert(strncmp(message.cptr, "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283", 64) == 0);

    FREE(alloc, content);
  }

  RESTORE(alloc, 0);

  // challenge 9
  {
    Byte_Buffer plaintext = from_cstring(alloc, "YELLOW SUBMARINE");
    Byte_Buffer padded = pkcs7(ALLOC(alloc, 20), plaintext);

    assert(padded.len == 20);
    assert(strncmp(padded.cptr, "YELLOW SUBMARINE\x04\x04\x04\x04", 20) == 0);

    FREE(alloc, padded);
    FREE(alloc, plaintext);
  }

  RESTORE(alloc, 0);

  // challenge 10
  {
    // openssl aes-128-cbc -a -d -in 10.txt -K $(echo -n "YELLOW SUBMARINE" | xxd -ps) -iv 0

    Byte_Buffer content = read_entire_file(alloc, "10.txt");
    Byte_Buffer base64 = remove_line_breaks(content);
    Byte_Buffer bytes_encoded = base64_to_bytes(alloc, base64);
    Byte_Buffer key = from_cstring(alloc, "YELLOW SUBMARINE");

    Byte_Buffer decoded_buffer = decode_aes_128_cbc_buffer(alloc, bytes_encoded);
    Byte_Buffer decoded = decode_aes_128_cbc(alloc, decoded_buffer, key, bytes_encoded);

    Byte_Buffer encoded_buffer = encode_aes_128_cbc_buffer(alloc, decoded);
    Byte_Buffer iv = ALLOC(alloc, 16);
    memset(iv.ptr, 0, iv.len);
    Byte_Buffer encoded = encode_aes_128_cbc(alloc, encoded_buffer, key, iv, decoded);

    Byte_Buffer base64_2 = bytes_to_base64(alloc, encoded, false);

    assert(bytes_encoded.len == encoded.len);

    assert(base64.len == base64_2.len);
    assert(memcmp(base64.ptr, base64_2.ptr, base64.len) == 0);

    FREE(alloc, iv);
    FREE(alloc, base64_2);
    FREE(alloc, encoded_buffer);
    FREE(alloc, decoded_buffer);
    FREE(alloc, key);
    FREE(alloc, bytes_encoded);
    FREE(alloc, content);
  }

  RESTORE(alloc, 0);

  // challenge 11
  {
    srand(time(NULL));

    Byte_Buffer random_key = byte_buffer_random(alloc, 16);
    Byte_Buffer iv = byte_buffer_random(alloc, 16);

    size_t prefix_len = rand_between(5, 10);
    size_t suffix_len = rand_between(5, 10);
    size_t data_len = rand_between(256, 1024);

    Byte_Buffer data = ALLOC(alloc, data_len + suffix_len + prefix_len);

    for (size_t i = 0; i < prefix_len; i++) AT(data, i) = rand_between(0, 255);
    for (size_t i = 0; i < data_len; i++) AT(data, prefix_len+i) = 'A';
    for (size_t i = 0; i < suffix_len; i++) AT(data, prefix_len+data_len+i) = rand_between(0, 255);

    Byte_Buffer encoding_buffer = EMPTY_BYTE_BUFFER;
    Byte_Buffer encoded = EMPTY_BYTE_BUFFER;

    char* actual_mode = NULL;

    if (rand_between(0, 100) < 50) {
      actual_mode = "cbc";

      encoding_buffer = encode_aes_128_cbc_buffer(alloc, data);
      encoded = encode_aes_128_cbc(alloc, encoding_buffer, random_key, iv, data);
    } else {
      actual_mode = "ecb";

      encoding_buffer = encode_aes_128_ecb_buffer(alloc, data.len);
      encoded = encode_aes_128_ecb(encoding_buffer, random_key, data, true);
    }

    const char* inferred_mode = detect_encoding(alloc, encoded, 16);

    FREE(alloc, encoding_buffer);
    FREE(alloc, data);
    FREE(alloc, iv);
    FREE(alloc, random_key);

    assert(strncmp(actual_mode, inferred_mode, 3) == 0);
  }

  RESTORE(alloc, 0);

  // challenge 12
  {
    srand(69);

    Byte_Buffer unknown_base64 = from_cstring(alloc, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                                                     "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                                                     "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                                                     "YnkK");
    Byte_Buffer unknown_bytes = base64_to_bytes(alloc, unknown_base64);

    Byte_Buffer key = byte_buffer_random(alloc, 16);
    Byte_Buffer input_data = byte_buffer_filled(alloc, unknown_bytes.len * 2, 0);
    Byte_Buffer target_buffer = encode_aes_128_ecb_buffer(alloc, input_data.len);
    Byte_Buffer test_buffer = encode_aes_128_ecb_buffer(alloc, input_data.len);
    Byte_Buffer decoded = byte_buffer_filled(alloc, unknown_bytes.len, 0);

    memcpy(input_data.ptr, unknown_bytes.ptr, unknown_bytes.len);
    size_t initial_len = encode_aes_128_ecb(target_buffer, key, byte_buffer_slice(input_data, 0, unknown_bytes.len), true).len;

    size_t block_size = 0;

    size_t i = 1;
    while (i < unknown_bytes.len) {
      memset(input_data.ptr, 'A', i);
      memcpy(input_data.ptr+i, unknown_bytes.ptr, unknown_bytes.len);
      size_t new_len = encode_aes_128_ecb(target_buffer, key, byte_buffer_slice(input_data, 0, i + unknown_bytes.len), true).len;

      if (new_len > initial_len) {
        block_size = new_len - initial_len;
        break;
      }
      i += 1;
    }

    assert(block_size == 16);

    for (size_t i = 0; i < unknown_bytes.len; i++) {
      size_t padding_len = block_size - (i % block_size) - 1;
      size_t block_index = i / block_size;

      memset(input_data.ptr, 'A', padding_len);
      memcpy(input_data.ptr + padding_len, unknown_bytes.ptr, unknown_bytes.len);
      Byte_Buffer target_block = byte_buffer_slice(
          encode_aes_128_ecb(target_buffer, key, byte_buffer_slice(input_data, 0, padding_len + unknown_bytes.len), true),
          block_index * block_size,
          16
      );

      memset(input_data.ptr, 'A', padding_len);
      memcpy(input_data.ptr + padding_len, decoded.ptr, i);
      AT(input_data, padding_len + i) = 0xff;

      size_t input_len = padding_len + i + 1;
      size_t rem_len = input_data.len - input_len;
      size_t copy_len = rem_len < unknown_bytes.len ? rem_len : unknown_bytes.len;
      memcpy(input_data.ptr + input_len, unknown_bytes.ptr, copy_len);
      input_len += copy_len;

      bool found = false;
      for (size_t ch = 0; ch < 256; ch++) {
        uint8_t test_ch = ch;

        AT(input_data, padding_len + i) = test_ch;

        Byte_Buffer test_block = byte_buffer_slice(
            encode_aes_128_ecb(test_buffer, key, byte_buffer_slice(input_data, 0, input_len), true),
            block_index * block_size,
            16
        );

        if (memcmp(target_block.ptr, test_block.ptr, 16) == 0) {
          AT(decoded, i) = test_ch;
          found = true;
          break;
        }
      }

      assert(found);
    }

    assert(memcmp(decoded.ptr, unknown_bytes.ptr, unknown_bytes.len) == 0);

    assert(strncmp(
          "Rollin' in my 5.0\n"
          "With my rag-top down so my hair can blow\n"
          "The girlies on standby waving just to say hi\n"
          "Did you stop? No, I just drove by\n",
          decoded.cptr,
          decoded.len) == 0
    );

    FREE(alloc, decoded);
    FREE(alloc, test_buffer);
    FREE(alloc, target_buffer);
    FREE(alloc, input_data);
    FREE(alloc, key);
    FREE(alloc, unknown_bytes);
    FREE(alloc, unknown_base64);
  }

  ARENA_DESTROY(&mallocator.alloc, &arena);

  printf("Malloc Allocated: %zu\n", mallocator.allocated);
  printf("Arena Allocated: %zu\n", arena.allocated);

  return 0;
}

