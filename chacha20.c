#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define DWORD_SIZE_BIT      32      // 32 bits in a DWORD

#define CHACHA20_CONSTANT   "expand 32-byte k"
#define CHACHA20_ROUNDS     20

#define KEY_LENGTH_BYTES    32      // 256 bits key length
#define IV_LENGTH_BYTES     16      // 128 bits initialization vector

#define KEY_LENGTH_HEX      64      // 64 hexadecimal characters for 256 bits key
#define IV_LENGTH_HEX       32      // 32 hexadecimal characters for 128 bits initialization vector

#define BUFFER_SIZE_BYTES   64      // Buffer size for reading and writing data

/**
 * ChaCha20 state structure.
 *
 * The ChaCha20 state consists of four detail blocks and a counter.
 *
 * The detail blocks are:
 * - constant: 4 DWORDs (f1, f2, f3, f4)
 * - key: 8 DWORDs (k1, k2, k3, k4, k5, k6, k7, k8)
 * - counter: 1 DWORD (c)
 * - nonce: 3 DWORDs (n1, n2, n3)
 *
 * +----+----+----+----+
 * | f1 | f2 | f3 | f4 |
 * +----+----+----+----+
 * | k1 | k2 | k3 | k4 |
 * +----+----+----+----+
 * | k5 | k6 | k7 | k8 |
 * +----+----+----+----+
 * |  c | n1 | n2 | n3 |
 * +----+----+----+----+
 * The counter is incremented after each block.
 *
 * As openssl's implementation, key and nonce are in little endian order.
 * The first 8 hex characters(32 bits) of the iv represents the counter.
 */

typedef struct chacha20_state_detail_s chacha20_state_detail_t;
struct chacha20_state_detail_s {
    unsigned char constant[16];     // 4 DWORD
    unsigned char key[32];          // 8 DWORD
    uint32_t counter;               // 1 DWORD
    unsigned char nonce[12];        // 3 DWORD
};

typedef struct chacha20_block_s chacha20_block_t;
struct chacha20_block_s {
    uint32_t constant[4];
    uint32_t key[8];
    uint32_t counter;
    uint32_t nonce[3];
};

typedef union chacha20_state_u chacha20_state_t;
union chacha20_state_u {
    unsigned char bytes[64];
    uint32_t dwords[16];
    chacha20_state_detail_t detail;
    chacha20_block_t block;
};

void chacha20_state_init(chacha20_state_t *state, const unsigned char *key, const unsigned char *iv)
{
    memset(state, 0, sizeof(*state));
    memcpy(state->detail.constant, CHACHA20_CONSTANT, sizeof(state->detail.constant));
    memcpy(state->detail.key, key, sizeof(state->detail.key));
    memcpy(&state->detail.counter, iv, sizeof(state->detail.counter));
    memcpy(state->detail.nonce, iv + sizeof(state->detail.counter), sizeof(state->detail.nonce));
}

void chacha20_print_state(const chacha20_state_t *state)
{
    printf("+----+----+----+----+    +------------+------------+------------+------------+\n");
    printf("| f1 | f2 | f3 | f4 |    | 0x%08x | 0x%08x | 0x%08x | 0x%08x |\n",
           state->block.constant[0], state->block.constant[1], state->block.constant[2], state->block.constant[3]);
    printf("+----+----+----+----+    +------------+------------+------------+------------+\n");
    printf("| k1 | k2 | k3 | k4 |    | 0x%08x | 0x%08x | 0x%08x | 0x%08x |\n",
           state->block.key[0], state->block.key[1], state->block.key[2], state->block.key[3]);
    printf("+----+----+----+----+ => +------------+------------+------------+------------+\n");
    printf("| k5 | k6 | k7 | k8 |    | 0x%08x | 0x%08x | 0x%08x | 0x%08x |\n",
           state->block.key[4], state->block.key[5], state->block.key[6], state->block.key[7]);
    printf("+----+----+----+----+    +------------+------------+------------+------------+\n");
    printf("|  c | n1 | n2 | n3 |    | 0x%08x | 0x%08x | 0x%08x | 0x%08x |\n",
           state->block.counter, state->block.nonce[0], state->block.nonce[1], state->block.nonce[2]);
    printf("+----+----+----+----+    +------------+------------+------------+------------+\n");
}

uint32_t chacha20_op_rotate_left(uint32_t block, int32_t shift)
{
    return (block << shift) | (block >> (DWORD_SIZE_BIT - shift));
}

void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b;
    *d ^= *a;
    *d = chacha20_op_rotate_left(*d, 16);

    *c += *d;
    *b ^= *c;
    *b = chacha20_op_rotate_left(*b, 12);

    *a += *b;
    *d ^= *a;
    *d = chacha20_op_rotate_left(*d, 8);

    *c += *d;
    *b ^= *c;
    *b = chacha20_op_rotate_left(*b, 7);
}

chacha20_state_t *chacha20_create_keystream(const chacha20_state_t *initial_state)
{
    uint32_t                    idx;
    uint32_t                    round;
    chacha20_state_t           *keystream = NULL;

    keystream = malloc(sizeof(chacha20_state_t));
    if (keystream == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        return NULL;
    }
    memcpy(keystream, initial_state, sizeof(chacha20_state_t));

    for (round = 1; round <= CHACHA20_ROUNDS; round++) {
        if (round % 2 == 0) {
            // Even round
            chacha20_quarter_round(&keystream->dwords[0], &keystream->dwords[5], &keystream->dwords[10], &keystream->dwords[15]);
            chacha20_quarter_round(&keystream->dwords[1], &keystream->dwords[6], &keystream->dwords[11], &keystream->dwords[12]);
            chacha20_quarter_round(&keystream->dwords[2], &keystream->dwords[7], &keystream->dwords[ 8], &keystream->dwords[13]);
            chacha20_quarter_round(&keystream->dwords[3], &keystream->dwords[4], &keystream->dwords[ 9], &keystream->dwords[14]);
        } else {
            // Odd round
            chacha20_quarter_round(&keystream->dwords[0], &keystream->dwords[4], &keystream->dwords[ 8], &keystream->dwords[12]);
            chacha20_quarter_round(&keystream->dwords[1], &keystream->dwords[5], &keystream->dwords[ 9], &keystream->dwords[13]);
            chacha20_quarter_round(&keystream->dwords[2], &keystream->dwords[6], &keystream->dwords[10], &keystream->dwords[14]);
            chacha20_quarter_round(&keystream->dwords[3], &keystream->dwords[7], &keystream->dwords[11], &keystream->dwords[15]);
        }
    }

    for (idx = 0; idx < 64; idx++)
        keystream->bytes[idx] += initial_state->bytes[idx];

    return keystream;
}

void chacha20_destroy_keystream(chacha20_state_t *keystream) {
    if (keystream != NULL) {
        free(keystream);
        keystream = NULL;
    }
}

bool hex_char_to_value(char in_char, unsigned char *out_byte)
{
    if ('0' <= in_char && in_char <= '9') {
        *out_byte = in_char - '0';
        return true;
    }
    if ('a' <= in_char && in_char <= 'f') {
        *out_byte = in_char - 'a' + 10;
        return true;
    }
    if ('A' <= in_char && in_char <= 'F') {
        *out_byte = in_char - 'A' + 10;
        return true;
    }
    fprintf(stderr, "Invalid hex character: %c\n", in_char);
    return false;
}

bool hex_string_to_bytes(const char *hex_str, unsigned char *out_bytes, size_t out_bytes_length)
{
    size_t                      hex_str_len = 0;
    size_t                      i = 0;
    bool                        return_value = false;
    bool                        result;
    unsigned char               nib1, nib2;

    hex_str_len = strlen(hex_str);
    if (out_bytes_length * 2 != hex_str_len) {
        fprintf(stderr, "Invalid hex string length. Expected %zu characters.\n", out_bytes_length * 2);
        goto end;
    }

    for (i = 0; i < out_bytes_length; i++) {
        nib1 = 0;
        nib2 = 0;

        result = hex_char_to_value(hex_str[i * 2], &nib1);
        if (!result) goto end;

        result = hex_char_to_value(hex_str[i * 2 + 1], &nib2);
        if (!result) goto end;
        
        out_bytes[i] = (nib1 << 4) | nib2;
    }

    return_value = true;

end:
    return return_value;
}

int main(int argc, char *argv[])
{
    int32_t                     return_code = EXIT_FAILURE;
    FILE                       *input_file  = NULL;
    FILE                       *output_file = NULL;
    uint32_t                    key_len = 0;
    uint32_t                    iv_len = 0;
    size_t                      bytes_read = 0;
    size_t                      idx = 0;
    bool                        result;
    char                        buffer[BUFFER_SIZE_BYTES];
    unsigned char               key[KEY_LENGTH_BYTES];
    unsigned char               iv[IV_LENGTH_BYTES];
    char                       *key_hex = NULL;
    char                       *iv_hex = NULL;
    chacha20_state_t            initial_state;
    chacha20_state_t           *keystream = NULL;

    key_hex = (char*)malloc(KEY_LENGTH_HEX + 1);
    iv_hex = (char*)malloc(IV_LENGTH_HEX + 1);
    if (key_hex == NULL || iv_hex == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        goto end;
    }

    memset(buffer, 0, BUFFER_SIZE_BYTES);
    memset(key, 0, KEY_LENGTH_BYTES);
    memset(iv, 0, IV_LENGTH_BYTES);
    memset(key_hex, '0', KEY_LENGTH_HEX);
    memset(iv_hex, '0', IV_LENGTH_HEX);
    key_hex[KEY_LENGTH_HEX] = 0;
    iv_hex[IV_LENGTH_HEX] = 0;

    if (argc != 5) {
        printf("Usage: %s <input_file> <output_file> <key-hex-str> <iv-hex-str>\n", argv[0]);
        goto end;
    }

    input_file = fopen(argv[1], "rb");
    if (input_file == NULL) {
        perror("Error opening input file\n");
        goto end;
    }

    output_file = fopen(argv[2], "wb");
    if (output_file == NULL) {
        perror("Error opening output file\n");
        goto end;
    }

    key_len = strlen(argv[3]);
    if (key_len > KEY_LENGTH_HEX) {
        printf("key: hex string is too long, ignoring excess\n");
        strncpy(key_hex, argv[3], KEY_LENGTH_HEX);
    } else if (key_len < KEY_LENGTH_HEX) {
        printf("key: hex string is too short, padding with zero bytes to length\n");
        strncpy(key_hex, argv[3], key_len);
    } else {
        strncpy(key_hex, argv[3], KEY_LENGTH_HEX);
    }

    iv_len = strlen(argv[4]);
    if (iv_len > IV_LENGTH_HEX) {
        printf("iv: hex string is too long, ignoring excess\n");
        strncpy(iv_hex, argv[4], IV_LENGTH_HEX);
    } else if (iv_len < IV_LENGTH_HEX) {
        printf("iv: hex string is too short, padding with zero bytes to length\n");
        strncpy(iv_hex, argv[4], iv_len);
    } else {
        strncpy(iv_hex, argv[4], IV_LENGTH_HEX);
    }

    result = hex_string_to_bytes(key_hex, key, KEY_LENGTH_BYTES);
    if (!result) goto end;
    result = hex_string_to_bytes(iv_hex, iv, IV_LENGTH_BYTES);
    if (!result) goto end;

    printf("key=%s\n", key_hex);
    printf("iv =%s\n", iv_hex);

    chacha20_state_init(&initial_state, key, iv);
    printf("Initial state:\n");
    chacha20_print_state(&initial_state);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE_BYTES);
        bytes_read = fread(buffer, sizeof(char), BUFFER_SIZE_BYTES, input_file);
        if (bytes_read == 0)
            break;

        keystream = chacha20_create_keystream(&initial_state);
        for (idx = 0; idx < bytes_read; idx++) {
            buffer[idx] ^= keystream->bytes[idx];
        }
        fwrite(buffer, sizeof(char), bytes_read, output_file);
        initial_state.block.counter++;
    }
end:
    if (input_file != NULL) 
        fclose(input_file);
    if (output_file != NULL)
        fclose(output_file);
    if (key_hex != NULL)
        free(key_hex);
    if (iv_hex != NULL)
        free(iv_hex);
    chacha20_destroy_keystream(keystream);
    return return_code;
}
