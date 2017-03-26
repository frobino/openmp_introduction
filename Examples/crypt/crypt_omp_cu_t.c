#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <omp.h>
#include "gperftools/profiler.h"

/*
 * The crypt application implements IDEA encryption and decryption of a single
 * input file using the secret key provided.
 */

// Chunking size for IDEA, in bytes
#define CHUNK_SIZE  8
// Length of the encryption/decryption keys, in bytes
#define KEY_LENGTH  52
#define BLOCK_SIZE_IN_CHUNKS    1024000
// Length of the secret key, in bytes
#define USERKEY_LENGTH  8
#define BITS_PER_BYTE   8

typedef enum { ENCRYPT, DECRYPT } action;

uint32_t dkey[KEY_LENGTH];

/*
 * doCrypt implements the core logic of IDEA. It iterates over the byte
 * chunks stored in plainList and outputs their encrypted/decrypted form to the
 * corresponding element in cryptList using the secret key provided.
 */
void doCrypt(uint32_t chunk, int8_t *plain,
	     int8_t *crypt, uint32_t *key)
{
    uint64_t x1, x2, x3, x4, t1, t2, ik, r;

    x1  = (((uint32_t)plain[chunk * CHUNK_SIZE]) & 0xff);
    x1 |= ((((uint32_t)plain[chunk * CHUNK_SIZE + 1]) & 0xff) <<
           BITS_PER_BYTE);
    x2  = (((uint32_t)plain[chunk * CHUNK_SIZE + 2]) & 0xff);
    x2 |= ((((uint32_t)plain[chunk * CHUNK_SIZE + 3]) & 0xff) <<
           BITS_PER_BYTE);
    x3  = (((uint32_t)plain[chunk * CHUNK_SIZE + 4]) & 0xff);
    x3 |= ((((uint32_t)plain[chunk * CHUNK_SIZE + 5]) & 0xff) <<
           BITS_PER_BYTE);
    x4  = (((uint32_t)plain[chunk * CHUNK_SIZE + 6]) & 0xff);
    x4 |= ((((uint32_t)plain[chunk * CHUNK_SIZE + 7]) & 0xff) <<
           BITS_PER_BYTE);
    ik  = 0;
    r = CHUNK_SIZE;

    do
    {
        x1 = (uint32_t)((((uint64_t)x1 * key[ik++]) % 0x10001L) & 0xffff);
        x2 = ((x2 + key[ik++]) & 0xffff);
        x3 = ((x3 + key[ik++]) & 0xffff);
        x4 = (uint32_t)((((uint64_t)x4 * key[ik++]) % 0x10001L) & 0xffff);

        t2 = (x1 ^ x3);
        t2 = (uint32_t)((((uint64_t)t2 * key[ik++]) % 0x10001L) & 0xffff);

        t1 = ((t2 + (x2 ^ x4)) & 0xffff);
        t1 = (uint32_t)((((uint64_t)t1 * key[ik++]) % 0x10001L) & 0xffff);
        t2 = (t1 + t2 & 0xffff);

        x1 = (x1 ^ t1);
        x4 = (x4 ^ t2);
        t2 = (t2 ^ x2);
        x2 = (x3 ^ t1);
        x3 = t2;
    }
    while(--r != 0);

    x1 = (uint32_t)((((uint64_t)x1 * key[ik++]) % 0x10001L) & 0xffff);
    x3 = ((x3 + key[ik++]) & 0xffff);
    x2 = ((x2 + key[ik++]) & 0xffff);
    x4 = (uint32_t)((((uint64_t)x4 * key[ik++]) % 0x10001L) & 0xffff);

    crypt[chunk * CHUNK_SIZE]     = (int8_t) x1;
    crypt[chunk * CHUNK_SIZE + 1] = (int8_t) ((uint64_t)x1 >>
                                    BITS_PER_BYTE);
    crypt[chunk * CHUNK_SIZE + 2] = (int8_t) x3;
    crypt[chunk * CHUNK_SIZE + 3] = (int8_t) ((uint64_t)x3 >>
                                    BITS_PER_BYTE);
    crypt[chunk * CHUNK_SIZE + 4] = (int8_t) x2;
    crypt[chunk * CHUNK_SIZE + 5] = (int8_t) ((uint64_t)x2 >>
                                    BITS_PER_BYTE);
    crypt[chunk * CHUNK_SIZE + 6] = (int8_t) x4;
    crypt[chunk * CHUNK_SIZE + 7] = (int8_t) ((uint64_t)x4 >>
                                    BITS_PER_BYTE);
}

static void h_encrypt_decrypt(int8_t *plain, int8_t *crypt, uint32_t *key,
                              uint32_t plainLength)
{
    uint32_t c;
    uint32_t nChunks = plainLength / CHUNK_SIZE;
    #pragma omp parallel for firstprivate(nChunks) private(c)
    for (c = 0; c < nChunks; c++)
    {
        doCrypt(c, plain, crypt, key);
    }
}

/*
 * Get the length of a file on disk.
 */
static size_t getFileLength(FILE *fp)
{
    fseek(fp, 0L, SEEK_END);
    size_t fileLen = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    return (fileLen);
}

/*
 * inv is used to generate the key used for decryption from the secret key.
 */
static uint32_t inv(uint32_t x)
{
    uint32_t t0, t1;
    uint32_t q, y;

    if (x <= 1)             // Assumes positive x.
        return (x);          // 0 and 1 are self-inverse.

    t1 = 0x10001 / x;       // (2**16+1)/x; x is >= 2, so fits 16 bits.
    y = 0x10001 % x;

    if (y == 1)
        return ((1 - t1) & 0xffff);

    t0 = 1;

    do
    {
        q = x / y;
        x = x % y;
        t0 += q * t1;

        if (x == 1) return (t0);

        q = y / x;
        y = y % x;
        t1 += q * t0;
    }
    while (y != 1);

    return ((1 - t1) & 0xffff);
}

/*
 * Generate the key to be used for encryption, based on the user key read from
 * disk.
 */
static uint32_t *generateEncryptKey(int16_t *userkey)
{
    uint32_t i, j;

    uint32_t *key = (uint32_t *)malloc(sizeof(uint32_t) * KEY_LENGTH);
    
    memset(key, 0x00, sizeof(uint32_t) * KEY_LENGTH);

    for (i = 0; i < CHUNK_SIZE; i++)
    {
        key[i] = (userkey[i] & 0xffff);
    }

    for (i = CHUNK_SIZE; i < KEY_LENGTH; i++)
    {
        j = i % CHUNK_SIZE;

        if (j < 6)
        {
            key[i] = ((key[i - 7] >> 9) | (key[i - 6] << 7))
                     & 0xffff;
            continue;
        }

        if (j == 6)
        {
            key[i] = ((key[i - 7] >> 9) | (key[i - 14] << 7))
                     & 0xffff;
            continue;
        }

        key[i] = ((key[i - 15] >> 9) | (key[i - 14] << 7))
                 & 0xffff;
    }

    return (key);
}

/*
 * Generate the key to be used for decryption, based on the user key read from
 * disk.
 */
static uint32_t *generateDecryptKey(int16_t *userkey)
{
    uint32_t *key = (uint32_t *)malloc(sizeof(uint32_t) * KEY_LENGTH);
    uint32_t i, j, k;
    uint32_t t1, t2, t3;

    uint32_t *Z = generateEncryptKey(userkey);

    t1 = inv(Z[0]);
    t2 = - Z[1] & 0xffff;
    t3 = - Z[2] & 0xffff;

    key[51] = inv(Z[3]);
    key[50] = t3;
    key[49] = t2;
    key[48] = t1;

    j = 47;
    k = 4;

    for (i = 0; i < 7; i++)
    {
        t1 = Z[k++];
        key[j--] = Z[k++];
        key[j--] = t1;
        t1 = inv(Z[k++]);
        t2 = -Z[k++] & 0xffff;
        t3 = -Z[k++] & 0xffff;
        key[j--] = inv(Z[k++]);
        key[j--] = t2;
        key[j--] = t3;
        key[j--] = t1;
    }

    t1 = Z[k++];
    key[j--] = Z[k++];
    key[j--] = t1;
    t1 = inv(Z[k++]);
    t2 = -Z[k++] & 0xffff;
    t3 = -Z[k++] & 0xffff;
    key[j--] = inv(Z[k++]);
    key[j--] = t3;
    key[j--] = t2;
    key[j--] = t1;

    free(Z);

    return (key);
}

void readInputData(FILE *in, size_t textLen, int8_t **text,
                   int8_t **crypt)
{

  *text = (int8_t*) malloc (textLen * sizeof(int8_t));
  if (text==NULL)
  {
    fprintf(stderr, "Failed allocating text memory \n");
    exit(1);
  }
    
  *crypt = (int8_t*) malloc (textLen * sizeof(int8_t));
  if (crypt==NULL)
  {
    fprintf(stderr, "Failed allocating crypt memory \n");
    exit(1);
  }

  size_t result = fread(*text, sizeof(int8_t), textLen, in);
  fprintf(stderr, "result %d , textLen %d \n", result, textLen);
    
  if (result != textLen)
  {
    fprintf(stderr, "Failed reading text from input file\n");
    exit(1);
  }
}

void cleanup(int8_t *text, int8_t *crypt, uint32_t *key,
             int16_t *userkey)
{
    free(userkey);
    free(key);
    free(text);
    free(crypt);
}

/*
 * Initialize application state by reading inputs from the disk and
 * pre-allocating memory. Hand off to encrypt_decrypt to perform the actualy
 * encryption or decryption. Then, write the encrypted/decrypted results to
 * disk.
 */
int main(int argc, char **argv)
{
    FILE *in, *out, *keyfile;
    int8_t *text, *crypt;
    size_t textLen, keyFileLength;
    int16_t *userkey;
    uint32_t *key;
    action a;

    if (argc != 5)
    {
        printf("usage: %s <encrypt|decrypt> <file.in> <file.out> <key.file>\n", argv[0]);
        return (1);
    }

    // Are we encrypting or decrypting?
    if (strncmp(argv[1], "encrypt", 7) == 0)
    {
        a = ENCRYPT;
    }
    else if (strncmp(argv[1], "decrypt", 7) == 0)
    {
        a = DECRYPT;
    }
    else
    {
        fprintf(stderr, "The action specified ('%s') is not valid. Must be "
                "either 'encrypt' or 'decrypt'\n", argv[1]);
        return (1);
    }

    // Input file
    in = fopen(argv[2], "r");

    if (in == NULL)
    {
        fprintf(stderr, "Unable to open %s for reading\n", argv[2]);
        return (1);
    }

    // Output file
    out = fopen(argv[3], "w");

    if (out == NULL)
    {
        fprintf(stderr, "Unable to open %s for writing\n", argv[3]);
        return (1);
    }

    // Key file
    keyfile = fopen(argv[4], "r");

    if (keyfile == NULL)
    {
        fprintf(stderr, "Unable to open key file %s for reading\n", argv[4]);
        return (1);
    }

    keyFileLength = getFileLength(keyfile);

    if (keyFileLength != sizeof(*userkey) * USERKEY_LENGTH)
    {
        fprintf(stderr, "Invalid user key file length %lu, must be %lu\n",
                keyFileLength, sizeof(*userkey) * USERKEY_LENGTH);
        return (1);
    }

    userkey = (int16_t *)malloc(sizeof(int16_t) * USERKEY_LENGTH);

    if (userkey == NULL)
    {
        fprintf(stderr, "Error allocating user key\n");
        return (1);
    }

    if (fread(userkey, sizeof(*userkey), USERKEY_LENGTH, keyfile) !=
            USERKEY_LENGTH)
    {
        fprintf(stderr, "Error reading user key\n");
        return (1);
    }

    if (a == ENCRYPT)
    {
        key = generateEncryptKey(userkey);
    }
    else
    {
        key = generateDecryptKey(userkey);
    }

    textLen = getFileLength(in);

    if (textLen % CHUNK_SIZE != 0)
    {
        fprintf(stderr, "Invalid input file length %lu, must be evenly "
                "divisible by %d\n", textLen, CHUNK_SIZE);
        return (1);
    }

    readInputData(in, textLen, &text, &crypt);
    fclose(in);

    // frobino: google-pprof
    ProfilerStart("crypt_omp_cu_t.prof");
    h_encrypt_decrypt(text, crypt, key, textLen);
    ProfilerFlush();
    ProfilerStop();
    
    if (fwrite(crypt, sizeof(int8_t), textLen, out) != textLen)
    {
        fprintf(stderr, "Failed writing crypt to %s\n", argv[3]);
        return (1);
    }

    fclose(out);

    cleanup(text, crypt, key, userkey);

    return (0);
}
