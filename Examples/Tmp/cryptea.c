// http://codereview.stackexchange.com/questions/2050/tiny-encryption-algorithm-tea-for-arbitrary-sized-data

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

const uint32_t TEAKey[4] = {0x95a8882c, 0x9d2cc113, 0x815aa0cd, 0xa1c489f7};

void encrypt (uint32_t* v, const uint32_t* k);
void decrypt (uint32_t* v, const uint32_t* k);

void btea(uint32_t *v, int n, uint32_t const k[4]);

void simpleencrypt(uint8_t * buffer);
void simpledecrypt(uint8_t * buffer);

int main(int argc, char **argv)
{
  FILE *fpin, *fpout;
  int bytecount;
  uint8_t buffer[9], bufferin[9], bufferout[9];
  int i;

  if(argc < 3)
    {
      printf("Use: %s [filenameinput] [filenameoutput]\n", argv[0]);
      return 0;
    }

  if( (fpin = fopen(argv[1], "rb")) == NULL)
    {
      printf("Problem opening input file %s.\n", argv[1]);
      return 0;
    }

  if( (fpout = fopen(argv[2], "wb")) == NULL)
    {
      printf("Problem opening output file %s.\n", argv[2]);
      return 0;
    }

  bytecount = 0;

  while(fread(buffer, 1, 8, fpin) == 8)
    {
      if(argc>3)
	{
	  for(i=0;i<8;i++)
	    {
	      bufferin[i] = buffer[i];
	    }

	  simpleencrypt(buffer);


	  for(i=0;i<8;i++)
	    {
	      bufferout[i] = buffer[i];
	    }
	  simpledecrypt(bufferout);
	  for(i=0;i<8;i++)
	    {
	      if(bufferin[i] != bufferout[i])
		{
		  printf("Internal decode test failed.\n");
		}
	    }

	}
      else
	{
	  simpledecrypt(buffer);
	}
      fwrite(buffer, 1, 8, fpout);
      bytecount+=8;
    }

  if (!feof(fpin))
    {
      printf("Unexpected input file error encountered.\n");
    }

  fclose(fpin);
  fclose(fpout);
  printf("%s complete, %i bytes total\n",((argc>3) ? "Encrypt" : "Decrypt"), bytecount);
  return 0;
}

void simpleencrypt(uint8_t * buffer)
{
  uint32_t datablock[2];

  datablock[0] = (buffer[0] << 24) | (buffer[1] << 16)  | (buffer[2] << 8) | (buffer[3]);
  datablock[1] = (buffer[4] << 24) | (buffer[5] << 16)  | (buffer[6] << 8) | (buffer[7]);

  encrypt (datablock, TEAKey);

  buffer[0] = (uint8_t) ((datablock[0] >> 24) & 0xFF);
  buffer[1] = (uint8_t) ((datablock[0] >> 16) & 0xFF);
  buffer[2] = (uint8_t) ((datablock[0] >> 8) & 0xFF);
  buffer[3] = (uint8_t) ((datablock[0]) & 0xFF);
  buffer[4] = (uint8_t) ((datablock[1] >> 24) & 0xFF);
  buffer[5] = (uint8_t) ((datablock[1] >> 16) & 0xFF);
  buffer[6] = (uint8_t) ((datablock[1] >> 8) & 0xFF);
  buffer[7] = (uint8_t) ((datablock[1]) & 0xFF);
}

void simpledecrypt(uint8_t * buffer)
{
  uint32_t datablock[2];

  datablock[0] = (buffer[0] << 24) | (buffer[1] << 16)  | (buffer[2] << 8) | (buffer[3]);
  datablock[1] = (buffer[4] << 24) | (buffer[5] << 16)  | (buffer[6] << 8) | (buffer[7]);

  decrypt (datablock, TEAKey);

  buffer[0] = (uint8_t) ((datablock[0] >> 24) & 0xFF);
  buffer[1] = (uint8_t) ((datablock[0] >> 16) & 0xFF);
  buffer[2] = (uint8_t) ((datablock[0] >> 8) & 0xFF);
  buffer[3] = (uint8_t) ((datablock[0]) & 0xFF);
  buffer[4] = (uint8_t) ((datablock[1] >> 24) & 0xFF);
  buffer[5] = (uint8_t) ((datablock[1] >> 16) & 0xFF);
  buffer[6] = (uint8_t) ((datablock[1] >> 8) & 0xFF);
  buffer[7] = (uint8_t) ((datablock[1]) & 0xFF);
}

/* encrypt
 *   Encrypt 64 bits with a 128 bit key using TEA
 *   From http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 * Arguments:
 *   v - array of two 32 bit uints to be encoded in place
 *   k - array of four 32 bit uints to act as key
 * Returns:
 *   v - encrypted result
 * Side effects:
 *   None
 */
void encrypt (uint32_t* v, const uint32_t* k) {
  uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
  uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
  uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
  for (i=0; i < 32; i++) {                       /* basic cycle start */
    sum += delta;
    v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
    v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
  }                                              /* end cycle */
  v[0]=v0; v[1]=v1;
}

/* decrypt
 *   Decrypt 64 bits with a 128 bit key using TEA
 *   From http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 * Arguments:
 *   v - array of two 32 bit uints to be decoded in place
 *   k - array of four 32 bit uints to act as key
 * Returns:
 *   v - decrypted result
 * Side effects:
 *   None
 */
void decrypt (uint32_t* v, const uint32_t* k) {
  uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
  uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
  uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
  for (i=0; i<32; i++) {                         /* basic cycle start */
    v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
    sum -= delta;
  }                                              /* end cycle */
  v[0]=v0; v[1]=v1;
}

#define DELTA 0x9e3779b9
#define MX ((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (k[(p&3)^e] ^ z));

void btea(uint32_t *v, int n, uint32_t const k[4]) {
  uint32_t y, z, sum;
  uint32_t p, rounds, e;
  if (n > 1) {          /* Coding Part */
    rounds = 6 + 52/n;
    sum = 0;
    z = v[n-1];
    do {
      sum += DELTA;
      e = (sum >> 2) & 3;
      for (p=0; p<n-1; p++)
	y = v[p+1], z = v[p] += MX;
      y = v[0];
      z = v[n-1] += MX;
    } while (--rounds);
  } else if (n < -1) {  /* Decoding Part */
    n = -n;
    rounds = 6 + 52/n;
    sum = rounds*DELTA;
    y = v[0];
    do {
      e = (sum >> 2) & 3;
      for (p=n-1; p>0; p--)
	z = v[p-1], y = v[p] -= MX;
      z = v[n-1];
      y = v[0] -= MX;
    } while ((sum -= DELTA) != 0);
  }
}
