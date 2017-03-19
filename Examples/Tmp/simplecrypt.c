/****************************************************************************
ringneckparrot (c)
License: http://creativecommons.org/licenses/by-nc-sa/3.0/

Contact Me:
Email: ringneckparrot@hotmail.com
Facebook: http://www.facebook.com/ringneckparrot
Twitter ID: pp4rr0t
SecurityTube: http://www.securitytube.net/user/ringneckparrot

****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main(int argc, char **argv)
{
  int i;
  char *string;
  char encrypted_string[strlen(string)];
  char decrypted_string[strlen(string)];
  char *key_ch;
  char key_int;

  string = argv[1];
  key_ch = argv[2];
  key_int = atoi(key_ch);

  if (strcmp(argv[3], "encrypt") == 0)
    {
      i = 0;
      while(i <= strlen(string)-1)
	{
	  encrypted_string[i] = string[i]+ key_int;
	  i++;
	}

      printf("Encrypted String: ");
      i = 0;
      while (i <= strlen(string)-1 )
	{
	  printf("%c", encrypted_string[i]);
	  i++;
	}
      printf("\n");
    }
  if (strcmp(argv[3], "decrypt") == 0)
    {
      i = 0;
      while(i <= strlen(string)-1)
	{
	  decrypted_string[i] = string[i] - key_int;
	  i++;
	}

      printf("Decrypted String: ");
      i = 0;
      while(i <= strlen(string)-1)
	{
	  printf("%c", decrypted_string[i]);
	  i++;
	}

      printf("\n");
    }
}
