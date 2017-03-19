#include <regex.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <omp.h>
#include <string.h>

char ignores [] = ",.'!?";
char common [][8] = {"THE", "BE", "TO", "OF", "AND", "A", "IN", "THAT", "HAVE", "I",
    "IT", "FOR", "NOT", "ON", "WITH", "HE", "AS", "YOU", "DO", "AT"};

unsigned char rotate(unsigned char c, int amount) {
    /* skip everything non-alphabetic */
    if (!isalpha(c)) {
        return c;
    }

    /* do the shift */
    unsigned char next = c + amount;

    /* wrap if needed */
    unsigned char last = isupper(c) ? 'Z' : 'z';
    while (next > last) {
        next -= 26;
    }

    return next;
}

int break_code(char* encrypted, unsigned int length, unsigned int amount) {
    /* make space for decrypted string */
    char* decrypted = malloc(length + 1);

    /* rotate each character that amount */
    unsigned int j;
    for (j = 0; j < length; j++) {
        decrypted[j] = rotate(encrypted[j], amount);
    }
    decrypted[j] = '\0';

    /* check how many common words is in the string */
    int count = 0;
    for (j = 0; j < (sizeof(common) / sizeof(char*)); j++) {
        /* build a regex to search for the word exactly */
        char regex_string[16];
        sprintf(regex_string, "\\<%s\\>", common[j]);
        regex_t regex;
        regcomp(&regex, regex_string, REG_ICASE);

        /* search the string for our matches if present */
        regmatch_t match;
        int offset = 0;
        /* while we have a match */
        while (!regexec(&regex, decrypted + offset, 1, &match, 0)) {
            /* count it an search the rest of the string */
            count++;
            offset += match.rm_eo;
        }
    }

    /* if the ratio of common words to the length of the text is over .01, it
     * is likely the correct decrypted text that we are looking for */
    if (((double)count / (double)strlen(decrypted)) >= .01) {
        printf("The decrypted text is:\n%s\n", decrypted);
        printf("The key was %d.\n", amount);
        return 1;
    } else {
        return 0;
    }
}


int main(int argc, char** argv) {
    /* be strict */
    if (argc < 2) {
        printf("Usage: code cipherfile\n");
        return 0;
    }

    /* open the file */
    FILE* file = fopen(argv[1], "r");
    if (!file) {
        printf("File '%s' could not be opened.\n", argv[1]);
        return 0;
    }

    /* will store the encrypted string */
    char* encrypted = NULL;

    /* find how big the file is and allocate that much space */
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    encrypted = malloc(length + 1);

    /* go back to the start and read it all in */
    fseek (file, 0, SEEK_SET);
    fread (encrypted, 1, length, file);
    fclose (file);

    /* try each possible shift amount */
    int found = 0, i;
#pragma omp parallel for num_threads(26) reduction(||:found)
    for (i = 0; i < 26; i++) {
        found = found || break_code(encrypted, length, i);
    }

    if (!found) {
        printf("Text could not be cracked with this method!\n");
    }

    return 0;
}

