#include "baseencode.h"
#include "otp.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <gcrypt.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h> 

/**
 * The maximum guaranateed time for a totp to be verifiable is PERIOD / 2.
 * We choose a period of 2 minutes to guarantee the user at least 60 seconds 
 * to verify the totp.
 */
#define PERIOD 120
#define TIMEOUT_TEST 60
#define DIGITS 8
#define SECRET_LEN 64 //adds extra bytes at sertain numbers not sure why. example 64 output 67 string
#define SHA1 GCRY_MD_SHA1
#define SHA256 GCRY_MD_SHA256
#define SHA512 GCRY_MD_SHA512

int main(int argC, char** argV) {
    cotp_error_t err;
    char* totp = NULL;
    unsigned char secret[SECRET_LEN+1]; 
    FILE *fp;  
    //srand(time(NULL));//Because rand only checks every second secrets are the same if multiple calls in one second. Need to fix.
    
    if ((fp = fopen("/dev/urandom", "r")) == NULL) { 
        fprintf(stderr, "Error! Could not open /dev/urandom for read\n"); 
        return -1; 
    }
    for(int i = 0; i < SECRET_LEN; i++){
        do {
        secret[i] = fgetc(fp);
        }
        while (secret[i] == '\0');        
    }

    fclose(fp);
    baseencode_error_t base_err;
    char *secret_base32 = base32_encode(secret, strnlen(secret, SECRET_LEN+1)+1, &base_err);
    printf("%s \n", secret_base32);
    totp = get_totp(secret_base32, DIGITS, PERIOD, SHA256, &err);
   
    printf("%s\n", totp); //generated otp to be sent to user

    char* user_totp = totp; // to be replaced with user input (eventually to be replaced by an auto phone pull from the android app)
    //sleep(TIMEOUT_TEST); //test timeout function
    int is_valid = totp_verify(secret_base32, user_totp, DIGITS, PERIOD, SHA256);

    printf("%d\n", is_valid); //output of validation test 0 = match 4= invalid pairing

    free(totp);
    free(secret_base32);

    return is_valid;
}
