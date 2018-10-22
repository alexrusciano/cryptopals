#include "set1.h"
#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
//#define _GNU_SOURCE

int main(){
/*    
    //test 1
    char hex_input_test[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    long len_decoded_input;
    char* decoded_input;
    char* output_test;
    output_test = hex2b64(hex_input_test);
    printf("%s\n", output_test);
    OPENSSL_free(output_test);

    //test2
    char encoded_xor_test_1[] = "1c0111001f010100061a024b53535009181c";
    char encoded_xor_test_2[] = "686974207468652062756c6c277320657965";
    char* decoded_xor_test_1;
    char* decoded_xor_test_2;
    char* xor_result;

    long xor_length_1;
    long xor_length_2;
    decoded_xor_test_1 = OPENSSL_hexstr2buf(encoded_xor_test_1, &xor_length_1);
    decoded_xor_test_2 = OPENSSL_hexstr2buf(encoded_xor_test_2, &xor_length_2);
    long len_xor_result;
    xor_result = repeated_xor(decoded_xor_test_1,decoded_xor_test_2,xor_length_1,xor_length_2, &len_xor_result);
    hex_print(xor_result,len_xor_result);

    OPENSSL_free(decoded_xor_test_1);
    OPENSSL_free(decoded_xor_test_2);
    OPENSSL_free(xor_result);

char encoded_single_xor_test[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
long len_single_xor_test;
char* single_xor_test = OPENSSL_hexstr2buf(encoded_single_xor_test,&len_single_xor_test);
struct Text_Decryption td =guess_single_byte_xor(single_xor_test, len_single_xor_test); 

printf("%s\n", td.decrypted);

free_Text_Decryption(td);

OPENSSL_free(single_xor_test);

FILE* fp_c4;
char* line_c4 = NULL;
size_t len_c4 = 0;
ssize_t read;

fp_c4 = fopen("set1c4_data.txt","r");
struct Text_Decryption td_c4;
if(fp_c4 == NULL)
    exit(0);

char first_c4 = 1;
while((read = getline(&line_c4, &len_c4, fp_c4)) != -1) {
    long len_next_c4_test;
    if (line_c4[read-1] == '\n'){
        line_c4[read-1] = '\0';
    }
    char* next_c4_test = OPENSSL_hexstr2buf(line_c4,&len_next_c4_test);

    struct Text_Decryption next_td = guess_single_byte_xor(next_c4_test, len_next_c4_test);
    if(first_c4){
        td_c4 = next_td;
        first_c4 = 0;
    }
    else if (next_td.score > td_c4.score){
        free_Text_Decryption(td_c4);
        td_c4 = next_td;
    }
    else{
        free_Text_Decryption(next_td);
    }
    OPENSSL_free(next_c4_test);
}
fclose(fp_c4);
if(line_c4)
    free(line_c4);
printf("%s\n", td_c4.decrypted);
free_Text_Decryption(td_c4);

char c5_plain_txt[] = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
char c5_key[] = "ICE";
long len_c5_key = strlen(c5_key);
long len_c5_plain_txt = strlen(c5_plain_txt);
long len_c5_output;
char* c5_output = repeated_xor(c5_key,c5_plain_txt, len_c5_key, len_c5_plain_txt, &len_c5_output);
hex_print(c5_output, len_c5_output);
OPENSSL_free(c5_output);

char c5_hamming_test1[] = "this is a test";
long len_c5_hamming_test1 = strlen(c5_hamming_test1);
char c5_hamming_test2[] = "wokka wokka!!!";
long len_c5_hamming_test2 = strlen(c5_hamming_test2);
long c5_distance_test = hamming(c5_hamming_test1,c5_hamming_test2,len_c5_hamming_test1,len_c5_hamming_test2);

printf("%lu\n", c5_distance_test);

FILE* fp_c6;
char* line_c6 = NULL;
size_t len_c6 = 0;
ssize_t read_again;


fp_c6 = fopen("set1c6_data.txt","r");
if(fp_c6 == NULL)
    exit(0);

char* file_str_c6;
int first=1;
while((read_again = getline(&line_c6, &len_c6, fp_c6)) != -1) {
    if (line_c6[read_again-1] == '\n'){
        line_c6[read_again-1] = '\0';
    }
    if (first){
        first = 0;
        file_str_c6 = malloc(strlen(line_c6)+1);
        strcpy(file_str_c6, line_c6);
    }
    else{
        char* tmp = file_str_c6;
        file_str_c6 = malloc(strlen(line_c6)+strlen(file_str_c6)+1);
        strcpy(file_str_c6, tmp);
        strcat(file_str_c6, line_c6);
        free(tmp);
    }
}
fclose(fp_c6);
if(line_c6)
    free(line_c6);

long len_c6_test; 
char* c6_test = b642buf(file_str_c6,&len_c6_test);

int top_guess = guess_vigenere_length(c6_test, 64);
char* c6_key = malloc(top_guess+1);
guess_vignere_key(c6_test, top_guess, len_c6_test, c6_key);
printf("%s\n", c6_key);

long len_c6_decrypted;
char* c6_decrypted = repeated_xor(c6_key, c6_test, top_guess, len_c6_test, &len_c6_test);
c6_decrypted[len_c6_test]='\0';
printf("%s\n", c6_decrypted);
free(c6_decrypted);
free(file_str_c6);
OPENSSL_free(c6_test);
free(c6_key);
*/
FILE* fp_c7;
char* line_c7 = NULL;
size_t len_c7 = 0;
ssize_t read_again;


fp_c7 = fopen("set1c7_data.txt","r");
if(fp_c7 == NULL)
    exit(0);

char* file_str_c7;
int first=1;
while((read_again = getline(&line_c7, &len_c7, fp_c7)) != -1) {
    if (line_c7[read_again-1] == '\n'){
        line_c7[read_again-1] = '\0';
    }
    if (first){
        first = 0;
        file_str_c7 = malloc(strlen(line_c7)+1);
        strcpy(file_str_c7, line_c7);
    }
    else{
        char* tmp = file_str_c7;
        file_str_c7 = malloc(strlen(line_c7)+strlen(file_str_c7)+1);
        strcpy(file_str_c7, tmp);
        strcat(file_str_c7, line_c7);
        free(tmp);
    }
}
fclose(fp_c7);
if(line_c7)
    free(line_c7);

long len_c7_test; 
char* c7_test = b642buf(file_str_c7,&len_c7_test);
char key[] = "YELLOW SUBMARINE";

char* c7_plaintxt = malloc(len_c7_test+200);
int len_c7_plaintxt;
EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(),NULL, key, NULL, 0);
EVP_CipherUpdate(ctx, c7_plaintxt, &len_c7_plaintxt, c7_test, len_c7_test);
EVP_CipherFinal_ex(ctx, c7_plaintxt, &len_c7_plaintxt);
c7_plaintxt[len_c7_test]='\0';
printf("%s\n", c7_plaintxt);

OPENSSL_free(c7_test);
free(c7_plaintxt);
EVP_CIPHER_CTX_free(ctx);
return 0;
}
