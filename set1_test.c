#include "set1.h"
#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <string.h>

int main(){
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
long len_decoded_single_xor_test;
char* decoded_single_xor_test = OPENSSL_hexstr2buf(encoded_single_xor_test,&len_decoded_single_xor_test);

char key = 0;
float best_score = 0;
char* decrypted;
for (int i = 0; i < 256; i++){
    float score = 0;
    long unused_length;
    char candidate_char = (char) i;
    char* decrypt_guess = repeated_xor(&candidate_char, decoded_single_xor_test, 1, len_decoded_single_xor_test, &unused_length);
    for (int j = 0; j < len_decoded_single_xor_test; j++){
        switch(decrypt_guess[j]){
            case ' ':
                score += .15;
                break;
            case 'E':
                score += .12;
                break;
            case 'e':
                score += .12;
                break;
            case 'T':
                score += .09;
                break;
            case 't':
                score += .09;
                break;
            case 'A':
                score +=.08;
                break;
            case 'O':
                score += .07;
                break;
            case 'a':
                score += .08;
                break;
            case 'o':
                score += .07;
                break;
            case 'i':
                score += .07;
                break;
            case 'I':
                score += .07;
                break;
            case 'N':
                score += .07;
                break;
            case 'n':
                score += .07;
                break;
            case 'S':
                score += .06;
                break;
            case 's':
                score +=.06;
                break;
            case 'R':
                score += .06;
                break;
            case 'r':
                score +=.06;
                break;
        }
    }
    if (score > best_score){
        best_score = score;
        key = (char) i;
        OPENSSL_free(decrypted);
        decrypted = decrypt_guess;
    } else{
        OPENSSL_free(decrypt_guess);
    }
}
//hex_print(decrypted,len_decoded_single_xor_test);
printf("%s\n", decrypted);
OPENSSL_free(decrypted);
OPENSSL_free(decoded_single_xor_test);
return 0;
}
