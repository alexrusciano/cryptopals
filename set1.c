#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>
#include "set1.h"

char* hex2b64(char* hex_str){
    long len_decoded_hex_str;
    char* decoded_hex_str;
    char* b64_str;
    decoded_hex_str = OPENSSL_hexstr2buf(hex_str, &len_decoded_hex_str);
    b64_str = OPENSSL_malloc(len_decoded_hex_str*4/3+len_decoded_hex_str%3);
    EVP_EncodeBlock(b64_str, decoded_hex_str, len_decoded_hex_str);
    OPENSSL_free(decoded_hex_str);
    return b64_str;
}

char* b642buf(char* b64_str, long* len_buf_str){
    int len_b64_str = strlen(b64_str);
    if(len_b64_str%4 != 0 )
        exit(0);
    *len_buf_str = 3 * len_b64_str / 4;
    char* buf_str = malloc(*len_buf_str);
    *len_buf_str = EVP_DecodeBlock(buf_str, b64_str, len_b64_str);
    return buf_str; 
}
void hex_print(char* str_buf, long len_str_buf){
    char* encoded_str_buf;
    encoded_str_buf = OPENSSL_buf2hexstr(str_buf, len_str_buf);
    printf("%s\n", encoded_str_buf);
    OPENSSL_free(encoded_str_buf);
}

char* my_xor(char* buf_1, char* buf_2, long length_buf_1, long length_buf_2, long* length_result){
    *length_result = length_buf_2;
    char* xor_result;
    if (length_buf_1 != length_buf_2){
        printf("invalid use\n");
        exit(0);
    }
    xor_result = OPENSSL_malloc(length_buf_1);
    for(int i = 0; i < length_buf_1; i++){
            xor_result[i]=buf_1[i]^buf_2[i];
    }
    return xor_result;
}

char* repeated_xor(char* buf_1, char* buf_2,long length_buf_1, long length_buf_2, long* length_result){
    *length_result = length_buf_2;
    char* xor_result;
    long full_xor_part = length_buf_2/length_buf_1;
    long residual_xor_part = length_buf_2 % length_buf_1;

    xor_result = malloc(length_buf_2+1);
    //printf("START\n");
    for (int i = 0; i < full_xor_part; i++){
        for(int j = 0; j < length_buf_1; j++){
            xor_result[i*length_buf_1+j] = buf_1[j]^buf_2[i*length_buf_1+j];
            //printf("%d\n", (int) xor_result[i*length_buf_1+j]); 
        }
    }
    for(int j = 0; j < residual_xor_part; j++){
        xor_result[full_xor_part*length_buf_1+j] = buf_1[j]^ buf_2[length_buf_1*full_xor_part+j];
    }
    //printf("END\n");
    return xor_result;
}

struct Text_Decryption create_Text_Decryption(char* key, long len_key, char* decrypted, long len_decrypted, float score){
    struct Text_Decryption td;
    td.key = key;
    td.len_key = len_key;
    td.decrypted = decrypted;
    td.len_decrypted = len_decrypted;
    td.score = score;
    return td;
}

void free_Text_Decryption(struct Text_Decryption td){
    free(td.key);
    free(td.decrypted);
}

struct Text_Decryption guess_single_byte_xor(char* cipher_txt, long len_cipher_txt){
    char* key = malloc(1);
    float best_score = 0;
    char* decrypted;
    int first_time = 1;
    for (int i = 0; i < 256; i++){
        float score = 0;
        long unused_length;
        char candidate_char = (char) i;
        char* decrypt_guess = repeated_xor(&candidate_char, cipher_txt, 1, len_cipher_txt, &unused_length);
        for (int j = 0; j < unused_length; j++){
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
            *key = (char) i;
            if(!first_time){
                OPENSSL_free(decrypted);
            }
            first_time = 0;
            decrypted = decrypt_guess;
        } else{
            OPENSSL_free(decrypt_guess);
        }
    }
    //hex_print(decrypted,len_decoded_single_xor_test);
    //printf("hmm %c \n", *key);
    struct Text_Decryption td = create_Text_Decryption(key,1,decrypted,len_cipher_txt, best_score); 
    return td;
}

long hamming(char* char_buf1, char* char_buf2, long len_char_buf1, long len_char_buf2){
    if (len_char_buf1 != len_char_buf2)
        exit(0);
    long distance=0;
    long len_different_bits;
    char* different_bits = repeated_xor(char_buf1, char_buf2, len_char_buf1, len_char_buf2,&len_different_bits);
    for(int i = 0; i < len_different_bits; i++){
        char next_byte = different_bits[i];
        for(next_byte; next_byte; next_byte>>=1){
            distance += next_byte & 0x01;
        }
    }
    free(different_bits);
    return distance;
}
char* read_file(char* file_name){
    char *source = NULL;
    FILE *fp = fopen(file_name, "r");
    if (fp != NULL) {
        /* Go to the end of the file. */
        if (fseek(fp, 0L, SEEK_END) == 0) {
            /* Get the size of the file. */
            long bufsize = ftell(fp);
            if (bufsize == -1) { /* Error */ }

            /* Allocate our buffer to that size. */
            source = malloc(sizeof(char) * (bufsize + 1));

            /* Go back to the start of the file. */
            if (fseek(fp, 0L, SEEK_SET) != 0) { /* Error */ }

            /* Read the entire file into memory. */
            size_t newLen = fread(source, sizeof(char), bufsize, fp);
            if ( ferror( fp ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                source[newLen++] = '\0'; /* Just to be safe. */
            }
        }
        fclose(fp);
    }
    return source;
}

int guess_vigenere_length(char* text, int max_key){
    int best_key_length = 0;
    float best_distance = -1;
    for(int i = 1; i<= max_key; i++){
        float distance = 0;
        for(int j = 0; j < 10; j++){
            distance += hamming(text+i*j,text+i*(j+1),i,i) / (float) i;
        }
        if ((best_distance > distance) || (best_distance < 0)){
            best_distance = distance;
            best_key_length = i;
        }
    }
    return best_key_length;
}

void guess_vignere_key(char* text, int key_length, long len_text, char* key){
    int num_blocks = len_text / key_length;
    char* transpose = malloc(num_blocks * key_length);
    for (int i = 0; i< key_length; i++){
        for(int j = 0; j< num_blocks; j++){
            transpose[j + i*num_blocks] = text[j*key_length+i];
        }
    }
    for (int i = 0; i < key_length; i++){
        struct Text_Decryption td = guess_single_byte_xor(transpose+i*num_blocks, num_blocks);
        key[i] = *td.key;
        free_Text_Decryption(td);
    }
    key[key_length] = '\0';
}
