#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

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

    xor_result = OPENSSL_malloc(length_buf_2);
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

