#ifndef SET1_H
#define SET1_H

char* hex2b64(char* hex_str);

char* b642buf(char* b64_str, long* len_buf_str);

void hex_print(char* char_buf, long length_char_buf);

char* my_xor(char* buf_1, char* buf_2, long len_buf_1, long len_buf_2, long* len_result);

char* repeated_xor(char* buf_1, char* buf_2, long len_buf_1, long len_buf_2, long* len_result);

struct Text_Decryption {
    char* key;
    long len_key;
    char* decrypted;
    long len_decrypted;
    float score;
};

struct Text_Decryption create_Text_Decryption(char* key, long len_key, char* decrypted, long len_decrypted, float socre);

void free_Text_Decryption(struct Text_Decryption);

struct Text_Decryption guess_single_byte_xor(char* cipher_txt, long len_cipher_txt);

long hamming(char* char_buf1, char* char_buf2, long len_char_buf1, long len_char_buf2);

char* read_file(char* file_name);

int guess_vigenere_length(char* text, int max_key);

void guess_vignere_key(char* text, int key_length, long len_text, char* key);
#endif
