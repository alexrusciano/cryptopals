#ifndef SET1_H
#define SET1_H

char* hex2b64(char* hex_str);

char* hex_print(char* char_buf, long length_char_buf);

char* my_xor(char* buf_1, char* buf_2, long len_buf_1, long len_buf_2, long* len_result);

char* repeated_xor(char* buf_1, char* buf_2, long len_buf_1, long len_buf_2, long* len_result);



#endif
