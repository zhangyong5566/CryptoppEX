#ifndef _CRYPT_H_
#define _CRYPT_H_

int aes_getsize(int len);

int aes_encrypt(char * key, char * in, int len, char * out, int size);

int aes_decrypt(char * key, char * in, int len, char * out, int size);

int RadomString(char * table, int len, std::string & str);
int RangeRandom(int range_min, int range_max);

#endif
