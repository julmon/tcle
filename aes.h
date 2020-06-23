#ifndef _AES_H_
#define _AES_H_

#define AES_BLOCKLEN		16
#define AES_IVLEN			16
#define AES_KEYLEN			32

#define AES_INVALID_FLAG	-1
#define AES_ENCRYPT_FLAG	0
#define AES_DECRYPT_FLAG	1
#define AES_NOCRYPT_FLAG	2


int AES_CBC_encrypt(unsigned char *plaintext, int plaintext_len,
					unsigned char *key, unsigned char *iv,
					unsigned char *ciphertext);

int AES_CBC_decrypt(unsigned char *ciphertext, int ciphertext_len,
					unsigned char *key, unsigned char *iv,
					unsigned char *plaintext);

#endif
