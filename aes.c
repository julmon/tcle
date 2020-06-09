/*----------------------------------------------------------------------------
 *
 *                   AES 256 CBC encryption / decryption
 *
 * Portions Copyright (c) 2020, Julien Tachoires
 *
 * Theses functions are wrappers around OpenSSL EVP functions. Encryption
 * algorithm is AES with 256 bits key length using CBC. OpenSSL EVP functions
 * allow usage of CPU instructions dedicated to AES encryption like AES-NI for
 * Intel CPUs.
 *
 * IDENTIFICATION
 *	  aes.c
 *
 *----------------------------------------------------------------------------
 */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#include "aes.h"

int AES_CBC_encrypt(unsigned char *plaintext, int plaintext_len,
					unsigned char *key, unsigned char *iv,
					unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int				len;
	int				ciphertext_len;

	if(!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		return -1;

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return -1;

	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		return -1;

	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int AES_CBC_decrypt(unsigned char *ciphertext, int ciphertext_len,
					unsigned char *key, unsigned char *iv,
					unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int				len;
	int				plaintext_len;

	if(!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		return -1;

	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		return -1;

	plaintext_len = len;

	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		return -1;

	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}
