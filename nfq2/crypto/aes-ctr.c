#include "aes-ctr.h"
#include <string.h>

#define AES_BLOCKLEN 16

#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
void aes_ctr_xcrypt_buffer(aes_context *ctx, const uint8_t *iv, const uint8_t *in, size_t length, uint8_t *out)
{
	uint8_t bi, buffer[AES_BLOCKLEN], ivc[AES_BLOCKLEN];
	size_t i, l16 = length & ~0xF;

	memcpy(ivc, iv, AES_BLOCKLEN);

	for (i = 0; i < l16; i += 16)
	{
		memcpy(buffer, ivc, AES_BLOCKLEN);
		aes_cipher(ctx, buffer, buffer);

		// Increment ivc and handle overflow
		for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
		{
			// inc will owerflow
			if (ivc[bi] == 255)
			{
				ivc[bi] = 0;
				continue;
			}
			ivc[bi]++;;
			break;
		}
		*((uint64_t*)(out + i)) = *((uint64_t*)(in + i)) ^ ((uint64_t*)buffer)[0];
		*((uint64_t*)(out + i + 8)) = *((uint64_t*)(in + i + 8)) ^ ((uint64_t*)buffer)[1];
	}

	if (i<length)
	{
		memcpy(buffer, ivc, AES_BLOCKLEN);
		aes_cipher(ctx, buffer, buffer);

		for (bi=0 ; i < length; i++, bi++)
			out[i] = in[i] ^ buffer[bi];
	}
}

int aes_ctr_crypt(const uint8_t *key, unsigned int key_len, const uint8_t *iv, const uint8_t *in, size_t length, uint8_t *out)
{
	int ret = 0;
	aes_context ctx;

	aes_init_keygen_tables();

	if (!(ret = aes_setkey(&ctx, AES_ENCRYPT, key, key_len)))
		aes_ctr_xcrypt_buffer(&ctx, iv, in, length, out);

	return ret;
}
