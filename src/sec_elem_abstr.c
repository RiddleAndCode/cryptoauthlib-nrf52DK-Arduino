#include <stdint.h>


#define V1
#define __SEA_V1__

#ifdef V1
#include "v1.h"
#endif

#ifdef V2
#include "v2.h"
#endif

#ifdef V3
#include "v3.h"
#endif

#include "sec_elem_abstr.h"
#include "ses.h"



#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define PUB_KEY_LEN 128
#define RAND_NUM_LEN 128
#define MSG_LEN 128
#define SIG_LEN 128
#define PRINT_LOG


SE_STATUS se_configure_hardware(uint8_t  slave_address, uint8_t  bus, uint32_t baud, uint32_t pin_sda, uint32_t pin_scl)
{
#ifdef __SEA_V2__
	return 	return SE_UNKNOWN;
#elif defined __SEA_V3__
	return 	return SE_UNKNOWN;
#elif defined __SEA_V1__
	v1_configure(slave_address, bus, baud, pin_sda, pin_scl);
#endif

}

SE_STATUS se_init(uint8_t mode)
{
#ifdef __SEA_V2__
	return v2_init(mode);
#elif defined __SEA_V3__
	return v3_init();
#elif defined __SEA_V1__
	return v1_init();
#endif

}

SE_STATUS se_close(void)
{
#ifdef __SEA_V2__
  return v2_close_i2c();
#elif defined __SEA_V3__
  return v3_close_i2c();
#elif defined __SEA_V1__
  return v1_close_i2c();
#endif
}

SE_STATUS se_get_random(uint8_t* rand_out , uint8_t randomLen)
{
#ifdef __SEA_V2__
	return v2_get_random(rand_out,randomLen);
#elif defined __SEA_V1__
	return v1_get_random(rand_out,randomLen);
#elif defined __SEA_V3__
	return v3_get_random(rand_out,randomLen);
#else
	return SE_UNKNOWN;
#endif
}

SE_STATUS se_get_pubkey(uint8_t index , uint8_t* publicKey , uint16_t* publicKeyLen)
{
#ifdef __SEA_V2__
	return v2_get_pubkey(index,publicKey,publicKeyLen);
#elif defined __SEA_V1__
	return v1_get_pubkey(index,publicKey);
#elif defined __SEA_V3__
	return v3_get_pubkey(index,publicKey,publicKeyLen);
#else
	return SE_UNKNOWN;
#endif
}

SE_STATUS se_sign(uint8_t index , const uint8_t *msg, uint16_t msglen, uint8_t *pSignature, uint16_t *pSignatureLen)
{
#ifdef __SEA_V2__
	return v2_sign( index,msg, msglen, pSignature, pSignatureLen);
#elif defined __SEA_V1__
	return v1_sign( index ,msg, pSignature);
#elif defined __SEA_V3__
	return v3_sign( index, msg, msglen, pSignature, pSignatureLen);
#endif
}

SE_STATUS se_sign_raw(uint8_t index, const uint8_t *msg, uint16_t msglen, uint8_t *pSignature, uint16_t *pSignatureLen, uint8_t *rawSign)
{
#ifdef __SEA_V2__
	return v2_sign_raw( index, msg, msglen, pSignature, pSignatureLen, rawSign);
#elif defined __SEA_V1__
	return v1_sign_raw( index, msg, msglen, pSignature, pSignatureLen, rawSign);
#else
	return SE_UNKNOWN;
#endif
}


SE_STATUS se_generate_keypair(uint8_t index)
{
#ifdef __SEA_V2__
	return v2_generate_keypair( index );
#elif defined __SEA_V1__
	return v1_generate_keypair( index );
#elif defined __SEA_V3__
	return v3_generate_keypair( index );;
#endif
}

SE_STATUS se_save_key_pair(uint8_t index, const uint8_t *publicKey, uint16_t publicKeyLen, const uint8_t *privateKey, uint16_t privateKeyLen)
{
#ifdef __SEA_V2__
	return v2_save_key_pair( index, publicKey, publicKeyLen, privateKey, privateKeyLen);
#else
	return SE_UNKNOWN;
 #endif
}

SE_STATUS se_verify(uint8_t index, const uint8_t *pHash, uint16_t hashLen, const uint8_t *pSignature, uint16_t signatureLen)
{
#ifdef __SEA_V2__
	return v2_verify(index, pHash, hashLen, pSignature, signatureLen);
#elif defined __SEA_V1__
	return v1_verify(index, pHash , pSignature);
#elif defined __SEA_V3__
	return  v3_verify(index, pHash, hashLen, pSignature, signatureLen);
#endif
}

SE_STATUS se_verify_external(uint8_t index,const uint8_t *pKeyData, uint16_t keyDataLen, const uint8_t *pHash, uint16_t hashLen, const uint8_t *pSignature, uint16_t signatureLen)
{
#ifdef __SEA_V2__
	return v2_verify_external( index, pKeyData, keyDataLen, pHash, hashLen, pSignature, signatureLen );
#elif defined __SEA_V3__
	return v3_verify_external(pKeyData, keyDataLen, pHash, hashLen, pSignature, signatureLen);
#elif defined __SEA_V1__
	return v1_verify_external(pHash, pSignature, pKeyData);
 #endif
}

SE_STATUS se_write_data(uint16_t dataOffset, uint8_t *data, uint16_t dataLen)
{
#ifdef __SEA_V2__
	return v2_write_data( dataOffset, data, dataLen );
#elif defined __SEA_V3__
	return v3_write_data(dataOffset,data,dataLen);
#elif defined __SEA_V1__
	return v1_write_data(dataOffset,data,dataLen);
#endif
}

SE_STATUS se_read_data(uint16_t dataOffset, uint8_t *data, uint16_t dataLen)
{
#ifdef __SEA_V2__
	return v2_read_data(dataOffset,data,dataLen);
#elif defined __SEA_V3__
	return v3_read_data(dataOffset,data,dataLen);
#elif defined __SEA_V1__
	return v1_read_data(dataOffset,data,dataLen);
#endif
}

SE_STATUS se_get_sha256(uint8_t* pMessage, uint16_t msgLen, uint8_t* sha, uint16_t* shaLen)
{
#ifdef __SEA_V2__
	return v2_get_sha256(pMessage,msgLen,sha,shaLen);
#elif defined __SEA_V3__
	return v3_get_sha256(pMessage,msgLen,sha);
#elif defined __SEA_V1__
	return v1_get_sha256(pMessage,msgLen,sha,shaLen);
#endif
}
SE_STATUS se_wipe_device(uint8_t index)
{
#ifdef __SEA_V2__
	return v2_wipe_device(index);
#else
	return SE_UNKNOWN;
#endif
}

SE_STATUS se_secure_storage_set_pin(uint8_t *pin, uint16_t pin_len)
{
	ses_set_pin(pin,pin_len);
	return SE_SUCCESS;
}


SE_STATUS se_secure_storage_personalize(bool lock)
{
	bool ret = false;
	puts("\n\n\t     ... Running configure ... \n\n\t... This may take up to a minute ...\n");
	ret = ses_configure(lock);
	if (ret)
		return SE_SUCCESS;
	else
		return SE_COM_FAIL;
}

SE_STATUS se_secure_store(uint8_t zone ,uint8_t * data, uint16_t len)
{
	uint8_t ret = -1;
	ret = ses_write(zone, data, len);
	if (ret == 0x00)
		return SE_SUCCESS;
	else
		return SE_COM_FAIL;
}

SE_STATUS se_secure_read(uint8_t zone ,uint8_t * data, uint16_t len)
{
	uint8_t ret = -1;
	ret = ses_read(zone, data, len);
	if (ret == 0x00)
		return SE_SUCCESS;
	else
		return SE_COM_FAIL;
}

SE_STATUS se_authenticate(uint8_t slot)
{
	bool ret = false;
	ret = ses_authenticate(slot);
	if (ret)
		return SE_SUCCESS;
	else
		return SE_COM_FAIL;
}

SE_STATUS se_secure_storage_init()
{
	int ret = ses_open();
	if (ret == 0)
		return SE_SUCCESS;
	else
		return SE_GEN_FAIL;
}

SE_STATUS se_secure_storage_close()
{
	int ret = ses_close();
	if (ret == 0)
		return SE_SUCCESS;
	else
		return SE_GEN_FAIL;
}

#pragma GCC diagnostic pop

