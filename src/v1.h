#ifndef __SECURE_ELEM_ABSTR_ATECC__
#define __SECURE_ELEM_ABSTR_ATECC__



#include "types.h"
#include <atca_status.h>

void v1_configure(uint8_t  slave_address, uint8_t  bus, uint32_t baud, uint32_t pin_sda, uint32_t pin_scl);
ATCA_STATUS v1_init();
ATCA_STATUS v1_close_i2c();
ATCA_STATUS v1_get_random(uint8_t* rand_out , uint8_t randomLen);
ATCA_STATUS v1_get_pubkey(uint8_t index , uint8_t* publicKey);
ATCA_STATUS v1_sign(uint8_t index , const uint8_t *msg, uint8_t *pSignature);
ATCA_STATUS v1_sign_raw(uint16_t key_id, const uint8_t *msg, uint16_t msglen, uint8_t *pSignature, uint16_t *pSignatureLen, uint8_t *rawSign);
ATCA_STATUS v1_verify(uint8_t index, const uint8_t *pHash,  const uint8_t *pSignature);
ATCA_STATUS v1_generate_keypair(uint8_t index);
ATCA_STATUS v1_verify_external(const uint8_t *message, const uint8_t *signature, const uint8_t *public_key);
ATCA_STATUS v1_write_data(uint16_t dataOffset, uint8_t *data, uint16_t dataLen);
ATCA_STATUS v1_read_data(uint16_t dataOffset, uint8_t *data, uint16_t dataLen);
ATCA_STATUS v1_get_sha256(uint8_t* pMessage, uint16_t msgLen, uint8_t* sha, uint16_t*shaLen);
ATCA_STATUS v1_save_key_pair(uint16_t slot, const uint8_t *public_key);




#endif
