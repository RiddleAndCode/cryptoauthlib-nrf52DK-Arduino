#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>

#include <atca_status.h>
#include <atca_device.h>
#include <atca_command.h>
#include <atca_iface.h>
#include <atca_cfgs.h>
#include <atca_host.h>
#include <atca_execution.h>
#include <atca_basic.h>
#include <atca_helpers.h>
#include <i2c_bitbang_arduino.h>
#define ATCAPRINTF

#define PUBLIC_KEY_SIZE 64
#define PRIVATE_KEY_SIZE 32
#define SIGNATURE_SIZE 64

#define __SUCCESS__

#include "v1.h"


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"


void v1_configure(uint8_t  slave_address, uint8_t  bus, uint32_t baud, uint32_t pin_sda, uint32_t pin_scl)
{
	extern I2CBuses i2c_buses_default;
	extern ATCAIfaceCfg cfg_ateccx08a_i2c_default;
	#ifdef ARDUINO
	cfg_ateccx08a_i2c_default.iface.atcai2c.slave_address = slave_address,
    cfg_ateccx08a_i2c_default.iface.atcai2c.bus           = bus,
    cfg_ateccx08a_i2c_default.iface.atcai2c.baud          = baud,
	#else
	cfg_ateccx08a_i2c_default.atcai2c.slave_address = slave_address,
    cfg_ateccx08a_i2c_default.atcai2c.bus           = bus,
    cfg_ateccx08a_i2c_default.atcai2c.baud          = baud,
	#endif
	i2c_buses_default.pin_sda[0] = pin_sda;
	i2c_buses_default.pin_scl[0] = pin_scl;

}

ATCA_STATUS v1_init()
{
	ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;
	ATCA_STATUS rv = ATCA_GEN_FAIL;
	rv = atcab_init(gCfg);

	return rv;
}
ATCA_STATUS  v1_close_i2c()
{
	return (atcab_release());
}
ATCA_STATUS  v1_get_random(uint8_t* rand_out , uint8_t randomLen)
{
	ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;
    ATCA_STATUS status = ATCA_GEN_FAIL;

    do
    {
        // build an random command
        packet.param1 = RANDOM_SEED_UPDATE;
        packet.param2 = 0x0000;

        if ((status = atRandom(ca_cmd, &packet)) != ATCA_SUCCESS)
        {
            break;
        }

        if ((status = atca_execute_command(&packet, _gDevice)) != ATCA_SUCCESS)
        {
            break;
        }

        if (packet.data[ATCA_COUNT_IDX] != RANDOM_RSP_SIZE)
        {
            status = ATCA_RX_FAIL;
            break;
        }

        if (rand_out)
        {
            memcpy(rand_out, &packet.data[ATCA_RSP_DATA_IDX], RANDOM_NUM_SIZE);
        }
    }
    while (0);


    return status;
}

ATCA_STATUS  v1_get_pubkey(uint8_t index , uint8_t* publicKey)
{
	ATCA_STATUS rv = ATCA_BAD_PARAM;
	if (!(index < 10))
		return ATCA_BAD_PARAM;
	rv = atcab_get_pubkey( index, publicKey);
	return rv;
}

ATCA_STATUS  v1_sign(uint8_t index , const uint8_t *msg, uint8_t *pSignature)
{
	ATCA_STATUS rv = ATCA_BAD_PARAM;
	rv = atcab_sign( index, msg, pSignature);

	return rv;
}
ATCA_STATUS  v1_sign_raw(uint16_t key_id, const uint8_t *msg, uint16_t msglen, uint8_t *pSignature, uint16_t *pSignatureLen, uint8_t *rawSign)
{
	ATCA_STATUS rv = ATCA_BAD_PARAM;
	if(msglen < 32 && *pSignatureLen < SIGN_RSP_SIZE)
		rv = atcab_sign(key_id, msg, pSignature);

	return rv;
}

ATCA_STATUS  v1_generate_keypair(uint8_t index)
{
	if (!(index < 10))
		return ATCA_BAD_PARAM;
	ATCA_STATUS rv;
	uint8_t public_key[64] = {0};

	rv = atcab_genkey(index , public_key);

	if(rv == ATCA_SUCCESS)
	{
		printf("Public key for index %d = ",index);
		for (size_t i = 0; i < 64; i++)
		{
			printf("0x%02x ",public_key[i]);
		}
		puts("\n");
	}


	return rv;
}

ATCA_STATUS v1_verify(uint8_t index, const uint8_t *pHash,  const uint8_t *pSignature)
{
	ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t nonce_target = NONCE_MODE_TARGET_TEMPKEY;
    uint8_t verify_source = VERIFY_MODE_SOURCE_TEMPKEY;

    if (pHash == NULL || pSignature == NULL)
    {
        return ATCA_BAD_PARAM;
    }

        // Load message into device
        if (_gDevice->mCommands->dt == ATECC608A)
        {
            // Use the Message Digest Buffer for the ATECC608A
            nonce_target = NONCE_MODE_TARGET_MSGDIGBUF;
            verify_source = VERIFY_MODE_SOURCE_MSGDIGBUF;
        }
        if ((status = atcab_nonce_load(nonce_target, pHash, 32)) != ATCA_SUCCESS)
        {
            return status;
        }

        status = atcab_verify(VERIFY_MODE_STORED | verify_source, index, pSignature, NULL, NULL, NULL);
		return status;


}

ATCA_STATUS  v1_verify_external(const uint8_t *message, const uint8_t *signature, const uint8_t *public_key)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t nonce_target = NONCE_MODE_TARGET_TEMPKEY;
    uint8_t verify_source = VERIFY_MODE_SOURCE_TEMPKEY;
 	bool is_verified = false;

    if (signature == NULL || message == NULL || public_key == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    do
    {
        // Load message into device
        if (_gDevice->mCommands->dt == ATECC608A)
        {
            // Use the Message Digest Buffer for the ATECC608A
            nonce_target = NONCE_MODE_TARGET_MSGDIGBUF;
            verify_source = VERIFY_MODE_SOURCE_MSGDIGBUF;
        }
        if ((status = atcab_nonce_load(nonce_target, message, 32)) != ATCA_SUCCESS)
        {
            break;
        }

        status = atcab_verify(VERIFY_MODE_EXTERNAL | verify_source, VERIFY_KEY_P256, signature, public_key, NULL, NULL);
		return status;

    }
    while (0);

    return (status);
}

ATCA_STATUS v1_write_data(uint16_t index, uint8_t *data, uint16_t dataLen)
{
	if (!(index > 9 && index < 16))
		return ATCA_BAD_PARAM; 
	ATCA_STATUS status = atcab_write_bytes_zone(ATCA_ZONE_DATA, index, 0, data, dataLen);
	return (status);
}

ATCA_STATUS v1_read_data(uint16_t index, uint8_t *data, uint16_t dataLen)
{
	if (!(index > 9 && index < 16))
		return ATCA_BAD_PARAM; 
	ATCA_STATUS status = atcab_read_bytes_zone(ATCA_ZONE_DATA, index, 0, data, dataLen);
	return (status);
}

ATCA_STATUS v1_get_sha256(uint8_t* pMessage, uint16_t msgLen, uint8_t* sha, uint16_t*shaLen)
{
	ATCA_STATUS status;
	uint8_t *pMessageHolder = pMessage;
	status = atcab_sha_base(SHA_MODE_SHA256_START, 0, NULL, NULL, NULL);
	if (status != ATCA_SUCCESS)
		return status;
	if(msgLen <= 64)
	{
		status = atcab_sha_base(SHA_MODE_SHA256_UPDATE, msgLen, pMessageHolder, NULL, NULL);
		if (status != ATCA_SUCCESS)
			return status;
	}
	else
	{
		while (msgLen > 0)
		{
			if (msgLen >= 64)
			{
				status = atcab_sha_base(SHA_MODE_SHA256_UPDATE, 64, pMessageHolder, NULL, NULL);
				pMessageHolder = pMessageHolder + 64;
				msgLen = msgLen - 64;
				if (status != ATCA_SUCCESS)
					return status;
			}
			else
			{
				status = atcab_sha_base(SHA_MODE_SHA256_UPDATE, msgLen, pMessageHolder, NULL, NULL);
				pMessageHolder = pMessageHolder + msgLen;
				msgLen = 0;
				if (status != ATCA_SUCCESS)
					return status;
			}

		}
	}



    status = atcab_sha_base(SHA_MODE_SHA256_END | SHA_MODE_TARGET_OUT_ONLY, 0, NULL, sha, shaLen);
	return status;
}


#pragma GCC diagnostic pop

