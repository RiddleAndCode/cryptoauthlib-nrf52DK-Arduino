

// http://ww1.microchip.com/downloads/en/DeviceDoc/ATAES132A-Data-Sheet-40002023A.pdf
// Read datasheet for more information
#include <assert.h>
#include "ses.h"
#include "keys.h"
#include "aes132_helper.h"
#include "aes132_impl.h"

int fd = 0;

__attribute__((weak)) uint8_t* get_key(uint8_t key_num)
{
  assert (key_num < 3);
  switch (key_num)
  {
  case 0:
    return key00;
    break;
  case 1:
    return key01;
    break;
  case 2:
    return key02;
    break;
  default:
    return key00;
    break;
  }
}
uint8_t ses_config_pin(uint8_t *key, uint8_t id)
{
  uint8_t ret = AES132_DEVICE_RETCODE_KEY_ERROR;
  uint8_t data[4] = {0};

  data[0] = AES132_KEY_CONFIG_INBOUND_AUTH | AES132_KEY_CONFIG_RANDOM_NONCE | AES132_KEY_CONFIG_CHANGE_KEYS;

  ret =  aes132m_write_memory(AES132_KEY_CONFIG_LENGTH, AES132_KEY_CONFIG_ADDR(id), data);
  ret += aes132m_write_memory(AES132_KEY_LENGTH, AES132_KEY_ADDR(id), key);

  return ret;
}

uint16_t ses_config_zone(uint8_t id, bool disable_auth)
{
  uint16_t ret = AES132_DEVICE_RETCODE_KEY_ERROR;
  uint8_t data[4] = {0};
  if(disable_auth)
    data[0] = 0x0;
  else
    data[0] = AES132_ZONE_CONFIG_AUTH_READ | AES132_ZONE_CONFIG_AUTH_WRITE;

  if(id == 5)
    data[1] = (0x01 << 4);
  else if(id == 6)
    data[1] = (0x02 << 4);
  else
    data[1] = 0;

  data[2] = 0x00;
  data[3] = 0x00;

  ret =  aes132m_write_memory(AES132_KEY_CONFIG_LENGTH, AES132_ZONE_CONFIG_ADDR(id), data);
  return ret ;
}

bool ses_configure(bool lock)
{

    uint8_t config[16] = {0};
    uint16_t ret = AES132_DEVICE_RETCODE_KEY_ERROR, expected_key_lock = 0;
    ret = aes132_read_size(config,  AES132_LOCK_KEYS_ADDR, 4);

    if(ret != 0)
        return false;

    if(config[0] != 0x55) // Locked Key
    {
        expected_key_lock = 0xe0;

        puts("Keys are Locked !");
    }
    if(ses_config_pin(get_key(0), 0) != expected_key_lock)
    {
        return false;
    }

    if(ses_config_pin(get_key(1), 1) != expected_key_lock)
    {
        return false;
    }

    if(ses_config_pin(get_key(2), 2) != expected_key_lock)
    {
        return false;
    }

    for(uint8_t i = 0; i < 16; i++)
    {
        ses_config_zone(i, i<5);
    }

    if (lock)
    {
        ret += aes132_lock_zone(AES132_LOCK_CONFIG);
        // ret += aes132_lock_zone(AES132_LOCK_KEYMEMORY);
    }
    return ret == expected_key_lock;
}

uint8_t ses_write(uint8_t zone ,uint8_t * data, int16_t len)
{
  uint8_t ret = AES132_DEVICE_RETCODE_KEY_ERROR;

  assert(zone <= 15);
  assert(len <= 256);

  if (len > 32)
  {
    size_t i = 0;
    while(len > 0)
    {
      ret = aes132m_write_memory((len >= 32 ? 32 : len), AES132_USER_ZONE_ADDR(zone) + (i*32), data);
      if (ret != AES132_DEVICE_RETCODE_SUCCESS)
      {
        return -1;
      }
      data = data + 32;
      len = len - 32;
      i++;
    }

  }

  else
  {
    ret = aes132m_write_memory(len, AES132_USER_ZONE_ADDR(zone), data);
  }

  return ret;
}

uint8_t ses_read(uint8_t zone ,uint8_t * data, int16_t len)
{
  uint8_t ret = AES132_DEVICE_RETCODE_KEY_ERROR;

  assert(zone <= 15);
  assert(len <= 256);

  if (len > 32)
  {
    size_t i = 0;
    uint8_t buffer[32] = {0};
    while(len > 0)
    {
      ret =  aes132_read_size(buffer,AES132_USER_ZONE_ADDR(zone) + (i*32), (len >= 32 ? 32 : len));  //aes132m_read_memory((len >= 32 ? 32 : len), AES132_USER_ZONE_ADDR(zone) + (i*32), buffer); 

      if (ret != AES132_DEVICE_RETCODE_SUCCESS)
      {
        return -1;
      }

      memcpy(data,(const void*)buffer,(len >= 32 ? 32 : len));
      memset(buffer,0,32);
      data = data + 32;
      len = len - 32;
      i++;
    }

  }

  else
  {
    ret = aes132_read_size(data, AES132_USER_ZONE_ADDR(zone), len);
  }

  return ret;
}
bool ses_authenticate(uint8_t slot)
{
  uint8_t ret = AES132_DEVICE_RETCODE_KEY_ERROR;

  switch (slot)
  {
    case 0: case 1: case 2: case 3: case 4:
      break;

    case 5:
      ret = aes132_nonce();
      if (ret != AES132_DEVICE_RETCODE_SUCCESS)
        return false;
      ret = aes132_inbound_auth_key(1, get_key(1), (AES132_AUTH_USAGE_READ_OK | AES132_AUTH_USAGE_WRITE_OK | AES132_AUTH_USAGE_KEY_USE));
      if (ret != AES132_DEVICE_RETCODE_SUCCESS)
        return false;
      break;

    case 6:
      ret = aes132_nonce();
      if (ret != AES132_DEVICE_RETCODE_SUCCESS)
        return false;
      ret = aes132_inbound_auth_key(2, get_key(2), (AES132_AUTH_USAGE_READ_OK | AES132_AUTH_USAGE_WRITE_OK | AES132_AUTH_USAGE_KEY_USE));
      if (ret != AES132_DEVICE_RETCODE_SUCCESS)
        return false;
      break;

    default:
      ret = aes132_nonce();
      if (ret != AES132_DEVICE_RETCODE_SUCCESS)
        return false;
      ret = aes132_inbound_auth_key(0, get_key(0), (AES132_AUTH_USAGE_READ_OK | AES132_AUTH_USAGE_WRITE_OK | AES132_AUTH_USAGE_KEY_USE));
      if (ret != AES132_DEVICE_RETCODE_SUCCESS)
        return false;
      break;
  }

  return true;

}


