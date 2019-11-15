// ----------------------------------------------------------------------------
//         ATMEL Crypto-Devices Software Support  -  Colorado Springs, CO -
// ----------------------------------------------------------------------------
// DISCLAIMER:  THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
// DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// ----------------------------------------------------------------------------

/** \file
 *  \brief 	This file contains implementations of I2C functions.
 *  \author Atmel Crypto Products
 *  \date 	June 16, 2011
 */

#include "aes132_i2c.h"                //!< I2C library definitions
#include "i2c_phys.h"
#include <stdint.h>                    //!< C type definitions
#include <string.h>
#include "Arduino.h"
#include "i2c_bitbang_arduino.h"

/** \brief These enumerations are flags for I2C read or write addressing. */
enum aes132_i2c_read_write_flag {
  I2C_WRITE = (uint8_t) 0x00,	//!< write command id
  I2C_READ  = (uint8_t) 0x01   //! read command id
};

/** \brief This function initializes and enables the I2C hardware peripheral. */
void aes132p_enable_interface(void) {
  i2c_enable_phys();
}


/** \brief This function disables the I2C hardware peripheral. */
void aes132p_disable_interface(void) {
  i2c_disable_phys();
}


/** \brief This function selects a I2C AES132 device.
 *
 * @param[in] device_id I2C address
 * @return always success
 */
uint8_t aes132p_select_device(uint8_t device_id) {
  return i2c_select_device_phys(device_id);
}


/** \brief This function writes bytes to the device.
 * \param[in] count number of bytes to write
 * \param[in] word_address word address to write to
 * \param[in] data pointer to tx buffer
 * \return status of the operation
 */
uint8_t aes132p_write_memory_physical(uint8_t count, uint16_t word_address, uint8_t *data) {
  // In both, big-endian and little-endian systems, we send MSB first.
  uint8_t word_address_buffer[2] = {(uint8_t) (word_address >> 8u), (uint8_t) (word_address & 0xFFu)};
  uint8_t data_buffer[2+count];
  memcpy(&data_buffer[0], word_address_buffer, 2);
  memcpy(&data_buffer[2], data, count);
  uint8_t aes132_lib_return = i2c_send_slave_address(I2C_WRITE);
  if (aes132_lib_return != AES132_FUNCTION_RETCODE_SUCCESS) {
    // There is no need to create a Stop condition, since function
    // aes132p_send_slave_address does that already in case of error.
    return aes132_lib_return;
  }

	unsigned char index, ack = 0;

for(index = 0; index <( 2+count); index++)
	{
		 ack = i2c_write_byte(data_buffer[index]);
		 if(!ack)
     {
            (void) i2c_send_stop();
       			return AES132_FUNCTION_RETCODE_COMM_FAIL;

     }
	}

  // success
   i2c_send_stop();
   return aes132_lib_return;

}


/** \brief This function reads bytes from the device.
 * \param[in] size number of bytes to write
 * \param[in] word_address word address to read from
 * \param[out] data pointer to rx buffer
 * \return status of the operation
 */
uint8_t aes132p_read_memory_physical(uint8_t size, uint16_t word_address, uint8_t *data) {
  // Random read:
  // Start, I2C address with write bit, word address,
  // Start, I2C address with read bit

  // In both, big-endian and little-endian systems, we send MSB first.
  const uint8_t word_address_buffer[2] = {(uint8_t) (word_address >> 8u), (uint8_t) (word_address & 0x00FFu)};
	unsigned char index, ack = 0;

  uint8_t aes132_lib_return = i2c_send_slave_address(I2C_WRITE);
  if (aes132_lib_return != AES132_FUNCTION_RETCODE_SUCCESS) {
    // There is no need to create a Stop condition, since function
    // aes132p_send_slave_address does that already in case of error.
    return aes132_lib_return;
  }


  for(index = 0; index < 2; index++)
	{
		 ack = i2c_write_byte(word_address_buffer[index]);
		 if(!ack)
     {
            (void) i2c_send_stop();
       			return AES132_FUNCTION_RETCODE_COMM_FAIL;

     }
	}
  (void) i2c_send_stop();


  // unsigned long startMillis = millis();

  // unsigned long currentMillis = millis();
  // while(currentMillis - startMillis <= 100)
  // {
  //   currentMillis = millis();
  // }

  aes132_lib_return = i2c_send_slave_address(I2C_READ);
  if (aes132_lib_return != AES132_FUNCTION_RETCODE_SUCCESS) {

    return aes132_lib_return;
  }
for(index = 0; index < size; index++)
	{
		i2c_read_byte(data, size, index);
	}
  //i2c_receive_bytes(size, data);
   // i2c_receive_bytes_nack(size, data);
		i2c_send_stop();


  return aes132_lib_return;
}


/** \brief This function resynchronizes communication.
 * \return status of the operation
 */
uint8_t aes132p_resync_physical(void) {
  uint8_t nine_clocks = 0xFF;
  uint8_t n_retries = 2;
  uint8_t aes132_lib_return= AES132_FUNCTION_RETCODE_SUCCESS;

  do {
     i2c_send_start();
    if (aes132_lib_return != AES132_FUNCTION_RETCODE_SUCCESS) {
      // If a device is holding SDA or SCL, disabling and
      // re-enabling the I2C peripheral might help.
      i2c_disable_phys();
      i2c_enable_phys();
    }
    if (--n_retries == 0) {
      return aes132_lib_return;
    }

    // Retry creating a Start condition if it failed.
  } while(aes132_lib_return != AES132_FUNCTION_RETCODE_SUCCESS);

  // Do not evaluate the return code which most likely indicates error,
  // since nine_clocks is unlikely to be acknowledged.
  i2c_write_byte(nine_clocks);


   i2c_send_stop();
}
