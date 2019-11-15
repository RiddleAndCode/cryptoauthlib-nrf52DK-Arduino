#ifndef _UECC_TESTS_H_
#define _UECC_TESTS_H_
#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>


uint8_t ses_write(uint8_t zone ,uint8_t * data, int16_t len);
uint8_t ses_read(uint8_t zone ,uint8_t * data, int16_t len);
bool ses_authenticate(uint8_t slot);
uint8_t ses_config_pin(uint8_t *key, uint8_t id);
uint16_t ses_config_zone(uint8_t id, bool disable_auth);
bool ses_configure(bool lock);
int8_t ses_open();
int8_t ses_close();

//! Poll this many ms for the device being ready for access.
#define AES132_DEVICE_READY_TIMEOUT      (100)

/** \brief Poll this many ms for the response buffer being ready for reading.
 *
 * When adjusting this number, consider the command execution delays used.
 * As these delays lie closer to or farther from the minimum command execution
 * delays, this number has to be made bigger or smaller accordingly. With other
 * words: The earlier we start polling after sending a command,
 * the longer we have to make the wait-for-response-ready time-out.
 */
#define AES132_RESPONSE_READY_TIMEOUT     (145) // Biggest response timeout is the one for the TempSense command (in ms).


// ----------------------- definitions for retry counts -----------------------------

//! number of retries for sending a command, receiving a response, and accessing memory
#define AES132_RETRY_COUNT_ERROR           ((uint8_t) 2)

//! number of re-synchronization retries
#define AES132_RETRY_COUNT_RESYNC          ((uint8_t) 2)


// ------------- definitions for packet sizes --------------------

//! size of CRC
#define AES132_CRC_SIZE                    ((uint8_t)  2)

//! minimum command size
#define AES132_COMMAND_SIZE_MIN            ((uint8_t)  9)

//! maximum command size (KeyImport command)
#define AES132_COMMAND_SIZE_MAX            ((uint8_t) 63)

//! minimum response size (EncRead and Encrypt command)
#define AES132_RESPONSE_SIZE_MIN           ((uint8_t)  4)

//! maximum response size
#define AES132_RESPONSE_SIZE_MAX           ((uint8_t) 52)

//! maximum number of bytes to write to or read from memory
#define AES132_MEM_ACCESS_MAX              ((uint8_t) 32)


// ------------- definitions for device word addresses --------------------

//! word address of command / response buffer
#define AES132_IO_ADDR                     ((uint16_t) 0xFE00)

//! Write to this word address to reset the index of the command / response buffer.
#define AES132_RESET_ADDR                  ((uint16_t) 0xFFE0)

//! word address of device status register
#define AES132_STATUS_ADDR                 ((uint16_t) 0xFFF0)


// ------------- definitions for device status register bits --------------------

//! bit position of the Write-In-Progress bit (WIP) in the device status register
#define AES132_WIP_BIT                          ((uint8_t) 0x01)

//! bit position of the Write-Enabled bit in the device status register (SPI only)
#define AES132_WEN_BIT                          ((uint8_t) 0x02)

//! bit position of the power state bit in the device status register
#define AES132_WAKE_BIT                         ((uint8_t) 0x04)

//! bit position of reserved bit 3 in the device status register
#define AES132_RESERVED3_BIT                    ((uint8_t) 0x08)

//! bit position of the CRC error bit in the device status register
#define AES132_CRC_ERROR_BIT                    ((uint8_t) 0x10)

//! bit position of reserved bit 5 in the device status register
#define AES132_RESERVED5_BIT                    ((uint8_t) 0x20)

//! bit position of the CRC error bit in the device status register
#define AES132_RESPONSE_READY_BIT               ((uint8_t) 0x40)

//! bit position of bit in the device status register that indicates error
#define AES132_DEVICE_ERROR_BIT                 ((uint8_t) 0x80)


// --- definitions for device return codes (byte at index 1 of device response buffer ---

//! no error in executing a command and receiving a response, or writing data to memory
#define AES132_DEVICE_RETCODE_SUCCESS           ((uint8_t) 0x00)

//! error when crossing a page or key boundary for a Write, BlockRead or EncRead
#define AES132_DEVICE_RETCODE_BOUNDARY_ERROR    ((uint8_t) 0x02)

//! Access to the specified User Zone is not permitted due to the current configuration or internal state.
#define AES132_DEVICE_RETCODE_RW_CONFIG         ((uint8_t) 0x04)

//! Address is not implemented, or address is illegal for this command, or attempted to write locked memory.
#define AES132_DEVICE_RETCODE_BAD_ADDR          ((uint8_t) 0x08)

//! Counter limit reached, or count usage error, or restricted key error.
#define AES132_DEVICE_RETCODE_COUNT_ERROR       ((uint8_t) 0x10)

//! no nonce available, or nonce invalid, or nonce does not include a random source, or MacCount limit has been reached
#define AES132_DEVICE_RETCODE_NONCE_ERROR       ((uint8_t) 0x20)

//! Authorization MAC input is missing, or MAC compare failed.
#define AES132_DEVICE_RETCODE_MAC_ERROR         ((uint8_t) 0x40)

//! bad opcode, bad mode, bad parameter, invalid length, or other encoding failure
#define AES132_DEVICE_RETCODE_PARSE_ERROR       ((uint8_t) 0x50)

//! EEPROM post-write automatic data verification failed due to data mismatch.
#define AES132_DEVICE_RETCODE_DATA_MISMATCH     ((uint8_t) 0x60)

//! Lock command contained bad checksum or bad MAC.
#define AES132_DEVICE_RETCODE_LOCK_ERROR        ((uint8_t) 0x70)

/** \brief Key is not permitted to be used for this operation,
 *         or wrong key was used for operation,
 *         or prior authentication has not been performed,
 *         or other authentication error,
 *         or other key error has occurred.
 */
#define AES132_DEVICE_RETCODE_KEY_ERROR         ((uint8_t) 0x80)

//! temperature sensor timeout error
#define AES132_DEVICE_RETCODE_TEMP_SENSE_ERROR  ((uint8_t) 0x90)


// ------------- definitions for option flags used when sending a command --------

//! default flags for option parameter
#define AES132_OPTION_DEFAULT                   ((uint8_t) 0x00)

/** \brief flag for option parameter that indicates whether or not to
 *         calculate and append a CRC.
 */
#define AES132_OPTION_NO_APPEND_CRC             ((uint8_t) 0x01)

/** \brief flag for option parameter that indicates whether or not to
 *         read the device status register after sending a command.
 */
#define AES132_OPTION_NO_STATUS_READ            ((uint8_t) 0x02)


// ----- definitions for byte indexes of command buffer --------

//! count at index 0 (1 byte)
#define AES132_COMMAND_INDEX_COUNT              (0)

//! op-code at index 1 (1 byte)
#define AES132_COMMAND_INDEX_OPCODE             (1)

//! mode at index 2 (1 byte)
#define AES132_COMMAND_INDEX_MODE               (2)

//! msb of param1 (2 bytes) at index 3
#define AES132_COMMAND_INDEX_PARAM1_MSB         (3)

//! lsb of param1 (2 bytes) at index 4
#define AES132_COMMAND_INDEX_PARAM1_LSB         (4)

//! msb of param2 (2 bytes) at index 5
#define AES132_COMMAND_INDEX_PARAM2_MSB         (5)

//! msb of param2 (2 bytes) at index 5
#define AES132_COMMAND_INDEX_PARAM2_LSB         (6)


// ----- definitions for Standby and Sleep modes --------

//! value of mode byte for the Sleep command to put device into Sleep mode
#define AES132_COMMAND_MODE_SLEEP               ((uint8_t) 0x00)

//! value of mode byte for the Sleep command to put device into Standby mode
#define AES132_COMMAND_MODE_STANDBY             ((uint8_t) 0x40)


// ----- definitions for byte indexes of response buffer --------

//! count at index 0 (1 byte)
#define AES132_RESPONSE_INDEX_COUNT             ((uint8_t)    0)

//! response return code at index 1 (1 byte)
#define AES132_RESPONSE_INDEX_RETURN_CODE       ((uint8_t)    1)

//! Response data start at index 2 (1 or more bytes).
#define AES132_RESPONSE_INDEX_DATA              ((uint8_t)    2)


// ------------ definitions for library return codes ----------------------------

#define AES132_FUNCTION_RETCODE_ADDRESS_WRITE_NACK   ((uint8_t) 0xA0) //!< I2C nack when sending a I2C address for writing
#define AES132_FUNCTION_RETCODE_ADDRESS_READ_NACK    ((uint8_t) 0xA1) //!< I2C nack when sending a I2C address for reading
#define AES132_FUNCTION_RETCODE_SIZE_TOO_SMALL       ((uint8_t) 0xA2) //!< Count value in response was bigger than buffer.

// The codes below are the same as in the SHA204 library.
#define AES132_FUNCTION_RETCODE_SUCCESS              ((uint8_t) 0x00) //!< Function succeeded.
#define AES132_FUNCTION_RETCODE_BAD_CRC_TX           ((uint8_t) 0xD4) //!< Device status register bit 4 (CRC) is set.
#define AES132_FUNCTION_RETCODE_NOT_IMPLEMENTED      ((uint8_t) 0xE0) //!< interface function not implemented
#define AES132_FUNCTION_RETCODE_DEVICE_SELECT_FAIL   ((uint8_t) 0xE3) //!< device index out of bounds
#define AES132_FUNCTION_RETCODE_COUNT_INVALID        ((uint8_t) 0xE4) //!< count byte in response is out of range
#define AES132_FUNCTION_RETCODE_BAD_CRC_RX           ((uint8_t) 0xE5) //!< incorrect CRC received
#define AES132_FUNCTION_RETCODE_TIMEOUT              ((uint8_t) 0xE7) //!< Function timed out while waiting for response.
#define AES132_FUNCTION_RETCODE_COMM_FAIL            ((uint8_t) 0xF0) //!< Communication with device failed.

#ifndef AES132_FUNCTION_RETCODE_BAD_PARAM
	#define AES132_FUNCTION_RETCODE_BAD_PARAM      ((uint8_t) (0xE2))
#endif

#ifndef AES132_MANUFACTURING_ID
	#define AES132_MANUFACTURING_ID                (0x00EE)
#endif

#ifndef AES132_COUNTER_MAX
	#define AES132_COUNTER_MAX                     (2097151)
#endif

//! Additional macro definitions for use with aes132 library
// --- Address ---
// User memory
#define AES132_USER_ZONE_ADDR(n)      ((uint16_t) (0x0000 + ((n) << 8)))

// Command memory
//   has been defined in aes132.h

// Configuration memory
#define AES132_SERIAL_NUM_ADDR        ((uint16_t) 0xF000)
#define AES132_MANUFACTURING_ID_ADDR  ((uint16_t) 0xF02B)
#define AES132_LOCK_KEYS_ADDR         ((uint16_t) 0xF020)
#define AES132_LOCK_SMALL_ADDR        ((uint16_t) 0xF021)
#define AES132_LOCK_CONFIG_ADDR       ((uint16_t) 0xF022)

#define AES132_KEY_CONFIG_ADDR(n)     ((uint16_t) (0xF080 + ((n) << 2)))
#define AES132_ZONE_CONFIG_ADDR(n)    ((uint16_t) (0xF0C0 + ((n) << 2)))
#define AES132_COUNTER_CONFIG_ADDR(n) ((uint16_t) (0xF060 + ((n) << 1)))
#define AES132_COUNTER_ADDR(n)        ((uint16_t) (0xF100 + ((n) << 3)))

#define AES132_SMALL_ZONE_ADDR        ((uint16_t) (0xF1E0))

// Key memory
#define AES132_KEY_ADDR(n)            ((uint16_t) (0xF200 + ((n) << 4)))


// --- Length ---
#define AES132_USER_ZONE_LENGTH          (256)
#define AES132_SERIAL_NUM_LENGTH         (8)
#define AES132_MANUFACTURING_ID_LENGTH   (2)
#define AES132_KEY_CONFIG_LENGTH         (4)
#define AES132_ZONE_CONFIG_LENGTH        (4)
#define AES132_COUNTER_CONFIG_LENGTH     (2)
#define AES132_COUNTER_LENGTH            (8)
#define AES132_KEY_LENGTH                (16)

#define AES132_MAC_LENGTH                (16)


// --- Bit positions ---
// KeyConfig Byte #0
#define AES132_KEY_CONFIG_EXTERNAL_CRYPTO     (1 << 0)
#define AES132_KEY_CONFIG_INBOUND_AUTH        (1 << 1)
#define AES132_KEY_CONFIG_RANDOM_NONCE        (1 << 2)
#define AES132_KEY_CONFIG_LEGACY_OK           (1 << 3)
#define AES132_KEY_CONFIG_AUTH_KEY            (1 << 4)
#define AES132_KEY_CONFIG_CHILD               (1 << 5)
#define AES132_KEY_CONFIG_PARENT              (1 << 6)
#define AES132_KEY_CONFIG_CHANGE_KEYS         (1 << 7)

// KeyConfig Byte #1
#define AES132_KEY_CONFIG_COUNTER_LIMIT       (1 << 0)
#define AES132_KEY_CONFIG_CHILD_MAC           (1 << 1)
#define AES132_KEY_CONFIG_AUTH_OUT            (1 << 2)
#define AES132_KEY_CONFIG_AUTH_OUT_HOLD       (1 << 3)
#define AES132_KEY_CONFIG_IMPORT_OK           (1 << 4)
#define AES132_KEY_CONFIG_EXPORT_AUTH         (1 << 5)
#define AES132_KEY_CONFIG_TRANSFER_OK         (1 << 6)
#define AES132_KEY_CONFIG_AUTH_COMPUTE        (1 << 7)

// CounterConfig Byte #0
#define AES132_COUNTER_CONFIG_INCREMENT_OK    (1 << 0)
#define AES132_COUNTER_CONFIG_REQUIRE_MAC     (1 << 1)

// ZoneConfig Byte #0
#define AES132_ZONE_CONFIG_AUTH_READ          (1 << 0)
#define AES132_ZONE_CONFIG_AUTH_WRITE         (1 << 1)
#define AES132_ZONE_CONFIG_ENC_READ           (1 << 2)
#define AES132_ZONE_CONFIG_ENC_WRITE          (1 << 3)
#define AES132_ZONE_CONFIG_WRITE_MODE_4       (1 << 4)
#define AES132_ZONE_CONFIG_WRITE_MODE_5       (1 << 5)
#define AES132_ZONE_CONFIG_USE_SERIAL         (1 << 6)
#define AES132_ZONE_CONFIG_USE_SMALL          (1 << 7)
// ZoneConfig Byte #2
#define AES132_ZONE_CONFIG_VOLATILE_TRANSFER_OK          (1 << 0)
// VolUsage Byte #0
#define AES132_VOL_USAGE_AUTH_OK              (1 << 0)
#define AES132_VOL_USAGE_ENCRYPT_OK_1         (1 << 1)
#define AES132_VOL_USAGE_ENCRYPT_OK_2         (1 << 2)
#define AES132_VOL_USAGE_DECRYPT_OK           (1 << 3)
#define AES132_VOL_USAGE_RANDOM_NONCE         (1 << 4)
#define AES132_VOL_USAGE_AUTH_COMPUTE         (1 << 5)
#define AES132_VOL_USAGE_LEGACY_OK            (1 << 6)
#define AES132_VOL_USAGE_EXPORT_OK            (1 << 7)

// VolUsage Byte #1
#define AES132_VOL_USAGE_WRITE_COMPUTE        (1 << 0)
#define AES132_VOL_USAGE_DEC_READ             (1 << 1)

// AuthUsage
#define AES132_AUTH_USAGE_READ_OK             (1 << 0)
#define AES132_AUTH_USAGE_WRITE_OK            (1 << 1)
#define AES132_AUTH_USAGE_KEY_USE             (1 << 2)

// MacFlag
#define AES132_MAC_FLAG_RANDOM                (1 << 0)
#define AES132_MAC_FLAG_INPUT                 (1 << 1)

// Info Register
#define AES132_INFO_MACCOUNT				0x0000
#define AES132_INFO_AUTH_STATUS				0x0005
#define AES132_INFO_DEVICENUMBER			0x0006
#define AES132_INFO_CHIPSTATE				0x000C

// Locks
#define AES132_LOCK_SMALLZONE	(0x00)
#define AES132_LOCK_KEYMEMORY	(0x01)
#define AES132_LOCK_CONFIG		(0x02)
#define AES132_LOCK_ZONECONFIG	(0x03)


extern int fd;

#endif //_UECC_TESTS_H_
#ifdef __cplusplus
}
#endif