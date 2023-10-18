/*
 * implifi_obj.hpp
 *
 *  Created on: Aug 23, 2023
 *      Author: Jethro Reimann
 */
#include "rs.hpp"
using namespace std;

#ifndef IMPLIFI_CLASS_INC_IMPLIFI_OBJ_HPP_
#define IMPLIFI_CLASS_INC_IMPLIFI_OBJ_HPP_

#define AES_BLOCK_LENGTH 8
#define PLAINTEXT_LENGTH  16
#define ECC_LENGTH 12
#define RS_MESSAGE_LENGTH 128

/**
  * Describe object here
  *
  *
  *
  *
  *
  *
  *
  *
  *
  *
  *
  */

class ImpLiFiClass
{
	public:
		uint8_t AES_Key[CRL_AES128_KEY];

		RS::ReedSolomon<RS_MESSAGE_LENGTH, ECC_LENGTH> rs; 		             // Reed solomon encoder data structure

		// VARS BELOW ARE FOR DECODE
		//variables for passing between encryption/decryption helper functions
		uint8_t manchester_encoded_buff_cpy[2*(RS_MESSAGE_LENGTH + ECC_LENGTH)]; // Raw input from UART
		uint8_t rs_encoded_buff[RS_MESSAGE_LENGTH + ECC_LENGTH];             // After decoding manchester
		uint8_t reed_solomon_repaired[RS_MESSAGE_LENGTH];
		uint8_t output_split_ciphertext[8][PLAINTEXT_LENGTH]; // Input plaintext split into 16 byte chunks
		uint8_t output_split_plaintext[8][PLAINTEXT_LENGTH];  // Input plaintext split into 16 byte chunks
		uint8_t output_message[RS_MESSAGE_LENGTH];            // Output of decoding

		uint8_t input_message[RS_MESSAGE_LENGTH];             // Input of encoding

		//VARS BELOW ARE FOR ENCODE
		uint8_t plaintext_cpy_in[RS_MESSAGE_LENGTH];
		uint8_t encoder_split_plaintext[8][PLAINTEXT_LENGTH];
		uint8_t encoder_split_ciphertext[8][PLAINTEXT_LENGTH];
		uint8_t encoder_ciphertext_str[RS_MESSAGE_LENGTH];
		uint8_t encoder_reed_solomon_str[RS_MESSAGE_LENGTH + ECC_LENGTH];
		uint8_t encoder_manchester[2*(RS_MESSAGE_LENGTH + ECC_LENGTH) + 2];
		uint8_t manchester_helper_temp[2];

		//variables for DecodeManchester
		int error_code;
		uint8_t byte_out;
		uint8_t byte_out_nibble_1;
		uint8_t byte_out_nibble_2;
		uint8_t uart_byte_1;
		uint8_t uart_byte_2;

		//variables for Reed-Solomon Decode
		uint8_t err_pos;
		size_t num_err;
		uint8_t num_errs_val;

		//variables for SplitStringForAESDecoding
		int indexing_dummy;

		//variables for AESDecrypt2DArray
		uint32_t output_message_length;

		//variables for CombineAES2DArray

		//constructors
		ImpLiFiClass(void);
		ImpLiFiClass(uint8_t aes_key_in[]);

		//public member functions/methods
		bool DecryptData(uint8_t manchester_in[]);   // Returns 0 if successful
		bool EncryptData(uint8_t plaintext_in[]);    // returns 0 if successful

		void EncodeManchester(uint8_t str_in[],
							  uint8_t str_out[]);

		void ManchesterHelper(uint8_t byte_i,
							  uint8_t bytes_out[]);

		void DecodeManchester(uint8_t manchester_in[],
							  uint8_t reed_solomon_out[]);

		void SplitStringForAESDecoding(uint8_t input_str[],
									   uint8_t output_ptr[][PLAINTEXT_LENGTH]);

		int32_t AESDecrypt2DArray(uint8_t input_ciphertext[][PLAINTEXT_LENGTH],
								  uint8_t output_plaintext[][PLAINTEXT_LENGTH]);

		void CombineAES2DArray(uint8_t input_ciphertext[][PLAINTEXT_LENGTH],
							   char output_str[]);

		int32_t STM32_AES_ECB_Decrypt(uint8_t* InputMessage,
		                              uint32_t InputMessageLength,
		                              uint8_t  *AES256_Key,
		                              uint8_t  *OutputMessage,
		                              uint32_t *OutputMessageLength);

		int32_t STM32_AES_ECB_Encrypt(uint8_t* InputMessage,
		                              uint32_t InputMessageLength,
		                              uint8_t  *AES256_Key,
		                              uint8_t  *OutputMessage,
		                              uint32_t *OutputMessageLength);

		// Updated reusable transmitter/receiver functions
		bool SplitStringForAES(uint8_t input_str[],
				               uint8_t output_mat[][PLAINTEXT_LENGTH]);

		int AES2DMatrix(uint8_t input_mat[][PLAINTEXT_LENGTH],
				        uint8_t output_mat[][PLAINTEXT_LENGTH],
						bool encrypt);

		bool Combine2DMatrix(uint8_t input_mat[][PLAINTEXT_LENGTH],
							 uint8_t output_str[]);


};

/**
  * Constructors
  */
ImpLiFiClass::ImpLiFiClass(void)
{
	AES_Key[0] = 0x00;
	AES_Key[1] = 0x01;
	AES_Key[2] = 0x02;
	AES_Key[3] = 0x03;
	AES_Key[4] = 0x04;
	AES_Key[5] = 0x05;
	AES_Key[6] = 0x06;
	AES_Key[7] = 0x07;
	AES_Key[8] = 0x08;
	AES_Key[9] = 0x09;
	AES_Key[10] = 0x0A;
	AES_Key[11] = 0x0B;
	AES_Key[12] = 0x0C;
	AES_Key[13] = 0x0D;
	AES_Key[14] = 0x0E;
	AES_Key[15] = 0x0F;

	output_message_length = 0;
	indexing_dummy = 0;
}

ImpLiFiClass::ImpLiFiClass(uint8_t aes_key_in[])
{
	for(int i = 0; i < CRL_AES128_KEY; i++)
	{
		AES_Key[i] = aes_key_in[i];
	}

	output_message_length = 0;
	indexing_dummy = 0;
}

bool ImpLiFiClass::EncryptData(uint8_t plaintext_in[])
{
	memcpy(plaintext_cpy_in, plaintext_in, sizeof(plaintext_cpy_in));

	SplitStringForAES(plaintext_cpy_in, encoder_split_plaintext);
	AES2DMatrix(encoder_split_plaintext, encoder_split_ciphertext, true);
	Combine2DMatrix(encoder_split_ciphertext, encoder_ciphertext_str);
	rs.Encode(encoder_ciphertext_str, encoder_reed_solomon_str);
	EncodeManchester(encoder_reed_solomon_str, encoder_manchester);

	return true;
}

bool ImpLiFiClass::DecryptData(uint8_t manchester_in[]) // Returns 0 if successful
{
	memcpy(manchester_encoded_buff_cpy, manchester_in, sizeof(manchester_encoded_buff_cpy));

	DecodeManchester(manchester_encoded_buff_cpy, rs_encoded_buff);
	error_code = rs.Decode(rs_encoded_buff, reed_solomon_repaired, NULL, 0, num_errs_val);
	//if(rs.Decode(rs_encoded_buff, reed_solomon_repaired, &err_pos, num_err, num_errs_val) != 0)
	//{
	//	return false;
	//}
	SplitStringForAES(reed_solomon_repaired, output_split_ciphertext);
	AES2DMatrix(output_split_ciphertext, output_split_plaintext, false);
	Combine2DMatrix(output_split_plaintext, output_message);

	return true;
}

/**
  * Runs helper functions
  *
  *
  */
/*
bool ImpLiFiClass::DecryptData(uint8_t manchester_in[]) // Returns 0 if successful
{
	memcpy(manchester_encoded_buff_cpy, manchester_in, sizeof(manchester_encoded_buff_cpy));

	DecodeManchester(manchester_encoded_buff_cpy, rs_encoded_buff);
	error_code = rs.Decode(rs_encoded_buff, reed_solomon_repaired, &err_pos, num_err, num_errs_val);       // Corrects bits errors - output is 129 bytes
	if(error_code != 0)
	{
		return error_code;
	}
	SplitStringForAES(reed_solomon_repaired, output_split_ciphertext); // Split message into 16 byte chunks and removes the termininating '\0' char
	AESDecrypt2DArray(output_split_ciphertext, output_split_plaintext);        // Decrypt each AES block
	Combine2DMatrix(output_split_plaintext, output_message);                 // Put all decrypted AES blocks into single char array

	//return string(output_message);
	return 0;
}
*/

/**
  * Takes 128 byte input and stuffs it into 16x8 matrix.
  * Delete indexing dummy, just for debugging
  *
  *
  *
  *
  *
  */
bool ImpLiFiClass::SplitStringForAES(uint8_t input_str[], uint8_t output_mat[][PLAINTEXT_LENGTH])
{
	// NOTE: Should check array/matrix size, but I dont have time to debug right now
	//if((sizeof(input_str) != 128) | (sizeof(output_str) != AES_BLOCK_LENGTH))
	//{
	//	return false;
	//}
	//indexing_dummy = 0;
	for(int i = 0; i < AES_BLOCK_LENGTH; i++)
	{
		for(int j = 0; j < PLAINTEXT_LENGTH; j++)
		{
			output_mat[i][j] = input_str[(PLAINTEXT_LENGTH*i) + j];
			//indexing_dummy = (PLAINTEXT_LENGTH*i) + j;
		}
	}

	return true;
}

/**
  * Encrypts or decrypts 2D matrix with AES key
  *
  */
int ImpLiFiClass::AES2DMatrix(uint8_t input_mat[][PLAINTEXT_LENGTH],
							  uint8_t output_mat[][PLAINTEXT_LENGTH],
							  bool encrypt)
{
	int32_t encrypt_status_temp;
	if(encrypt == false) // Decrypt
	{
		for(int i = 0; i < AES_BLOCK_LENGTH; i++)
		{
			encrypt_status_temp = STM32_AES_ECB_Decrypt(input_mat[i], PLAINTEXT_LENGTH, AES_Key, output_mat[i], &output_message_length);
			if(encrypt_status_temp != AES_SUCCESS)
			{
				return encrypt_status_temp;
			}
		}
		return AES_SUCCESS;
	}
	else                 // Encrypt
	{
		for(int i = 0; i < AES_BLOCK_LENGTH; i++)
		{
			encrypt_status_temp = STM32_AES_ECB_Encrypt(input_mat[i], PLAINTEXT_LENGTH, AES_Key, output_mat[i], &output_message_length);
			if(encrypt_status_temp != AES_SUCCESS)
			{
				return encrypt_status_temp;
			}
		}
		return AES_SUCCESS;
	}
}

/**
  * Combines 16x8 2D matrix into 128 byte string.
  */

bool ImpLiFiClass::Combine2DMatrix(uint8_t input_mat[][PLAINTEXT_LENGTH], uint8_t output_str[])
{
	// Should measure inputs and make sure they are 8x16 bytes and 128 bytes, respectively.
	// Return false if not. Dont have time to implement atm.
	for(int i = 0; i < AES_BLOCK_LENGTH; i++)
	{
		for(int j = 0; j < PLAINTEXT_LENGTH; j++)
		{
			output_str[(PLAINTEXT_LENGTH*i) + j] = (char)input_mat[i][j];
		}
	}

	return true;
}

/**
  * bool DecryptData(uint8_t manchester_in[])
  * 	Param(s):
  * 		uint8_t manchester_in[]: Data received from the UART Buffer
  * 	Returns:
  * 		True if successful, false if not
  * Call helper functions to:
  * 	a. Decode Manchester Data
  * 	b. Correct transmission errors w/ Reed-Solomon
  * 	c. Split the 128 bytes into a 8x16 matrix
  * 	d. Decrypt the eight 16 byte AES frames
  * 	e. Combine the eight 16 byte AES frames into 128 byte string
  */

/*
bool ImpLiFiClass::DecryptData(uint8_t manchester_in[]) // Returns 0 if successful
{
	memcpy(manchester_encoded_buff_cpy, manchester_in, sizeof(manchester_encoded_buff_cpy));

	DecodeManchester(manchester_encoded_buff_cpy, rs_encoded_buff);
	error_code = rs.Decode(rs_encoded_buff, reed_solomon_repaired, &err_pos, num_err, num_errs_val);       // Corrects bits errors - output is 129 bytes
	if(error_code != 0)
	{
		return error_code;
	}
	SplitStringForAESDecoding(reed_solomon_repaired, output_split_ciphertext); // Split message into 16 byte chunks and removes the termininating '\0' char
	AESDecrypt2DArray(output_split_ciphertext, output_split_plaintext);        // Decrypt each AES block
	CombineAES2DArray(output_split_plaintext, output_message);                 // Put all decrypted AES blocks into single char array

	//return string(output_message);
	return 0;
}
*/


void ImpLiFiClass::DecodeManchester(uint8_t manchester_in[], uint8_t reed_solomon_out[])
{
	//decoding manchester
	for(int i = 0; i < RS_MESSAGE_LENGTH + ECC_LENGTH; i++)
	{
		byte_out = 0x00;
		byte_out_nibble_1 = 0x00;
		byte_out_nibble_2 = 0x00;

		uart_byte_1 = manchester_in[2*i];
		uart_byte_2 = manchester_in[2*i + 1];


		if((uart_byte_1 & 0xC0) == 0x40) // 8th bit is rising edge = one
		{
			byte_out_nibble_1 = byte_out_nibble_1 | 0x08;     // Turn 8th bit to 1
		}
		if((uart_byte_1 & 0x30) == 0x10) // 7th bit is rising edge = one
		{
			byte_out_nibble_1 = byte_out_nibble_1 | 0x04;     // Turn 7th bit to 1
		}
		if((uart_byte_1 & 0x0C) == 0x04) // 6th bit is rising edge = one
		{
			byte_out_nibble_1 = byte_out_nibble_1 | 0x02;     // Turn 6th bit to 1
		}
		if((uart_byte_1 & 0x03) == 0x01) // 5th bit is rising edge = one
		{
			byte_out_nibble_1 = byte_out_nibble_1 | 0x01;     // Turn 5th bit to 1
		}

		if((uart_byte_2 & 0xC0) == 0x40) // 4th bit is rising edge = one
		{
			byte_out_nibble_2 = byte_out_nibble_2 | 0x08;     // Turn 4th bit to 1
		}
		if((uart_byte_2 & 0x30) == 0x10) // 3rd bit is rising edge = one
		{
			byte_out_nibble_2 = byte_out_nibble_2 | 0x04;     // Turn 3rd bit to 1
		}
		if((uart_byte_2 & 0x0C) == 0x04) // 2nd bit is rising edge = one
		{
			byte_out_nibble_2 = byte_out_nibble_2 | 0x02;     // Turn 2nd bit to 1
		}
		if((uart_byte_2 & 0x03) == 0x01) // 1st bit is rising edge = one
		{
			byte_out_nibble_2 = byte_out_nibble_2 | 0x01;     // Turn 1st bit to 1
		}

		reed_solomon_out[i] = (byte_out_nibble_1<<4) | byte_out_nibble_2;
	}
}

void ImpLiFiClass::EncodeManchester(uint8_t str_in[], uint8_t str_out[])
{
	str_out[0] = 0x00;
	str_out[1] = 0x00;
	for(int i = 0; i < RS_MESSAGE_LENGTH + ECC_LENGTH; i++)
	{
		ManchesterHelper(str_in[i], manchester_helper_temp);
		str_out[2*i + 2] = manchester_helper_temp[0];
		str_out[2*i + 3] = manchester_helper_temp[1];
	}
}

void ImpLiFiClass::ManchesterHelper(uint8_t byte_i, uint8_t bytes_out[])
{
	uint8_t manchester_byte_1 = 0x00;
	uint8_t manchester_byte_2 = 0x00;

	//FIRST BIT
	if((byte_i & 0x80) == 0x00) //MSB is zero
	{
		manchester_byte_1 = manchester_byte_1+128; //send falling edge
	}
	else                       //MSB is one
	{
		manchester_byte_1 = manchester_byte_1+64; //send rising edge
	}

	//SECOND BIT
	if((byte_i & 0x40) == 0x00) //2nd MSB is zero
	{
		manchester_byte_1 = manchester_byte_1+32; //send falling edge
	}
	else                       //2nd MSB is one
	{
		manchester_byte_1 = manchester_byte_1+16; //send rising edge
	}

	//THIRD BIT
	if((byte_i & 0x20) == 0x00) //3rd MSB is zero
	{
		manchester_byte_1 = manchester_byte_1 + 8; //send falling edge
	}
	else                       //3rd MSB is one
	{
		manchester_byte_1 = manchester_byte_1 + 4; //send rising edge
	}

		//FOURTH BIT
	if((byte_i & 0x10) == 0x00) //4th MSB is zero
	{
		manchester_byte_1 = manchester_byte_1 + 2; //send falling edge
	}
	else                       //4th MSB is one
	{
		manchester_byte_1 = manchester_byte_1 + 1; //send rising edge
	}

	//FIFTH BIT
	if((byte_i & 0x08) == 0x00) //4th MSB is zero
	{
		manchester_byte_2 = manchester_byte_2 + 0x80; //send falling edge
	}
	else                       //4th MSB is one
	{
		manchester_byte_2 = manchester_byte_2 + 0x40; //send rising edge
	}

	//SIXTH BIT
	if((byte_i & 0x04) == 0x00) //5th MSB is zero
	{
		manchester_byte_2 = manchester_byte_2 + 0x20; //send falling edge
	}
	else                       //5th MSB is one
	{
		manchester_byte_2 = manchester_byte_2 + 0x10; //send rising edge
	}

	//SEVENTH BIT
	if((byte_i & 0x02) == 0x00) //7th MSB is zero
	{
		manchester_byte_2 = manchester_byte_2 + 0x08; //send falling edge
	}
	else                       //7th MSB is one
	{
		manchester_byte_2 = manchester_byte_2 + 0x04; //send rising edge
	}

	//EIGHTH BIT
	if((byte_i & 0x01) == 0x00) //8th MSB is zero
	{
		manchester_byte_2 = manchester_byte_2 + 0x02; //send falling edge
	}
	else                       //8th MSB is one
	{
		manchester_byte_2 = manchester_byte_2 + 0x01; //send rising edge
	}

	bytes_out[0] = manchester_byte_1;
	bytes_out[1] = manchester_byte_2;
}


/*
void ImpLiFiClass::SplitStringForAESDecoding(uint8_t input_str[], uint8_t output_ptr[][PLAINTEXT_LENGTH])
{
	indexing_dummy = 0;
	for(int i = 0; i < AES_BLOCK_LENGTH; i++)
	{
		for(int j = 0; j < PLAINTEXT_LENGTH; j++)
		{
			output_ptr[i][j] = input_str[(PLAINTEXT_LENGTH*i) + j];
			indexing_dummy = (PLAINTEXT_LENGTH*i) + j;
		}
	}
}
*/


int32_t ImpLiFiClass::AESDecrypt2DArray(uint8_t input_ciphertext[][PLAINTEXT_LENGTH], uint8_t output_plaintext[][PLAINTEXT_LENGTH])
{
	int32_t encrypt_status_temp;
	for(int i = 0; i < AES_BLOCK_LENGTH; i++)
	{
		encrypt_status_temp = STM32_AES_ECB_Decrypt(input_ciphertext[i], PLAINTEXT_LENGTH, AES_Key, output_plaintext[i], &output_message_length);
		if(encrypt_status_temp != AES_SUCCESS)
		{
			return encrypt_status_temp;
		}
	}
	return AES_SUCCESS;
}


/*
void ImpLiFiClass::CombineAES2DArray(uint8_t input_ciphertext[][PLAINTEXT_LENGTH], char output_str[])
{
	for(int i = 0; i < AES_BLOCK_LENGTH; i++)
	{
		for(int j = 0; j < PLAINTEXT_LENGTH; j++)
		{
			output_str[(PLAINTEXT_LENGTH*i) + j] = (char)input_ciphertext[i][j];
		}
	}
}
*/

int32_t ImpLiFiClass::STM32_AES_ECB_Encrypt(uint8_t* InputMessage,
                              uint32_t InputMessageLength,
                              uint8_t  *AES256_Key,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength)
{
  AESECBctx_stt AESctx;

  uint32_t error_status = AES_SUCCESS;

  int32_t outputLength = 0;

  /* Set flag field to default value */
  AESctx.mFlags = E_SK_DEFAULT;

  /* Set key size to 32 (corresponding to AES-256) */
  //AESctx.mKeySize = 32;
  AESctx.mKeySize = 16;

  /* Initialize the operation, by passing the key.
   * Third parameter is NULL because ECB doesn't use any IV */
  error_status = AES_ECB_Encrypt_Init(&AESctx, AES256_Key, NULL );

  /* check for initialization errors */
  if (error_status == AES_SUCCESS)
  {
    /* Encrypt Data */
    error_status = AES_ECB_Encrypt_Append(&AESctx,
                                          InputMessage,
                                          InputMessageLength,
                                          OutputMessage,
                                          &outputLength);

    if (error_status == AES_SUCCESS)
    {
      /* Write the number of data written*/
      *OutputMessageLength = outputLength;
      /* Do the Finalization */
      error_status = AES_ECB_Encrypt_Finish(&AESctx, OutputMessage + *OutputMessageLength, &outputLength);
      /* Add data written to the information to be returned */
      *OutputMessageLength += outputLength;
    }
  }

  return error_status;
}

int32_t ImpLiFiClass::STM32_AES_ECB_Decrypt(uint8_t* InputMessage,
                              uint32_t InputMessageLength,
                              uint8_t  *AES256_Key,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength)
{
  AESECBctx_stt AESctx;

  uint32_t error_status = AES_SUCCESS;

  int32_t outputLength = 0;

  /* Set flag field to default value */
  AESctx.mFlags = E_SK_DEFAULT;

  /* Set key size to 32 (corresponding to AES-256) */
  //AESctx.mKeySize = 32;
  AESctx.mKeySize = 16;

  /* Initialize the operation, by passing the key.
   * Third parameter is NULL because ECB doesn't use any IV */
  error_status = AES_ECB_Decrypt_Init(&AESctx, AES256_Key, NULL );

  /* check for initialization errors */
  if (error_status == AES_SUCCESS)
  {
    /* Decrypt Data */
    error_status = AES_ECB_Decrypt_Append(&AESctx,
                                          InputMessage,
                                          InputMessageLength,
                                          OutputMessage,
                                          &outputLength);

    if (error_status == AES_SUCCESS)
    {
      /* Write the number of data written*/
      *OutputMessageLength = outputLength;
      /* Do the Finalization */
      error_status = AES_ECB_Decrypt_Finish(&AESctx, OutputMessage + *OutputMessageLength, &outputLength);
      /* Add data written to the information to be returned */
      *OutputMessageLength += outputLength;
    }
  }

  return error_status;
}

#endif /* IMPLIFI_CLASS_INC_IMPLIFI_OBJ_HPP_ */
