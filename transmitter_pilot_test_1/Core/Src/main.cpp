/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2023 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "crypto.h"
#include "stdio.h"
#include <string>
#include "rs.hpp"
#include "implifi_obj.hpp"
using namespace std;
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
typedef enum {FAILED = 0, PASSED = !FAILED} TestStatus;
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define AES_BLOCK_LENGTH 8
//#define PLAINTEXT_LENGTH  28
#define PLAINTEXT_LENGTH  16
//#define ECC_LENGTH        126 // ECC_LENGTH + RS_MESSAGE_LENGTH = 255
#define ECC_LENGTH 12
#define RS_MESSAGE_LENGTH 128

#define UART_BAUD_RATE 57600
#define UART_STOP_BITS UART_STOPBITS_2

//#define RS_MESSAGE_LENGTH 16
//#define ECC_LENGTH 12
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
CRC_HandleTypeDef hcrc;

UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
//char Message[8*PLAINTEXT_LENGTH];// = "LiFi Test ABCDE\n";
string input_message_str;
char input_message_char[RS_MESSAGE_LENGTH];
uint8_t plaintext[PLAINTEXT_LENGTH];

uint8_t AES_Key[CRL_AES128_KEY] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

uint8_t EncryptedMessage[PLAINTEXT_LENGTH];

uint32_t output_message_length = 0;

char buf[64];

uint8_t zero_array[2] = {0x00, 0x00};

RS::ReedSolomon<RS_MESSAGE_LENGTH, ECC_LENGTH> rs; 		        // Reed solomon encoder data structure

//AES Encoding variables
uint8_t split_plaintext[8][PLAINTEXT_LENGTH];  // Input plaintext split into 16 byte chunks
uint8_t input_split_ciphertext[8][PLAINTEXT_LENGTH];  // Input plaintext split into 16 byte chunks
int32_t aes_encrypt_status = AES_SUCCESS;

char output_message[RS_MESSAGE_LENGTH];

uint16_t frame_index = 0;

ImpLiFiClass implifi_test_obj;

uint8_t manchester_temp_arr[282];

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_CRC_Init(void);
static void MX_USART2_UART_Init(void);

/* USER CODE BEGIN PFP */
void TestImpLiFiEncodeDecode(void);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_CRC_Init();
  MX_USART2_UART_Init();

  /* USER CODE BEGIN 2 */
  input_message_str = "   LiFi Test ABCD  LiFi Test ABCD  LiFi Test ABCD  LiFi Test ABCD  LiFi Test ABCD  LiFi Test ABCD  LiFi Test ABCD  LiFi Test ABC";
  //input_message_char
  strcpy(input_message_char, input_message_str.c_str());
  frame_index = 0;
  //TestImpLiFiEncodeDecode();

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
	  //EncryptData(input_message);
	  //EncodeManchester(reed_solomon_encoded, manchester_encoded);
	  //HAL_UART_Transmit_IT(&huart2, zero_array, 2);

	  //HAL_UART_Transmit(&huart2, manchester_encoded, RS_MESSAGE_LENGTH + ECC_LENGTH, 50);
	  //HAL_UART_Transmit_IT(&huart2, manchester_encoded, RS_MESSAGE_LENGTH + ECC_LENGTH);
	  //HAL_UART_Transmit(&huart2, 0x00, 1, 5);

	  input_message_char[0] = (uint8_t)(frame_index >> 8);
	  input_message_char[1] = (uint8_t)(frame_index >> 0);
	  if(implifi_test_obj.EncryptData((uint8_t*)input_message_char))
	  {
		  while(huart2.gState != HAL_UART_STATE_READY)
		  {
			  // loop here until the previous message has finished sending
		  }
		  HAL_Delay(1);
		  memcpy(manchester_temp_arr, implifi_test_obj.encoder_manchester, sizeof(implifi_test_obj.encoder_manchester));
		  HAL_UART_Transmit_IT(&huart2, manchester_temp_arr, 2*(RS_MESSAGE_LENGTH + ECC_LENGTH) + 2);

		  /*
		  uint8_t temp_section[42];
		  std::copy(manchester_temp_arr, manchester_temp_arr + 41, temp_section);
		  HAL_UART_Transmit_IT(&huart2, temp_section, 42);
		  HAL_Delay(5);

		  copy(manchester_temp_arr + 42, manchester_temp_arr + 81, temp_section);
		  HAL_UART_Transmit_IT(&huart2, temp_section, 40);
		  HAL_Delay(5);

		  copy(manchester_temp_arr + 82, manchester_temp_arr + 121, temp_section);
		  HAL_UART_Transmit_IT(&huart2, temp_section, 40);
		  HAL_Delay(5);

		  copy(manchester_temp_arr + 122, manchester_temp_arr + 161, temp_section);
		  HAL_UART_Transmit_IT(&huart2, temp_section, 40);
		  HAL_Delay(5);

		  copy(manchester_temp_arr + 162, manchester_temp_arr + 201, temp_section);
		  HAL_UART_Transmit_IT(&huart2, temp_section, 40);
		  HAL_Delay(5);

		  copy(manchester_temp_arr + 202, manchester_temp_arr + 241, temp_section);
		  HAL_UART_Transmit_IT(&huart2, temp_section, 40);
		  HAL_Delay(5);

		  copy(manchester_temp_arr + 242, manchester_temp_arr + 281, temp_section);
		  HAL_UART_Transmit_IT(&huart2, temp_section, 40);
		  HAL_Delay(5);
		  */

	  }
	  frame_index++;

	  if(frame_index >= 65535)
	  {
		  frame_index = 0;
	  }
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.HSEPredivValue = RCC_HSE_PREDIV_DIV1;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL9;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief CRC Initialization Function
  * @param None
  * @retval None
  */
static void MX_CRC_Init(void)
{

  /* USER CODE BEGIN CRC_Init 0 */

  /* USER CODE END CRC_Init 0 */

  /* USER CODE BEGIN CRC_Init 1 */

  /* USER CODE END CRC_Init 1 */
  hcrc.Instance = CRC;
  if (HAL_CRC_Init(&hcrc) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN CRC_Init 2 */

  /* USER CODE END CRC_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = UART_BAUD_RATE;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  //huart2.Init.StopBits = UART_STOPBITS_1;
  //huart2.Init.StopBits = UART_STOPBITS_2;
  huart2.Init.StopBits = UART_STOP_BITS;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_RESET);

  /*Configure GPIO pin : PA2 */
  //GPIO_InitStruct.Pin = GPIO_PIN_2;
  //GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  //GPIO_InitStruct.Pull = GPIO_NOPULL;
  //GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
 // HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

}

/* USER CODE BEGIN 4 */
/*
string EncryptData(string input_str)
{
	aes_encrypt_status = AES_SUCCESS;

	SplitStringForAESEncoding(input_str, split_plaintext); 				// Splits the message into 16 byte chunks and pads with 0x00 bytes

	AESEncrypt2DArray(split_plaintext, input_split_ciphertext);       // Encrypts each 16 byte chunk with AES-128

	CombineAES2DArray(input_split_ciphertext, reed_solomon_message);  // Takes the chunks and combines them into a 129 byte array with '\0' char at the end

	rs.Encode(reed_solomon_message, reed_solomon_encoded);            // Add the reed solomon redundant bits

	EncodeManchester(reed_solomon_encoded, manchester_encoded);

	return reed_solomon_encoded;
}
*/

/*
string DecryptData(string input_str)
{
	//HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_SET);
	// NOTE: This returns 0 if it worked, 1 if there was problem (too many corrupted bits
	//error_code = rs.Decode(reed_solomon_encoded, reed_solomon_repaired);       // Corrects bits errors - output is 129 bytes
	//HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_RESET);

	//HAL_Delay(10);

	//HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_SET);
	SplitStringForAESDecoding(reed_solomon_repaired, output_split_ciphertext); // Split message into 16 byte chunks and removes the termininating '\0' char
	//HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_RESET);

	//HAL_Delay(10);

	//HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_SET);
	AESDecrypt2DArray(output_split_ciphertext, output_split_plaintext);        // Decrypt each AES block
	//HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_RESET);

	//HAL_Delay(10);

	//HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_SET);
	CombineAES2DArray(output_split_plaintext, output_message);                 // Put all decrypted AES blocks into single char array
	//HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_RESET);

	//HAL_Delay(10);

	return string(output_message);
}
*/

/*
void SendByteImpLifi(uint8_t byte_i)
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

	//LL_USART_TransmitData8(USART2, manchester_byte_1);
	//LL_USART_TransmitData8(USART2, manchester_byte_2);
	HAL_UART_Transmit(&huart2, &manchester_byte_1, 1, 10);
	HAL_UART_Transmit(&huart2, &manchester_byte_2, 1, 10);	//UARTCharPutNonBlocking(UART5_BASE, manchester_byte_1);	UARTCharPutNonBlocking(UART5_BASE, manchester_byte_2);	//SysCtlDelay((SysCtlClockGet()/3u)/500); //THIS IS 1/500 SECOND DELAY
	//SysCtlDelay((SysCtlClockGet()/3u)/6000); //THIS IS 1/6000 SECOND DELAY (24x f=115200 baud rate periods)
}
*/

void SendZerosImpLifi(void)
{
	HAL_UART_Transmit(&huart2, zero_array, 2, 10);
	//HAL_Delay(0.0001);
	//TickDelay(500);
	//UARTCharPutNonBlocking(UART5_BASE, 0x00);
	//UARTCharPutNonBlocking(UART5_BASE, 0x00);
	//SysCtlDelay((SysCtlClockGet()/3u)/6000); //THIS IS 1/6000 SECOND DELAY (24x f=115200 baud rate periods)
}

void TickDelay(int n)
{
	for(int i = 0; i < n; i++)
	{

	}

}

void TestImpLiFiEncodeDecode(void)
{
	ImpLiFiClass implifi_test_obj; // create object

	//convert string into uint8_t[128] array
	string test_input_str = "Lifi Test ABCDE Lifi Test ABCDE Lifi Test ABCDE Lifi Test ABCDE Lifi Test ABCDE Lifi Test ABCDE Lifi Test ABCDE Lifi Test ABCDE "; // I think this is 128 bytes, plus null terminating
	uint8_t test_input_uint[128];
	for(int i = 0; i < 128; i++)
	{
		test_input_uint[i] = test_input_str[i];
	}

	implifi_test_obj.EncryptData(test_input_uint);

	uint8_t encoder_manchester_test[280];

	// This for loop should be memcpy
	for(int i = 2; i < 282; i++)
	{
		encoder_manchester_test[i-2] = implifi_test_obj.encoder_manchester[i];
	}

	// Flip some bytes to simulate transmission error
	// to test reed-solomon error correction

	encoder_manchester_test[7] = 0x00;
	encoder_manchester_test[17] = 0x00;
	encoder_manchester_test[27] = 0x00;


	//implifi_test_obj.DecryptData(encoder_manchester_test);

	ImpLiFiClass implifi_test_decode_obj;
	implifi_test_decode_obj.DecryptData(encoder_manchester_test);

	frame_index++; // for breakpoint debugging, delete later
}

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
