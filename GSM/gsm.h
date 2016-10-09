#ifndef __GSM_H_
#define __GSM_H_

#include "board_cfg.h"

/* GSM */
#define		MODEM_POWER_OFF		GPIO_ResetBits(MODEM_POWER_PORT, MODEM_POWER_PIN)
#define		MODEM_POWER_ON		GPIO_SetBits(MODEM_POWER_PORT, MODEM_POWER_PIN)

/* 引脚电平与IO口相反，因硬件上有取反三极管 */
#define		MODEM_PWRKEY_H		GPIO_ResetBits(MODEM_POWERKEY_PORT, MODEM_POWERKEY_PIN) 
#define		MODEM_PWRKEY_L		GPIO_SetBits(MODEM_POWERKEY_PORT, MODEM_POWERKEY_PIN)

#define		GSM_DCD_OFF			GPIO_ResetBits(MODEM_DCD_PORT, MODEM_DCD_PIN)
#define		GSM_DCD_ON			GPIO_SetBits(MODEM_DCD_PORT, MODEM_DCD_PIN)

#define		MODEM_DTR_WAKEUP	GPIO_ResetBits(MODEM_DTR_PORT, MODEM_DTR_PIN)
#define		MODEM_DTR_SLEEP		GPIO_SetBits(MODEM_DTR_PORT, MODEM_DTR_PIN)

#define		GSM_READ_RING		       GPIO_ReadInputDataBit(MODEM_RING_PORT, MODEM_RING_PIN)
#define		GSM_READ_STATUS	       GPIO_ReadInputDataBit(MODEM_STATUS_PORT, MODEM_STATUS_PIN)

#define MAX_GSM_RX_BUF_LEN 1200

struct gsm_usart_buf_struct
{
    uint8_t rx_buf[MAX_GSM_RX_BUF_LEN];
    uint16_t rx_len;
    uint16_t rx_time;
};

void init_hw_gsm(void);

#endif

