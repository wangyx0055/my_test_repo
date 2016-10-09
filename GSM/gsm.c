#if (HW_GSM == TRUE)
/*yy*/
#include "common.h"
#include	"gsm.h"

struct gsm_usart_buf_struct g_gsm_usart_buf;

void init_hw_gsm(void)
{
    GPIO_Init( MODEM_POWER_PORT,MODEM_POWER_PIN,GPIO_MODE_OUT,GPIO_OType_PP,GPIO_Speed_100MHz,GPIO_PuPd_NOPULL );
    MODEM_POWER_OFF;

    //GSM_POWER INIT
    GPIO_Init( MODEM_POWERKEY_PORT,MODEM_POWERKEY_PIN,GPIO_MODE_OUT,GPIO_OType_PP,GPIO_Speed_100MHz,GPIO_PuPd_NOPULL );		//GSM_POWERKEY INIT
    MODEM_PWRKEY_L;

    GPIO_Init( MODEM_DCD_PORT,MODEM_DCD_PIN,GPIO_MODE_OUT,GPIO_OType_PP,GPIO_Speed_100MHz,GPIO_PuPd_NOPULL );				//GSM_DCD INIT
    GSM_DCD_OFF;

    GPIO_Init( MODEM_DTR_PORT,MODEM_DTR_PIN,GPIO_MODE_OUT,GPIO_OType_PP,GPIO_Speed_100MHz,GPIO_PuPd_NOPULL );				//GPS_DTR INIT
    MODEM_DTR_WAKEUP;

    GPIO_Init( MODEM_RING_PORT,MODEM_RING_PIN,GPIO_MODE_IN,GPIO_OType_PP,GPIO_Speed_100MHz,GPIO_PuPd_NOPULL );				//GSM_RING_INIT
    GPIO_Init( MODEM_STATUS_PORT,MODEM_STATUS_PIN,GPIO_MODE_IN,GPIO_OType_PP,GPIO_Speed_100MHz,GPIO_PuPd_NOPULL );			//GSM_STATUS INIT

    //GSM_USART INIT
    GPIO_Init( MODEM_GPIO_RX_POTR,MODEM_GPIO_RX_PIN,GPIO_MODE_AF,GPIO_OType_PP,GPIO_Speed_50MHz,GPIO_PuPd_UP );
    GPIO_Init( MODEM_GPIO_TX_PORT,MODEM_GPIO_TX_PIN,GPIO_MODE_AF,GPIO_OType_PP,GPIO_Speed_50MHz,GPIO_PuPd_UP );
    GPIO_PinAFConfig( MODEM_GPIO_RX_POTR,MODEM_GPIO_RX_PinSource,MODEM_GPIO_AF );
    GPIO_PinAFConfig( MODEM_GPIO_TX_PORT,MODEM_GPIO_TX_PinSource,MODEM_GPIO_AF );

    USART_Init(MODEM_USART_PORT,  MODEM_USART_BAUD);
    USART_ClearFlag(MODEM_USART_PORT,USART_FLAG_TC);
    USART_ITConfig(MODEM_USART_PORT, USART_IT_RXNE, ENABLE);	//开启接收中断

    NVIC_Init(MODEM_USART_IRQn, 2,1, ENABLE);  

    MY_PRINT(GSM_PRINT, "\r\n\t初始化GSM硬件\r\n");
}

void deal_with_rx_data(uint8_t rx_data)
{
    if (g_gsm_usart_buf.rx_len >= MAX_GSM_RX_BUF_LEN)
    {
        g_gsm_usart_buf.rx_len = 0;
    }
    
    g_gsm_usart_buf.rx_buf[g_gsm_usart_buf.rx_len++] = rx_data;
    g_gsm_usart_buf.rx_time = 0;
}

void gsm_usart_irq_handler(void)
{
    uint8_t rx_data;  

    /* 使能了接收中断，那么ORE中断也同时被开启，所以也要解除串口溢出中断 */    
    if (USART_GetITStatus(MODEM_USART_PORT, USART_IT_ORE_RX) != RESET)
    {
        BUG_LED_ON;
        USART_ClearFlag(MODEM_USART_PORT, USART_FLAG_ORE);
        rx_data = USART_ReceiveAData(MODEM_USART_PORT);
        deal_with_rx_data(rx_data);
    }

    /* 处理串口接收中断 */
    if (USART_GetITStatus(MODEM_USART_PORT, USART_IT_RXNE) != RESET)  
    {
        USART_ClearFlag(MODEM_USART_PORT, USART_FLAG_RXNE);
        rx_data = (uint8_t)USART_ReceiveAData(MODEM_USART_PORT);
        deal_with_rx_data(rx_data);
    }
}

#endif

