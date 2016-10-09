#ifndef __APP_GSM_H_
#define __APP_GSM_H_

#include "common.h"
#include "app_lq.h"

#define GSM_INIT_NO_OK 0
#define GSM_INIT_OK 1

#define GSM_SHARED_BUF_DEFAULT_STATUS 0
#define GSM_SHARED_BUF_SEND_DOING         1

#define AT_FAILED_TIMES 10
#define GPRS_AT_FAILED_TIMES 5

#define GPRS_LINK_FAILED_TIMES 3
#define GPRS_LINK_FAILED_LOOPS 3

#define GPRS_SEND_DATA_FAILED_TIMES 3
#define GPRS_SEND_DATA_FAILED_LOOPS 3

#define GPRS_SEND_ENABLE_FAILED_TIMES 3
#define GPRS_SEND_ENABLE_FAILED_LOOPS 3

#define SMS_SEND_DATA_FAILED_TIMES 3
#define SMS_SEND_DATA_FAILED_LOOPS 3

#define SMS_SEND_ENABLE_FAILED_TIMES 3
#define SMS_SEND_ENABLE_FAILED_LOOPS 3

#define GSM_POWER_OFF_TIMES 6

#define GSM_SEND_PACKET_BUF_LEN 256 //帧协议所支持的帧长
#define GSM_SEND_PACKET_BUF_NUM 15

#define MAX_AT_NUM 35

#define MAX_SMS_SEND_LEN 140
#define MAX_SMS_SEND_CHAR (MAX_SMS_SEND_LEN * 2) //注意，在发送时一个字节占2个字符位
#define SMS_SEND_HEADER_LEN 15

#ifndef NEW_PROTOCOL
#define BY_GPRS 15
#define BY_SMS   0
#else
#define BY_GPRS 2
#define BY_SMS   1
#endif


#define PDU_SMS_HEADER 58
#define SMS_NUMBER_LEN 11

enum gprs_link_status_enum
{
    GPRS_NOT_CONNECTED,
    GPRS_CONNECTED,
};

enum at_ack_enum
{
    AT_ACK_OK, //0x0
    AT_ACK_ERROR,
    AT_ACK_CSQ,
    AT_ACK_CSCA,
    AT_ACK_CLOSE_OK, //0x04
    AT_ACK_SHUT_OK,
    AT_ACK_IP_ADDR,
    AT_ACK_CONNECT_OK,
    AT_ACK_STATE_CONNECT_OK, //0x08
    AT_ACK_GPRS_SEND_ENABLE,
    AT_ACK_GPRS_SEND_OK,
    AT_ACK_SMS_SEND_ENABLE, //0x0b
    AT_ACK_DEFAULT = 99,
};

enum at_index_enum
{
    /* GSM POWER */
    GSM_POWER_OFF, //0x0
    GSM_POWER_ON,
    GSM_PWRKEY_H_1,
    GSM_PWRKEY_L,
    GSM_PWRKEY_H_2,
    GSM_DTR_WAKEUP, //0x05
    
    /* GSM AT */
    GSM_AT, //0x06
    GSM_ATE0,
    GSM_AT_IPR,
    GSM_AT_W,
    GSM_ATS0, //0x0a 
    GSM_AT_CMGF,  
#ifdef SMS_TEXT //------------------- 若该宏使能，则下面编号在原有编号基础上 + 1
    GSM_AT_CSCS,
#endif
    GSM_AT_CNMI,
    GSM_AT_CSCA,
    GSM_AT_CIPHEAD, //0x0e
    GSM_AT_CSCLK,
    GSM_AT_CLIP, 
    GSM_AT_CGREG,
    GSM_AT_CGDCONT, //0x12
    GSM_AT_CIPMUX,
    GSM_AT_CIPMODE,
    GSM_AT_CSQ,   
    GSM_INIT_OVER, //0x16
    
    /* GPRS INIT AT */
    GPRS_AT_CIPSHUT, //0x17
    GPRS_AT_CSTT,
    GPRS_AT_CIICR,
    GPRS_AT_CIFSR,
    GPRS_AT_CIPSTART,
    GPRS_LINK_OVER, //0x1c
    
    /* GPRS SEND DATA */
    GPRS_AT_CIPSTATUS, //0x1D
    GPRS_AT_CIPSEND,
    GPRS_SEND_DATA,
    GPRS_SEND_OVER,
    
    /* SMS SEND DATA */
    SMS_AT_CMGS, //0x21
    SMS_SEND_DATA,
    SMS_SEND_OVER,
};

struct at_list_struct
{
    uint8_t at_buf[32];
    uint16_t last_at_exec_timeout;
    uint8_t last_at_ack;
};

struct gsm_send_packet_struct
{
    uint8_t buf[GSM_SEND_PACKET_BUF_LEN];
    uint16_t len;
    uint8_t send_times;
    uint8_t type;
    uint8_t ctrl_flag;
};

struct gsm_ring_buf_struct
{
    uint16_t front_read;
    uint16_t tail_write;
    struct gsm_send_packet_struct gsm_send_packet[GSM_SEND_PACKET_BUF_NUM];
};

struct gsm_ctrl_struct
{
    uint8_t ring_times;
    uint8_t gsm_init_status;
    uint8_t gprs_link_status;
    uint8_t gprs_link_failed_times;
    uint8_t gprs_link_failed_loops;
    uint8_t gprs_at_failed_times[MAX_AT_NUM];
    uint8_t gsm_power_off_times;
    uint8_t send_commu_method;

    uint8_t gprs_send_enable_failed_times;
    uint8_t gprs_send_enable_failed_loops;
    uint8_t gprs_send_data_failed_times;
    uint8_t gprs_send_data_failed_loops;
    uint8_t sms_send_enable_failed_times;
    uint8_t sms_send_enable_failed_loops;
    uint8_t sms_send_data_failed_times;
    uint8_t sms_send_data_failed_loops;
    
    uint8_t last_at_ack;
    uint8_t at_index;
    uint16_t at_exec_timeout;
    uint16_t at_failed_times[MAX_AT_NUM];
};

struct server_ip_and_port_struct
{
    uint8_t server_ip[16]; //ip的字符串格式，最多字符串"xxx.xxx.xxx.xxx"
    uint8_t server_port[6]; //端口的字符串格式，最多字符串"xxxxx"
};

void test_at(void);
void send_test_data(void);
void init_app_gsm(void);
void main_gsm(void);
void print_gsm(void);
uint8_t push_gsm_ring_buf(struct gsm_ring_buf_struct *gsm_ring_buf, struct gsm_send_packet_struct *gsm_send_packet);
void tx_gsm_string(uint8_t *buf, uint16_t len);
void get_server_ip_and_port(struct server_ip_and_port_struct * ptr_server_ip_and_port);
void exec_gsm_at(uint8_t *at_cmd, uint8_t at_cmd_len, uint16_t last_at_exec_timeout, uint8_t last_at_ack);

#endif

