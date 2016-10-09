#if (APP_GSM == TRUE)

#include "stm32f4xx.h" 
#include "stdlib.h"
#include "string.h"
#include "common.h"
#include "gsm.h"
#include "app_gsm.h"
#include "app_protocol.h"
#include "app_new_protocol.h"
/*modify for test*/
/* extern */
extern uint16_t g_commu_packet_seq;
extern struct gsm_usart_buf_struct g_gsm_usart_buf;
extern struct lq_info_struct g_measure_lq_info;
#ifndef NEW_PROTOCOL
extern struct local_para_struct g_local_para;
extern struct report_value_struct g_report_value;
#else
extern struct set_para_struct g_set_para;
extern struct network_manage_para_struct g_network_manage_para;
extern struct sample_value_struct g_sample_value;
#endif

extern void reboot_rtu(uint16_t reboot_reason);

/* 自定义变量 */
struct gsm_ctrl_struct g_gsm_ctrl;
struct gsm_ring_buf_struct g_gsm_ring_buf;
struct gsm_send_packet_struct g_gsm_shared_buf;
struct at_list_struct g_at_list[] =
{
    {"AT\r",                                             SECOND_0,   AT_ACK_DEFAULT}, //AT指令
    {"ATE0\r",                                         SECOND_3,   AT_ACK_OK}, //0:关闭回显,1:打开回显
    { "AT+IPR=0\r",                                 SECOND_3,   AT_ACK_OK}, //设置波特率为自动适配模式
    {"AT&W\r",                                        SECOND_3,   AT_ACK_OK}, //保存设置
    {"ATS0=0\r",                                     SECOND_3,   AT_ACK_OK}, //0=禁止，1~255次振铃后自动接听
#ifdef SMS_TEXT
    { "AT+CMGF=1\r",                              SECOND_3,   AT_ACK_OK}, //选择短信息格式为PDU格式(0:PDU，1:文本)
    {"AT+CSCS=\"GSM\"\r",                      SECOND_3,   AT_ACK_OK}, //选择文本方式的GSM方式
#else
    {"AT+CMGF=0\r",                               SECOND_3,   AT_ACK_OK}, //选择短信息格式为PDU格式(0:PDU，1:文本)
#endif
    {"AT+CNMI=2,1,0,0,0\r",                     SECOND_3,  AT_ACK_OK}, //设置新消息指示方式，这里是短信存SIM卡
    {"AT+CSCA?\r",                                  SECOND_10, AT_ACK_OK}, //查询SMS短信服务中心号码
    {"AT+CIPHEAD=1\r",                           SECOND_3,  AT_ACK_CSCA}, //0=无IP头；1=格式 格式: +IPD,data length:
    {"AT+CSCLK=1\r",                              SECOND_3,  AT_ACK_OK}, //为1表示使能休眠模式，DTR拉高时进入休眠模式，DTR拉低时退出休眠模式
    {"AT+CLIP=1\r",                                 SECOND_3,  AT_ACK_OK}, //指示来电号码，为1则显示
    {"AT+CGREG=1\r",                             SECOND_3,  AT_ACK_OK}, //为1表示启动网络注册状态非请求结果码: +CGREG:<stat>
    {"AT+CGDCONT=1,\"IP\",\"CMNET\"\r", SECOND_3,  AT_ACK_OK}, //0=无IP头；1=格式 格式: +IPD,data length:
    {"AT+CIPMUX=0\r",                             SECOND_3,  AT_ACK_OK}, //0表示单连接
    {"AT+CIPMODE=0\r",                          SECOND_3,  AT_ACK_OK}, //0表示非透明传输
    {"AT+CSQ\r",                                     SECOND_3,  AT_ACK_OK}, //查询场强
    {"",                                                    SECOND_3,  AT_ACK_CSQ}, //gsm at指令结束
};

void init_gsm_at(void)
{   
    uint8_t at_list_index;
    
    switch (g_gsm_ctrl.at_index)
    {
        case GSM_POWER_OFF:
            MODEM_POWER_OFF;
            MODEM_PWRKEY_H; //把powerkey管脚拉高
            g_gsm_ctrl.at_exec_timeout = SECOND_0;
            g_gsm_ctrl.at_index++;
            break;
        case GSM_POWER_ON:
            if (g_gsm_ctrl.at_exec_timeout > SECOND_2)
            {
                MODEM_POWER_ON;
                g_gsm_ctrl.at_exec_timeout = SECOND_0;
                g_gsm_ctrl.at_index++;
            }
            break;
        case GSM_PWRKEY_H_1:
            if (g_gsm_ctrl.at_exec_timeout > SECOND_2)
            {
                MODEM_PWRKEY_H; 
                g_gsm_ctrl.at_exec_timeout = SECOND_0;
                g_gsm_ctrl.at_index++;
            }
            break;
        case GSM_PWRKEY_L:
            if (g_gsm_ctrl.at_exec_timeout > SECOND_2)
            {
                MODEM_PWRKEY_L;
                g_gsm_ctrl.at_exec_timeout = SECOND_0;
                g_gsm_ctrl.at_index++;
            }
            break;
        case GSM_PWRKEY_H_2:  
            if (g_gsm_ctrl.at_exec_timeout > SECOND_2)
            {
                MODEM_PWRKEY_H; 
                g_gsm_ctrl.at_exec_timeout = SECOND_0;
                g_gsm_ctrl.at_index++;
            }
            break;
        case GSM_DTR_WAKEUP:
            if (g_gsm_ctrl.at_exec_timeout > SECOND_2)
            {
                MODEM_DTR_WAKEUP;
                g_gsm_ctrl.at_exec_timeout = SECOND_0;
                g_gsm_ctrl.at_index++;
            }
            break;

        case GSM_AT:
        case GSM_ATE0:
        case GSM_AT_IPR:
        case GSM_AT_W:
        case GSM_ATS0:           
        case GSM_AT_CMGF:
#ifdef SMS_TEXT
        case GSM_AT_CSCS:
#endif        
        case GSM_AT_CNMI:
        case GSM_AT_CSCA:
        case GSM_AT_CIPHEAD:
        case GSM_AT_CSCLK:
        case GSM_AT_CLIP:
        case GSM_AT_CGREG:
        case GSM_AT_CGDCONT:
        case GSM_AT_CIPMUX:
        case GSM_AT_CIPMODE:
        case GSM_AT_CSQ:
        case GSM_INIT_OVER:
            at_list_index = g_gsm_ctrl.at_index - GSM_AT;
            exec_gsm_at(g_at_list[at_list_index].at_buf, strlen((const char *)g_at_list[at_list_index].at_buf), 
                                  g_at_list[at_list_index].last_at_exec_timeout, g_at_list[at_list_index].last_at_ack); 
            break;     
        default:
            break;
    }
}

void init_gsm_ring_buf(struct gsm_ring_buf_struct *gsm_ring_buf)
{
    gsm_ring_buf->front_read = 0;
    gsm_ring_buf->tail_write = 0;
}

void init_app_gsm(void)
{
    g_gsm_ctrl.at_index = GSM_POWER_OFF;
    g_gsm_ctrl.at_exec_timeout = SECOND_0;
    g_gsm_ctrl.last_at_ack = AT_ACK_DEFAULT;
    g_gsm_ctrl.send_commu_method = BY_GPRS;
    
    init_gsm_ring_buf(&g_gsm_ring_buf);
}

uint8_t is_gsm_ring_buf_empty(struct gsm_ring_buf_struct *gsm_ring_buf)
{
    if (gsm_ring_buf->front_read == gsm_ring_buf->tail_write)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

uint8_t is_gsm_ring_buf_full(struct gsm_ring_buf_struct *gsm_ring_buf)
{
    if ( ( (gsm_ring_buf->tail_write + 1) % GSM_SEND_PACKET_BUF_NUM) == gsm_ring_buf->front_read )
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

uint8_t push_gsm_ring_buf(struct gsm_ring_buf_struct *gsm_ring_buf, struct gsm_send_packet_struct *gsm_send_packet)
{
    if (is_gsm_ring_buf_full(gsm_ring_buf))
    {
        return ERROR;
    }

    memcpy(gsm_ring_buf->gsm_send_packet[gsm_ring_buf->tail_write].buf, 
                 gsm_send_packet->buf, 
                 gsm_send_packet->len);
    
    gsm_ring_buf->gsm_send_packet[gsm_ring_buf->tail_write].len = gsm_send_packet->len;
    gsm_ring_buf->gsm_send_packet[gsm_ring_buf->tail_write].send_times = gsm_send_packet->send_times;
    gsm_ring_buf->gsm_send_packet[gsm_ring_buf->tail_write].type = gsm_send_packet->type;
    gsm_ring_buf->gsm_send_packet[gsm_ring_buf->tail_write].ctrl_flag = gsm_send_packet->ctrl_flag;

    gsm_ring_buf->tail_write = (gsm_ring_buf->tail_write + 1) % GSM_SEND_PACKET_BUF_NUM;

    return SUCCESS;
}

uint8_t pop_gsm_ring_buf(struct gsm_ring_buf_struct *gsm_ring_buf, struct gsm_send_packet_struct *gsm_send_packet)
{
    if (is_gsm_ring_buf_empty(gsm_ring_buf))
    {
        return ERROR;
    }

    memcpy(gsm_send_packet->buf, 
                 gsm_ring_buf->gsm_send_packet[gsm_ring_buf->front_read].buf, 
                 gsm_ring_buf->gsm_send_packet[gsm_ring_buf->front_read].len);

    gsm_send_packet->len= gsm_ring_buf->gsm_send_packet[gsm_ring_buf->front_read].len;      
    gsm_send_packet->send_times= gsm_ring_buf->gsm_send_packet[gsm_ring_buf->front_read].send_times;   
    gsm_send_packet->type =  gsm_ring_buf->gsm_send_packet[gsm_ring_buf->front_read].type;   
    gsm_send_packet->ctrl_flag =  gsm_ring_buf->gsm_send_packet[gsm_ring_buf->front_read].ctrl_flag;   

    gsm_ring_buf->front_read = (gsm_ring_buf->front_read + 1) % GSM_SEND_PACKET_BUF_NUM;

    return SUCCESS;
}

void clean_gsm_usart_buf(void)
{
    g_gsm_usart_buf.rx_len = 0;
    memset(g_gsm_usart_buf.rx_buf, 0x0, sizeof(g_gsm_usart_buf.rx_buf));
}

void tx_gsm_string(uint8_t *buf, uint16_t len)
{   
    if (buf)
    {
        MODEM_DTR_WAKEUP;
        clean_gsm_usart_buf(); //发送之前先清GSM串口缓存
        USART_SendData(MODEM_USART_PORT, len, buf); 
    }
}

uint8_t tx_gsm_string_reply(uint8_t *tx_cmd, uint8_t *cmd_reply, uint16_t delay_seconds)
{
    uint32_t last_tick;
   
    tx_gsm_string(tx_cmd, strlen((const char *)tx_cmd));
    
    last_tick = get_current_tick();
   
    while (get_current_tick() < (last_tick + delay_seconds))
    {
        if (g_gsm_usart_buf.rx_time > MSECOND_20)
        {
            if (find_string(g_gsm_usart_buf.rx_buf, cmd_reply) != NULL)
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

/* 注意这里switch都没有break，说明是从高位到低位逐步检测的 */
void get_server_ip_and_port(struct server_ip_and_port_struct * ptr_server_ip_and_port)
{
    uint8_t i;
    uint8_t j = 0;
    uint8_t k = 0;
    uint16_t ip;
    uint16_t port;
    uint8_t *server_ip = ptr_server_ip_and_port->server_ip;
    uint8_t *server_port = ptr_server_ip_and_port->server_port;
        
    for (i = 0; i < 4; ++i) //处理ip地址
    {
#ifndef NEW_PROTOCOL
        ip = g_local_para.ip_port_apn[i];
#else
        ip = g_network_manage_para.server_ip_addr[i];
#endif

        switch (ip > 99) //处理百位
        {
            case 1: //有百位先处理百位，再检测下面的十位
                {
                    server_ip[j++] = (ip / 100 + '0'); //取百位
                }
            case 0: //无百位则检测十位
               {
                    switch (ip > 9) //处理十位
                    {
                        case 1: //有十位先处理十位，再处理下面的个位
                            {
                                server_ip[j++] = ((ip % 100) / 10) + '0'; //取十位
                            }
                        case 0: //无十位直接处理个位
                            {
                                server_ip[j++] = ((ip % 10) / 1) + '0';
                            }
                    }
               }

               if (i < 3)
               {
                    server_ip[j++] = '.';
               }
        }
    }
    
#ifndef NEW_PROTOCOL
    port = byte_array_to_uint16(&g_local_para.ip_port_apn[4]);
#else   
    port = byte_array_to_uint16(g_network_manage_para.server_port);
#endif

    switch (port > 9999) //处理万位
    {
        case 1:
            server_port[k++] = (port / 10000 + '0'); //取万位
        case 0:
            switch (port > 999) //处理千位
            {
                case 1:
                    server_port[k++] = ((port % 10000) / 1000) + '0'; //取千位
                case 0:
                    {
                        switch (port > 99) //处理百位
                        {
                            case 1:
                                server_port[k++] = ((port % 1000) / 100) + '0'; //取百位
                            case 0:
                                switch (port > 9) //处理十位
                                {
                                    case 1:
                                        server_port[k++] = ((port % 100) / 10) + '0'; //取十位
                                    case 0:
                                        server_port[k++] = ((port % 10) / 1) + '0'; //取个位
                                }
                        }
                    }
            }
    }
}

/**
  * +IPD,85: 
  * 其中comma表示逗号','，colon表示冒号':'.
  */
void parse_rx_gprs_packet(uint8_t *rx_buf, uint16_t rx_len)
{ 
    uint16_t i;
    uint8_t payload_len;
    uint16_t comma_index = 0;
    uint16_t colon_index = 0;
    uint8_t *payload;
    uint8_t payload_len_buf[16];

    //MY_PRINT(GSM_PRINT, "\t[%s] GPRS接收串口长度:%d,接收串口内容:", __FUNCTION__, rx_len);
    //print_buf(rx_buf, rx_len, HEX_FLAG);

    for (i = 0; i < rx_len; ++i)
    {
        if (rx_buf[i] == ',')
        {
            comma_index = i;
            break;
        }
    }

    for (i = 0; i < rx_len; ++i)
    {
        if (rx_buf[i] == ':')
        {
            colon_index = i;
            break;
        }
    }

    if ( (comma_index == 0) || (colon_index == 0) || (comma_index >= colon_index) ) //需要进行数据合理性校验处理
    {
        MY_PRINT(GSM_PRINT, "\t[%s] 读取的GPRS内容非法,comma_index = %d, colon_index = %d\r\n", __FUNCTION__, comma_index, colon_index);
        return;
    }
    
    memcpy(payload_len_buf, &(rx_buf[comma_index + 1]), (colon_index - comma_index + 1 - 2));
    payload_len = atoi((char const*)payload_len_buf);  
    payload = (rx_buf + colon_index + 1);
    
    MY_PRINT(GSM_PRINT, "\t[%s] GPRS接收净荷长度:%d,内容:", __FUNCTION__, payload_len);
    print_buf(payload, payload_len, HEX_FLAG);

#ifndef NEW_PROTOCOL    
    parse_protocol(payload, payload_len);
#else
    parse_new_protocol(GPRS_METHOD, payload, payload_len);
#endif
}

#ifdef SMS_TEXT
/**
  * 短信要求:
  * 1、发送数据包之前，先生成CRC校验值，再采用“ASCII码拆分处理”；
  * 2、在接收到数据包后，先进行“ASCII码拆分处理”的反向处理，再进行CRC校验。
  */
void parse_text_sms_packet(uint8_t *rx_buf, uint16_t rx_len)
{
    uint16_t i;
    uint16_t sms_start_flag = 0;
    uint16_t sms_end_flag = 0;
    uint16_t sms_len;
    uint8_t payload[180] = {0};
    
    MY_PRINT(GSM_PRINT, "\t[%s] SMS接收串口长度:%d,接收串口内容:", __FUNCTION__, rx_len);
    print_buf(rx_buf, rx_len, HEX_FLAG);

#ifdef NEW_PROTOCOL
    parse_sms_num(rx_buf, rx_len, g_network_manage_para.recent_user_sms_num);
#endif
   
    for (i = 0; i < (rx_len - 1); ++i)
    {
        if (rx_buf[i] == SMS_START_FLAG) //SMS报文新协议的起始标志
        {
            sms_start_flag = i;
            break;
        }
    }

    for (i = (rx_len - 1); i > 0; --i)
    {
        if (rx_buf[i] == SMS_END_FLAG) //SMS报文新协议的结束标志
        {
            sms_end_flag = i;
            break;
        }
    }

    if ( (sms_start_flag == 0) || (sms_end_flag == 0) || (sms_start_flag >= sms_end_flag) ) //需要进行数据合理性校验处理
    {
        MY_PRINT(GSM_PRINT, "\t[%s] 读取的SMS内容非法,sms_start_flag = %d, sms_end_flag = %d\r\n", __FUNCTION__, sms_start_flag, sms_end_flag);
        return;
    }

    sms_len = (sms_end_flag - sms_start_flag + 1);
    ascii_to_hex(&rx_buf[sms_start_flag + 1], &payload[1], sms_len);
    payload[0] = START_FLAG;
    payload[sms_len / 2 + 1] = END_FLAG;

    parse_new_protocol(SMS_METHOD, payload, sms_len / 2 + 2);
}

#else

void parse_pdu_sms_packet_1(uint8_t *rx_buf, uint16_t rx_len)
{
    uint16_t i;
    uint16_t protocol_sms_header= 0;
    uint16_t protocol_sms_tailer = 0;
    uint16_t protocol_sms_len = 0;
    uint8_t payload[180] = {0};
    uint8_t payload_len = 0;

    MY_PRINT(GSM_PRINT, "\t[%s] SMS接收串口长度:%d,接收串口内容:", __FUNCTION__, rx_len);
    print_buf(rx_buf, rx_len, HEX_FLAG);
    
    for (i = 0; i < (rx_len - 1); ++i)
    {
#ifndef NEW_PROTOCOL
        if ((rx_buf[i] == '2') && (rx_buf[i + 1] == '4') ) //$
#else
        if ((rx_buf[i] == '2') && (rx_buf[i + 1] == '1') ) //!
#endif
        {
            protocol_sms_header = i;
            break;
        }
    }

    for (i = (rx_len - 1); i > 0; --i)
    {
#ifndef NEW_PROTOCOL
        if ((rx_buf[i] == '4') && (rx_buf[i - 1] == '2') ) //$
#else
        if ((rx_buf[i] == '1') && (rx_buf[i + 1] == '2') ) //!
#endif
        {
            protocol_sms_tailer = i;
            break;
        }
    }

    if ( (protocol_sms_header == 0) 
        || (protocol_sms_tailer == 0) 
        || ((protocol_sms_tailer - protocol_sms_header) <= 1) )  //需要进行数据合理性校验处理
    {
        MY_PRINT(GSM_PRINT, "\t[%s] 读取的短信内容非法,protocol_sms_header:%d,protocol_sms_tailer:%d\r\n", 
                                            __FUNCTION__, protocol_sms_header, protocol_sms_header);
        return;
    }

    protocol_sms_len = protocol_sms_tailer - protocol_sms_header + 1;   
    MY_PRINT(GSM_PRINT, "\t[%s] 协议短信头:%d,短信尾:%d,短信长度:%d\r\n", 
                                        __FUNCTION__, protocol_sms_header, protocol_sms_tailer, protocol_sms_len);

    ascii_to_hex(rx_buf + protocol_sms_header, payload, protocol_sms_len);
    payload_len = protocol_sms_len / 2;
    
    MY_PRINT(GSM_PRINT, "\t[%s] 协议长度:%d,协议内容:", __FUNCTION__, payload_len);
    print_buf(payload, payload_len, HEX_FLAG);

#ifndef NEW_PROTOCOL    
        parse_protocol(payload, payload_len);
#else
        parse_new_protocol(SMS_METHOD, payload, payload_len);
#endif
}

/**
  *   \r\n+CMGR: 0,"",134\r\n<pdu>\r\n OK
  *   CR:0x0D, LF: 0x0A(LF_CHAR)
  *
  *   second_LF
  *   |____________________________________________
  *   |sms header     |sms payload                 |
  *   |_______________|____________________________|
  *
  *                   |   payload  |                  
  *
  * 
  */
void parse_pdu_sms_packet(uint8_t *rx_buf, uint16_t rx_len)
{
    uint16_t i;
    uint16_t first_LF = 0; //第一个换行
    uint16_t second_LF = 0; //第二个换行
    uint8_t *sms;
    uint16_t sms_len;
    uint8_t *sms_payload;
    uint16_t sms_payload_len;
    uint16_t payload_len;
    uint8_t payload[180] = {0};

    MY_PRINT(GSM_PRINT, "\r\n\t[%s] SMS接收串口长度:%d,接收串口内容:", __FUNCTION__, rx_len);
    print_buf(rx_buf, rx_len, CHAR_FLAG);

    /* 查找第一个',' */
    for (i = 0; i < rx_len; ++i)
    {
        if (rx_buf[i] == ',') //0x27
        {
            break;
        }
    }
    
    /* 查找第二个',' */
    for (i = i + 1; i < rx_len; ++i) 
    {
        if (rx_buf[i] == ',') //0x27
        {
            break;
        }
    }
    
    /* 查找第一个换行符'\n'(0x0a) */
    for (i = i + 1; i < rx_len; ++i)
    {
        if (rx_buf[i] == LF_CHAR)
        {
            first_LF = i;
            break;
        }
    }
    
    /* 查找第二个换行符'\n'(0x0a) */
    for (i = (first_LF + 1); i < rx_len; ++i)
    {
        if (rx_buf[i] == LF_CHAR)
        {
            second_LF = i;
            break;
        }
    }

    if ( ((second_LF - first_LF) <= 1) || (first_LF == 0) || (second_LF == 0) )  //需要进行数据合理性校验处理
    {
        MY_PRINT(GSM_PRINT, "\r\n\t[%s] 读取的短信内容非法,first_LF:%d,second_LF:%d\r\n", 
                                            __FUNCTION__, first_LF, second_LF);
        return;
    }
    
    sms = rx_buf + first_LF + 1;
    sms_len = (second_LF - first_LF + 1) - 3;

    MY_PRINT(GSM_PRINT, "\r\n\t[%s] first_LF:%d,second_LF:%d,sms_len:%d\r\n", 
                                        __FUNCTION__, first_LF, second_LF, sms_len);
    
    sms_payload = sms + PDU_SMS_HEADER;
    sms_payload_len = sms_len - PDU_SMS_HEADER;

    MY_PRINT(GSM_PRINT, "\t[%s] 短信净荷长度:%d,净荷内容:", __FUNCTION__, sms_payload_len);
    print_buf(sms_payload, sms_payload_len, CHAR_FLAG);

    ascii_to_hex(sms_payload, payload, sms_payload_len);
    payload_len = sms_payload_len / 2;

    MY_PRINT(GSM_PRINT, "\r\n\t[%s] 读取的协议长度:%d,协议内容:", __FUNCTION__, payload_len);
    print_buf(payload, payload_len, HEX_FLAG);
    
#ifndef NEW_PROTOCOL    
    parse_protocol(payload, payload_len);
#else
    parse_new_protocol(SMS_METHOD, payload, payload_len);
#endif
}
#endif

void delete_sms(uint8_t sms_index)
{
    uint8_t at_cmgd_buf[32];

    memset(at_cmgd_buf, 0, sizeof(at_cmgd_buf));
    sprintf((char *)at_cmgd_buf, "AT+CMGD=%d\r", sms_index);
    
    MY_PRINT(GSM_PRINT, "\r\n\t[%s] 开始删除短信编号为%d的短信...\r\n", __FUNCTION__, sms_index);
    
    if (tx_gsm_string_reply(at_cmgd_buf, "OK", SECOND_5) == TRUE)
    {
        MY_PRINT(GSM_PRINT, "\t[%s] 删除短信编号为%d的短信成功!\r\n", __FUNCTION__, sms_index);
    }
    else
    {
        MY_PRINT(GSM_PRINT, "\t[%s] 删除短信编号为%d的短信失败!\r\n", __FUNCTION__, sms_index);
    }
}

void read_sms(uint8_t sms_index)
{
    uint8_t at_cmgr_buf[32];

    memset(at_cmgr_buf, 0, sizeof(at_cmgr_buf));
    sprintf((char *)at_cmgr_buf, "AT+CMGR=%d\r", sms_index);
   
    MY_PRINT(GSM_PRINT, "\t[%s] 开始读取短信编号为%d的短信......\r\n", __FUNCTION__, sms_index);
    
    if (tx_gsm_string_reply(at_cmgr_buf, "OK", SECOND_5) == TRUE)
    {
        MY_PRINT(GSM_PRINT, "\t[%s] 读取短信编号为%d的短信成功!\r\n", __FUNCTION__, sms_index);
#ifdef SMS_TEXT
        parse_text_sms_packet(g_gsm_usart_buf.rx_buf, g_gsm_usart_buf.rx_len);
#else
        parse_pdu_sms_packet(g_gsm_usart_buf.rx_buf, g_gsm_usart_buf.rx_len);
#endif
        delete_sms(sms_index);
    }
    else
    {
        MY_PRINT(GSM_PRINT, "\t[%s] 读取短信编号为%d的短信失败!\r\n", __FUNCTION__, sms_index);
    }
}

/**
  * +CMTI: "MT",1\r\n
  */
void parse_rx_sms_index(uint8_t *rx_buf, uint16_t rx_len)
{
    uint8_t sms_index;
    uint8_t sms_index_buf[8];
    uint16_t i;
    uint16_t comma_index; //逗号,
    uint16_t CR_index; //回车\r

    for (i = 0; i < rx_len; ++i)
    {
        if (rx_buf[i] == ',')
        {
            comma_index = i;
            break;
        }
    }

    for (i = comma_index + 1; i < rx_len; ++i)
    {
        if (rx_buf[i] == '\r') //CR_CHAR
        {
            CR_index = i;
        }
    }

    memcpy(sms_index_buf, &(rx_buf[comma_index + 1]), (CR_index - comma_index + 1 - 2));
    sms_index = atoi((char const*)sms_index_buf);
    MY_PRINT(GSM_PRINT, "\t[%s] sms_no = %d\r\n", __FUNCTION__, sms_index);

    read_sms(sms_index); //读取短信
}

void deal_with_gsm_usart_rx(void)
{
    uint8_t rx_buf[MAX_GSM_RX_BUF_LEN] = {0};
    uint8_t rx_len;

    /* 缓冲区有数据的话，则进行串口缓存读取 */
    if ( (g_gsm_usart_buf.rx_len > 0) && (g_gsm_usart_buf.rx_time > MSECOND_20) )
    {
        rx_len = g_gsm_usart_buf.rx_len;
        memcpy(rx_buf, g_gsm_usart_buf.rx_buf, rx_len);
        clean_gsm_usart_buf();
        
        if (find_string(rx_buf, "OK") != NULL)
        {
            g_gsm_ctrl.last_at_ack = AT_ACK_OK;
        }

        if (find_string(rx_buf, "CLOSE OK") != NULL) //AT+CIPCLOSE
        {
            g_gsm_ctrl.last_at_ack = AT_ACK_CLOSE_OK;
        }
        
        if (find_string(rx_buf, "SHUT OK") != NULL) //AT+CIPSHUT
        {
            g_gsm_ctrl.last_at_ack = AT_ACK_SHUT_OK;
        }
        
        if (find_string(rx_buf, "CONNECT OK") != NULL) 
        {
            if (find_string(rx_buf, "STATE: CONNECT OK") != NULL) //AT+CIPSTATUS
            {
                g_gsm_ctrl.last_at_ack = AT_ACK_STATE_CONNECT_OK;
            }
            else //AT+CIPSTART
            {
                MY_PRINT(GSM_PRINT, "\r\n\t[%s] GPRS链接成功!\r\n", __FUNCTION__); 
                g_gsm_ctrl.last_at_ack = AT_ACK_CONNECT_OK;
            }
        }
        
        if (find_string(rx_buf, "SEND OK") != NULL)
        {
            MY_PRINT(GSM_PRINT, "\r\n\t[%s] 发送GPRS数据成功!\r\n\r\n", __FUNCTION__); 
            g_gsm_ctrl.last_at_ack = AT_ACK_GPRS_SEND_OK;
        }
        
        if (find_string(rx_buf, ".") != NULL)
        {
            g_gsm_ctrl.last_at_ack = AT_ACK_IP_ADDR;
        }
        
        if (find_string(rx_buf, ">") != NULL)
        {
            if (g_gsm_ctrl.at_index == GPRS_SEND_DATA)
            {
                MY_PRINT(GSM_PRINT, "\r\n\t[%s] 获取GPRS发送使能成功!\r\n", __FUNCTION__); 
                g_gsm_ctrl.last_at_ack = AT_ACK_GPRS_SEND_ENABLE;
            }
            else
            {
                MY_PRINT(GSM_PRINT, "\r\n\t[%s] 获取SMS发送使能成功!\r\n", __FUNCTION__); 
                g_gsm_ctrl.last_at_ack = AT_ACK_SMS_SEND_ENABLE;
            }
        }
        
        if (find_string(rx_buf, "+CSCA:") != NULL) //解析短信中心号码
        {
#ifndef NEW_PROTOCOL
            parse_sms_num(rx_buf, rx_len, &g_local_para.sms_center_num[1]);
#else
            parse_sms_num(rx_buf, rx_len, g_network_manage_para.sms_center_num);
#endif
            g_gsm_ctrl.last_at_ack = AT_ACK_CSCA;
        }
        
        if (find_string(rx_buf, "+CSQ:") != NULL) //解析CSQ
        {
            parse_csq(rx_buf, rx_len);
            g_gsm_ctrl.last_at_ack = AT_ACK_CSQ;
        }
        
        if (find_string(rx_buf, "+PDP: DEACT") != NULL) //收到上位机的GPRS释放信号
        {
            MY_PRINT(GSM_PRINT, "\r\n\r\n\t[%s] 收到上位机释放PDP场景信号!\r\n", __FUNCTION__);
        }
        
        if (find_string(rx_buf, "+IPD,") != NULL) //解析接收到的GPRS报文
        {
            MY_PRINT(GSM_PRINT, "\r\n\r\n\t[%s] 收到GPRS报文!\r\n", __FUNCTION__);
            parse_rx_gprs_packet(rx_buf, rx_len);
        }
               
        /* 格式为\r\n+CMTI: "SM",sms_index\r\n */
        if (find_string(rx_buf, "+CMTI: \"SM\",") != NULL) //收到短信报文
        {
            MY_PRINT(GSM_PRINT, "\r\n\r\n\t[%s] 收到短信报文!\r\n", __FUNCTION__);
            parse_rx_sms_index(rx_buf, rx_len);
        }
        
        if (find_string(rx_buf, "RING") != NULL) //处理响铃事件
        {
            g_gsm_ctrl.ring_times++;
            if (g_gsm_ctrl.ring_times >= 3)
            {			
                g_gsm_ctrl.ring_times = 0;
                MY_PRINT(GSM_PRINT, "\r\n\r\n\t[%s] 三次响铃后挂机!\r\n", __FUNCTION__);
                
                MODEM_DTR_WAKEUP;
                delay_ms(1000);
                tx_gsm_string("ATH\r", 4); 
                delay_ms(3000);
                MY_PRINT(GSM_PRINT, "\r\n\r\n\t[%s] 挂机成功!\r\n", __FUNCTION__);
#ifndef	NEW_PROTOCOL
                send_terminal_status_packet(STATUS_PACKET, NULL, FRAME_ID_COMMON);
#else       
                new_send_active_report(RING_REPORT);         
#endif
            }
        }
    }
}

void exec_last_at_over(void)
{
    g_gsm_ctrl.at_exec_timeout = SECOND_0;
    g_gsm_ctrl.last_at_ack = AT_ACK_DEFAULT;
}

/**
  * 1、at_cmd:本次要执行的指令
  * 2、at_cmd_len:本次要执行指令的长度
  * 3、last_at_exec_timeout:上轮at指令执行的超时时间
  * 4、last_at_ack:上轮at指令的返回结果
  */
void exec_gsm_at(uint8_t *at_cmd, uint8_t at_cmd_len, uint16_t last_at_exec_timeout, uint8_t needed_last_at_ack)
{
    uint8_t last_at_index = g_gsm_ctrl.at_index - 1;
    
    if (g_gsm_ctrl.last_at_ack == needed_last_at_ack) //上次指令执行成功
    {  
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == GSM_INIT_OVER) //指令GSM最后一条AT指令(AT + CSQ)成功
        {
            MY_PRINT(GSM_PRINT, "\r\n\tGSM AT初始化成功!\r\n"); 
            g_gsm_ctrl.at_failed_times[last_at_index] = 0;
            g_gsm_ctrl.gsm_power_off_times = 0;            
            g_gsm_ctrl.gsm_init_status = GSM_INIT_OK;
            g_gsm_ctrl.at_index++;
        }
        else //执行GSM一般指令
        {
            g_gsm_ctrl.at_failed_times[last_at_index] = 0;
            tx_gsm_string(at_cmd, at_cmd_len);
            g_gsm_ctrl.at_index++;
        }
    }
    else if (g_gsm_ctrl.at_exec_timeout > last_at_exec_timeout) //上次指令执行超时
    {
        exec_last_at_over();
        g_gsm_ctrl.at_failed_times[last_at_index]++;
        if (g_gsm_ctrl.at_failed_times[last_at_index] < AT_FAILED_TIMES) //不到AT_FAIL_TIMES次，只需重新从头执行AT指令
        {
            g_gsm_ctrl.at_index = GSM_AT; 
        }
        else //达到AT_FAIL_TIMES次则重启GSM模块
        {
            g_gsm_ctrl.at_failed_times[last_at_index] = 0;
            g_gsm_ctrl.at_index = GSM_POWER_OFF; 
            g_gsm_ctrl.gsm_power_off_times++;
            MY_PRINT(GSM_PRINT, "\r\n\t执行AT序号为0x%x的指令失败次数达到%d次,进行第%d次GSM上下电操作!\r\n", 
                                                last_at_index, AT_FAILED_TIMES, g_gsm_ctrl.gsm_power_off_times);                      
            if (g_gsm_ctrl.gsm_power_off_times >= GSM_POWER_OFF_TIMES) //达到GSM_POWER_OFF_TIMES次就重启RTU
            {
                g_gsm_ctrl.gsm_power_off_times = 0;
                MY_PRINT(GSM_PRINT, "\r\n\r\n\tGSM上下电操作达到%d次,重新启动RTU!\r\n", GSM_POWER_OFF_TIMES);
                reboot_rtu(APP_RESET_GSM);
            }
        }        
    }    
    else //上次指令正在执行过程中
    {
        //exec doing
    }
}

/**
  * 1、at_cmd:本次要执行的指令
  * 2、at_cmd_len:本次要执行指令的长度
  * 3、last_at_exec_timeout:上轮at指令执行的超时时间
  * 4、last_at_ack:上轮at指令的返回结果
  */
void exec_gprs_at(uint8_t *at_cmd, uint16_t at_cmd_len, uint16_t last_at_exec_timeout, uint8_t needed_last_at_ack)
{
    uint8_t last_at_index = g_gsm_ctrl.at_index - 1;

    if (g_gsm_ctrl.last_at_ack == needed_last_at_ack) //上次指令执行成功
    {
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == GPRS_LINK_OVER)  //执行GPRS链接指令成功
        {
            g_gsm_ctrl.gprs_link_failed_times = 0;
            g_gsm_ctrl.gprs_link_failed_loops = 0;
            g_gsm_ctrl.gprs_link_status = GPRS_CONNECTED; 
            g_gsm_ctrl.at_index++;
        }
        else //执行GPRS一般指令(非GPRS链接指令)成功
        {
            g_gsm_ctrl.gprs_at_failed_times[last_at_index] = 0;
            tx_gsm_string(at_cmd, at_cmd_len);
            g_gsm_ctrl.at_index++;
        }        
    }
    else if (g_gsm_ctrl.at_exec_timeout > last_at_exec_timeout) //上次指令执行超时
    {       
        g_gsm_ctrl.gprs_link_status = GPRS_NOT_CONNECTED;       
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == GPRS_LINK_OVER) //执行GPRS链接指令失败
        {
            g_gsm_ctrl.gprs_link_failed_times++;
            if (g_gsm_ctrl.gprs_link_failed_times < GPRS_LINK_FAILED_TIMES) //不到GPRS_LINK_FAILED_TIMES次，则重新从头执行GPRS初始化指令
            {
                MY_PRINT(GSM_PRINT, "\r\n\t执行GPRS链接指令失败次数(%d)小于%d次,从头执行基本GPRS指令!\r\n", 
                                                     g_gsm_ctrl.gprs_link_failed_times, GPRS_LINK_FAILED_TIMES); 
                g_gsm_ctrl.at_index = GPRS_AT_CIPSHUT;
            }
            else //达到GPRS_LINK_FAILED_TIMES次
            {
                g_gsm_ctrl.gprs_link_failed_times = 0;
                g_gsm_ctrl.gprs_link_failed_loops++;
                if (g_gsm_ctrl.gprs_link_failed_loops < GPRS_LINK_FAILED_LOOPS) //不到GPRS_LINK_FAILED_LOOPS轮，则初始化GSM模块的AT指令
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t执行GPRS链接指令失败轮数[%d]小于%d轮,从头执行基本AT指令!\r\n", 
                                                        g_gsm_ctrl.gprs_link_failed_loops, GPRS_LINK_FAILED_TIMES); 
                    g_gsm_ctrl.gsm_init_status = GSM_INIT_NO_OK;
                    g_gsm_ctrl.at_index = GSM_AT; 
                }
                else //达到GPRS_LINK_FAILED_LOOPS轮，则切换发送方式为短信
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t执行GPRS链接指令失败轮数达到%d轮,切换到短信发送!\r\n", 
                                                        GPRS_LINK_FAILED_LOOPS); 
                    g_gsm_ctrl.gprs_link_failed_loops = 0;
                    g_gsm_ctrl.at_index = SMS_AT_CMGS;
                    g_gsm_ctrl.send_commu_method = BY_SMS;
                }
            }
        }
        else //执行GPRS‘一般指令’(非链接指令)失败
        {
            g_gsm_ctrl.gprs_at_failed_times[last_at_index]++;
            if (g_gsm_ctrl.gprs_at_failed_times[last_at_index] < GPRS_AT_FAILED_TIMES) //小于GPRS_AT_FAILED_TIMES次，则重新执行GPRS指令
            {  
                MY_PRINT(GSM_PRINT, "\r\n\t执行GPRS序号为0x%x指令失败次数(%d)小于%d次,从头执行基本GPRS指令!\r\n", 
                                                    last_at_index, g_gsm_ctrl.gprs_at_failed_times[last_at_index], GPRS_AT_FAILED_TIMES); 
                g_gsm_ctrl.at_index = GPRS_AT_CIPSHUT;
            }
            else //达到GPRS_AT_FAILED_TIMES次,则切换发送方式为短信
            {
                MY_PRINT(GSM_PRINT, "\r\n\t执行GPRS序号为0x%x指令失败达到%d次,切换到短信发送!\r\n", 
                                                    last_at_index, GPRS_AT_FAILED_TIMES); 
                g_gsm_ctrl.gprs_at_failed_times[last_at_index] = 0;
                g_gsm_ctrl.at_index = SMS_AT_CMGS;
                g_gsm_ctrl.send_commu_method = BY_SMS;
            }
        }
    }
    else //执行过程中
    {
        //exec doing
    }
}

void exec_gprs_send_data(uint8_t *at_cmd, uint16_t at_cmd_len, uint16_t last_at_exec_timeout, uint8_t needed_last_at_ack)
{
    if (g_gsm_ctrl.last_at_ack == needed_last_at_ack) //上次指令执行成功
    {   
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == GPRS_SEND_OVER) //发送数据成功
        {
            g_gsm_ctrl.gprs_send_data_failed_times = 0;
            g_gsm_ctrl.gprs_send_data_failed_loops = 0;
            g_gsm_ctrl.send_commu_method = BY_GPRS;
            g_gsm_ctrl.at_index = GPRS_AT_CIPSTATUS;
            
            if (g_gsm_shared_buf.send_times > 0)
            {
                g_gsm_shared_buf.send_times--;
            }

            if (g_gsm_shared_buf.send_times == 0)
            {
                g_gsm_shared_buf.ctrl_flag = GSM_SHARED_BUF_DEFAULT_STATUS;
            }
        }
        else if (g_gsm_ctrl.at_index == GPRS_SEND_DATA) //获取到发送数据使能
        {
            g_gsm_ctrl.gprs_send_enable_failed_times = 0;
            g_gsm_ctrl.gprs_send_enable_failed_loops = 0;
            g_gsm_ctrl.at_index++;
            
            MY_PRINT(GSM_PRINT, "\r\n\t[%s] GPRS发送数据长度:%d,内容:", __FUNCTION__, at_cmd_len);
            print_buf(at_cmd, at_cmd_len, HEX_FLAG);
            tx_gsm_string(at_cmd, at_cmd_len);
        }
        else //执行AT+CIPSTATUS，或AT+CIPSEND
        {
            g_gsm_ctrl.at_index++;
            tx_gsm_string(at_cmd, at_cmd_len);
        }
    }
    else if (g_gsm_ctrl.at_exec_timeout > last_at_exec_timeout) //上次指令执行超时且失败
    {
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == GPRS_SEND_OVER) //send data失败
        {
            g_gsm_ctrl.gprs_send_data_failed_times++;
            if (g_gsm_ctrl.gprs_send_data_failed_times < GPRS_SEND_DATA_FAILED_TIMES) //小于GPRS_SEND_DATA_FAILED_TIMES次，则重新发送数据
            {
                MY_PRINT(GSM_PRINT, "\r\n\t发送GPRS数据失败次数(%d)小于%d次,从头执行基本GPRS发送数据指令!\r\n", 
                                                     g_gsm_ctrl.gprs_send_data_failed_times, GPRS_SEND_DATA_FAILED_TIMES); 
                g_gsm_ctrl.at_index = GPRS_AT_CIPSTATUS;
            }
            else //达到GPRS_SEND_DATA_FAILED_TIMES次
            {
                g_gsm_ctrl.gprs_send_data_failed_times = 0;
                g_gsm_ctrl.gprs_send_data_failed_loops++;
                if (g_gsm_ctrl.gprs_send_data_failed_loops < GPRS_SEND_DATA_FAILED_LOOPS) //小于GPRS_SEND_DATA_FAILED_LOOPS轮，则进行GPRS初始化
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t发送GPRS数据失败轮数[%d]小于%d轮,从头执行基本GPRS指令!\r\n", 
                                                        g_gsm_ctrl.gprs_send_data_failed_loops, GPRS_SEND_DATA_FAILED_LOOPS); 
                    g_gsm_ctrl.at_index = GPRS_AT_CIPSHUT;
                }
                else //达到GPRS_SEND_DATA_FAILED_LOOPS轮，则切换发送方式为短信
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t发送GPRS数据失败轮数达到%d轮,切换到短信发送!\r\n", 
                                                        GPRS_SEND_DATA_FAILED_LOOPS); 
                    g_gsm_ctrl.gprs_send_data_failed_loops = 0;
                    g_gsm_ctrl.at_index = SMS_AT_CMGS;
                    g_gsm_ctrl.send_commu_method = BY_SMS;
                }
            }
        }
        else if (g_gsm_ctrl.at_index == GPRS_SEND_DATA) //执行获取>的指令失败
        {
            g_gsm_ctrl.gprs_send_enable_failed_times++;
            if (g_gsm_ctrl.gprs_send_enable_failed_times < GPRS_SEND_ENABLE_FAILED_TIMES) //不到GPRS_SEND_ENABLE_FAILED_TIMES次，则重新执行发送数据流程
            {
                MY_PRINT(GSM_PRINT, "\r\n\t获取GPRS发送使能失败次数(%d)小于%d次,从头执行基本GPRS发送数据指令!\r\n", 
                                                    g_gsm_ctrl.gprs_send_enable_failed_times, GPRS_SEND_ENABLE_FAILED_TIMES); 
                g_gsm_ctrl.at_index = GPRS_AT_CIPSTATUS;
            }
            else //达到GPRS_SEND_ENABLE_FAILED_TIMES次
            {
                g_gsm_ctrl.gprs_send_enable_failed_times = 0;
                g_gsm_ctrl.gprs_send_enable_failed_loops++;
                if (g_gsm_ctrl.gprs_send_enable_failed_loops < GPRS_SEND_ENABLE_FAILED_LOOPS) //小于GPRS_SEND_ENABLE_FAILED_LOOPS轮，则进行GPRS初始化
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t获取GPRS发送使能失败轮数[%d]小于%d轮,从头执行基本GPRS指令!\r\n", 
                                                        g_gsm_ctrl.gprs_send_enable_failed_loops, GPRS_SEND_ENABLE_FAILED_LOOPS); 
                    g_gsm_ctrl.at_index = GPRS_AT_CIPSHUT;
                }
                else //达到GPRS_SEND_ENABLE_FAILED_LOOPS轮，则切换发送方式为短信
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t获取GPRS发送使能失败轮数达到%d轮,切换到短信发送!\r\n", 
                                                        GPRS_SEND_ENABLE_FAILED_LOOPS); 
                    g_gsm_ctrl.gprs_send_enable_failed_loops = 0;
                    g_gsm_ctrl.at_index = SMS_AT_CMGS;
                    g_gsm_ctrl.send_commu_method = BY_SMS;
                }
            }
        }
        else //获取执行AT+CIPSTATUS的指令，获取"connect ok"失败
        {
            MY_PRINT(GSM_PRINT, "\r\n\t发送GPRS数据前检测到GPRS链接断开,从头执行基本GPRS指令!\r\n"); 
            g_gsm_ctrl.at_index = GPRS_AT_CIPSHUT;
        }        
    }   
    else //执行过程中
    {
        //exec doing
    }
}

/** 
  * 用PDU 模式收发短消息可以使用三种编码: 7-bit 编码、8-bit 编码和UCS2 编码。
  * 7-bit编码用于发送普通的ASCII 字符；8-bit 编码通常用于发送数据消息,如图片或铃声等；
  * UCS2编码用于发送Unicode 字符。
  * 参考http://blog.csdn.net/linux_xiaomugua/article/details/7085374
  */  
void send_pdu_sms(uint8_t *buf, uint16_t len)
{
    uint8_t tmp;
    uint8_t *ptr_tmp;
    uint8_t sms_number_len = SMS_NUMBER_LEN;
    uint16_t i;
    uint16_t index = 0;  
    uint8_t tmp_buf[500] = {0}; 
    uint8_t ascii_buf[MAX_SMS_SEND_CHAR];
   
    MY_PRINT(GSM_PRINT, "\r\n\t[%s] 短消息净荷长度:%d,内容:", __FUNCTION__, len);
    print_buf(buf, len, HEX_FLAG);

    if (len >= MAX_SMS_SEND_LEN)
    {
        MY_PRINT(GSM_PRINT, "\r\n\t[%s]短消息净荷长度超过%u字符,退出短消息发送!\r\n", __FUNCTION__, MAX_SMS_SEND_LEN);
        return;
    }
    
    if (sms_number_len % 2)
    {
#ifndef NEW_PROTOCOL 
        g_local_para.sms_center_num[sms_number_len + 1] = 'F';
#else
        g_network_manage_para.sms_center_num[sms_number_len] = 'F';
#endif
    }

     /* 9168 */
    memcpy(tmp_buf, "089168", 6);
    index += 6;
    
    /* 短信中心号码 */
    for (i = 0; i < 6; ++i)
    {
#ifndef NEW_PROTOCOL 
        tmp_buf[index++] = (g_local_para.sms_center_num[2 + i * 2]);
        tmp_buf[index++] = (g_local_para.sms_center_num[1 + i * 2]);
#else
        tmp_buf[index++] = (g_network_manage_para.sms_center_num[1 + i * 2]);
        tmp_buf[index++] = (g_network_manage_para.sms_center_num[0 + i * 2]);   
#endif
    }

    /* 1100 */ 
    memcpy(&tmp_buf[index], "1100", 4);
    index += 4;
   
   /* 0D9168 */ 
    memcpy(&tmp_buf[index], "0D9168", 6);
    index += 6;

    /* 目的手机号码 */
    if (sms_number_len % 2)
    {
#ifndef NEW_PROTOCOL
        g_local_para.sms_server_num[sms_number_len + 1] = 'F';
#else
        g_network_manage_para.sms_server_num[sms_number_len] = 'F';
#endif
    }

    for (i = 0; i < 6; ++i)
    {
#ifndef NEW_PROTOCOL
        tmp_buf[index++] = (g_local_para.sms_server_num[2 + i * 2]);
        tmp_buf[index++] = (g_local_para.sms_server_num[1 + i * 2]);
#else
        tmp_buf[index++] = (g_network_manage_para.sms_server_num[1 + i * 2]);
        tmp_buf[index++] = (g_network_manage_para.sms_server_num[0 + i * 2]);        
#endif
    }
    
    /* 使用8-bit编码，对于中文，编码方式为UCS-2,下面需填000800 */
    memcpy(&tmp_buf[index], "000400", 6);        
    index += 6;
    
    /* 短信净荷长度 */
    if ((len / 16) < 10)
    {
        tmp_buf[index++] = (len / 16) + '0'; //数字
    }
    else
    {
        tmp_buf[index++] = (len / 16) - 10 + 65; //字母
    }

    if ((len % 16) < 10)
    {
        tmp_buf[index++] = (len % 16) + '0'; //数字
    }
    else
    {
        tmp_buf[index++] = (len % 16) - 10 + 65; //字母
    }
    
    /* 短信净荷 */
    hex_to_ascii(buf, ascii_buf, len);
    memcpy(&tmp_buf[index], ascii_buf, 2 * len);
    index += 2 * len;

    MY_PRINT(GSM_PRINT, "\r\n\t[%s] 短消息长度:%d,内容:", __FUNCTION__, len);
    print_buf(tmp_buf, strlen((const char *)tmp_buf), CHAR_FLAG);

    /* 发送短信内容到gsm串口 */
    tx_gsm_string(tmp_buf, strlen((const char *)tmp_buf));
        
   /* 发送结束标志 */		
    ptr_tmp = &tmp; 
    tmp = 0x1a;
    tx_gsm_string(ptr_tmp, 1);
}

void send_text_sms(uint8_t *buf, uint16_t len)
{
    uint8_t tmp;
    uint8_t *ptr_tmp;

    buf[0] = '!';
    buf[len -1] = '!';
    
    MY_PRINT(GSM_PRINT, "\r\n\t[%s] 短消息长度:%d,内容:", __FUNCTION__, len);
    print_buf(buf, len, HEX_FLAG);

    if (len >= MAX_SMS_SEND_LEN)
    {
        MY_PRINT(GSM_PRINT, "\r\n\t[%s] 短消息长度超过%u字符,退出短消息发送\r\n", 
                                            __FUNCTION__, MAX_SMS_SEND_LEN);
        return;
    }
    
    /* 发送短信内容到gsm串口 */
    tx_gsm_string(buf, len);
        
   /* 发送结束标志 */		
    ptr_tmp = &tmp; 
    tmp = 0x1a;
    tx_gsm_string(ptr_tmp, 1);
}

void exec_sms_send_data(uint8_t *at_cmd, uint16_t at_cmd_len, uint16_t last_at_exec_timeout, uint8_t needed_last_at_ack)
{
    if (g_gsm_ctrl.last_at_ack == needed_last_at_ack) //上次指令执行成功
    {    
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == SMS_SEND_OVER) //发送数据成功
        {
            MY_PRINT(GSM_PRINT, "\r\n\t发送SMS数据成功!\r\n"); 
            g_gsm_ctrl.sms_send_data_failed_times = 0;
            g_gsm_ctrl.sms_send_data_failed_loops = 0;
            g_gsm_ctrl.at_index = GPRS_AT_CIPSTATUS;
            g_gsm_ctrl.send_commu_method = BY_GPRS;
            
            if (g_gsm_shared_buf.send_times > 0)
            {
                g_gsm_shared_buf.send_times--;
            }

            if (g_gsm_shared_buf.send_times == 0)
            {
                g_gsm_shared_buf.ctrl_flag = GSM_SHARED_BUF_DEFAULT_STATUS;
            }
        }
        else if (g_gsm_ctrl.at_index == SMS_SEND_DATA)
        {
            MY_PRINT(GSM_PRINT, "\r\n\t获取到SMS发送使能!\r\n"); 
            g_gsm_ctrl.sms_send_enable_failed_times = 0;
            g_gsm_ctrl.sms_send_enable_failed_loops = 0;
            g_gsm_ctrl.at_index++;
#ifdef SMS_TEXT
            send_text_sms(at_cmd, at_cmd_len);
#else
            send_pdu_sms(at_cmd, at_cmd_len);
#endif
        }
        else //发送使能指令
        {
            g_gsm_ctrl.at_index++;
            tx_gsm_string(at_cmd, at_cmd_len);
        }
    }
    else if (g_gsm_ctrl.at_exec_timeout > last_at_exec_timeout)
    {     
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == SMS_SEND_OVER) //发送数据失败
        {
            g_gsm_ctrl.sms_send_data_failed_times++;
            if (g_gsm_ctrl.sms_send_data_failed_times < SMS_SEND_DATA_FAILED_TIMES) //小于SMS_SEND_DATA_FAILED_TIMES次，则重新发送数据
            {
                MY_PRINT(GSM_PRINT, "\r\n\t发送SMS数据失败次数(%d)小于%d次,从头执行SMS基本发送数据指令!\r\n", 
                                                    g_gsm_ctrl.sms_send_data_failed_times, SMS_SEND_DATA_FAILED_TIMES); 
                g_gsm_ctrl.at_index = SMS_AT_CMGS;
            }
            else //达到SMS_SEND_DATA_FAILED_TIMES次
            {
                g_gsm_ctrl.sms_send_data_failed_times = 0;
                g_gsm_ctrl.sms_send_data_failed_loops++;
                if (g_gsm_ctrl.sms_send_data_failed_loops < SMS_SEND_DATA_FAILED_LOOPS) //小于SMS_SEND_DATA_FAILED_LOOPS轮，则进行GSM AT指令初始化
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t发送SMS数据失败轮数[%d]小于%d轮,从头执行基本AT指令!\r\n", 
                                                        g_gsm_ctrl.sms_send_data_failed_loops, SMS_SEND_DATA_FAILED_LOOPS); 
                    g_gsm_ctrl.gsm_init_status = GSM_INIT_NO_OK;
                    g_gsm_ctrl.at_index = GSM_AT;
                }
                else //达到SMS_SEND_DATA_FAILED_LOOPS轮，则切换发送方式为GPRS
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t发送SMS数据失败轮数达到%d轮,切换到GPRS发送!\r\n", 
                                                        SMS_SEND_DATA_FAILED_LOOPS); 
                    g_gsm_ctrl.sms_send_data_failed_loops = 0;
                    g_gsm_ctrl.at_index = GPRS_AT_CIPSTATUS;
                    g_gsm_ctrl.send_commu_method = BY_GPRS;
                }
            }
        }
        else //执行获取>的指令失败
        {
            g_gsm_ctrl.sms_send_enable_failed_times++;
            if (g_gsm_ctrl.sms_send_enable_failed_times < SMS_SEND_ENABLE_FAILED_TIMES) //小于SMS_SEND_ENABLE_FAILED_TIMES次，则重试
            {
                MY_PRINT(GSM_PRINT, "\r\n\t获取SMS发送使能失败次数(%d)小于%d次,从头执行基本SMS发送数据指令!\r\n", 
                                                    g_gsm_ctrl.sms_send_enable_failed_times, SMS_SEND_ENABLE_FAILED_TIMES); 
                g_gsm_ctrl.at_index = SMS_AT_CMGS;
            }
            else //达到SMS_SEND_ENABLE_FAILED_TIMES次
            {
                g_gsm_ctrl.sms_send_enable_failed_times = 0;
                g_gsm_ctrl.sms_send_enable_failed_loops++;
                if (g_gsm_ctrl.sms_send_enable_failed_loops < SMS_SEND_ENABLE_FAILED_LOOPS) //小于SMS_SEND_ENABLE_FAILED_LOOPS轮，则进行GSM AT指令初始化
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t获取SMS发送使能失败轮数[%d]小于%d轮,从头执行基本AT指令!\r\n", 
                                                        g_gsm_ctrl.sms_send_enable_failed_loops, SMS_SEND_ENABLE_FAILED_LOOPS); 
                    g_gsm_ctrl.gsm_init_status = GSM_INIT_NO_OK;
                    g_gsm_ctrl.at_index = GSM_AT;
                }
                else //达到SMS_SEND_ENABLE_FAILED_LOOPS轮，则切换发送方式为GPRS
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t获取SMS发送使能失败轮数达到%d轮,切换到GPRS发送!\r\n", 
                                                        SMS_SEND_ENABLE_FAILED_LOOPS); 
                    g_gsm_ctrl.sms_send_enable_failed_loops = 0;
                    g_gsm_ctrl.at_index = GPRS_AT_CIPSTATUS;
                    g_gsm_ctrl.send_commu_method = BY_GPRS;
                }
            }
        }        
    }  
    else //执行过程中
    {
        //exec doing
    }
}

void build_gprs_link(void)
{
    uint8_t at_buf[64]= {0};
    struct server_ip_and_port_struct server_ip_and_port;
    
    switch (g_gsm_ctrl.at_index)
    {
        case GPRS_AT_CIPSHUT:
            exec_last_at_over();
            strcpy((char *)at_buf, "AT+CIPSHUT\r");
            exec_gprs_at(at_buf, strlen((const char *)at_buf), SECOND_0, AT_ACK_DEFAULT);
            break;
        case GPRS_AT_CSTT:
            strcpy((char *)at_buf, "AT+CSTT=\"CMNET\"\r");
            exec_gprs_at(at_buf, strlen((const char *)at_buf), SECOND_15, AT_ACK_SHUT_OK); //设置gprs接入点
            break;
        case GPRS_AT_CIICR: 
            strcpy((char *)at_buf, "AT+CIICR\r");
            exec_gprs_at(at_buf, strlen((const char *)at_buf), SECOND_10, AT_ACK_OK); //打开无线连接（GPRS 或者 CSD）
            break;
        case GPRS_AT_CIFSR:
            strcpy((char *)at_buf, "AT+CIFSR\r");
            exec_gprs_at(at_buf, strlen((const char *)at_buf), SECOND_20, AT_ACK_OK); //获取本机IP地址
            break;
        case GPRS_AT_CIPSTART:
            memset(&server_ip_and_port, 0x0, sizeof(struct server_ip_and_port_struct));
            get_server_ip_and_port(&server_ip_and_port);
            sprintf((char *)at_buf, "AT+CIPSTART=\"TCP\",\"%s\",%s\r", server_ip_and_port.server_ip, server_ip_and_port.server_port);
            MY_PRINT(GSM_PRINT, "\r\n\t[%s] 执行链接指令:%s\r\n", __FUNCTION__, at_buf);
            exec_gprs_at(at_buf, strlen((const char *)at_buf), SECOND_5, AT_ACK_IP_ADDR);
            break;
        case GPRS_LINK_OVER:
            exec_gprs_at(NULL, 0, SECOND_10, AT_ACK_CONNECT_OK);           
            break;
        default:
            break;
    }      
}

/**
  * uint8_t tmp;
  * uint8_t *ptr_tmp;
  * tx_gsm_string("0891683108705505F011000D91688125801135F2000400104142434445464748494A4B4C4D4E4F50", 
        strlen("0891683108705505F011000D91688125801135F2000400104142434445464748494A4B4C4D4E4F50")); //len = 15+ 32/2 =31
  * tx_gsm_string("0891683108705505F011000D91688125801135F20008005660A85F53524D5E1062374F59989D0034002E003700305143FF0C51764E2D57FA672C5E1062374F59989D0034002E003700305143FF0C8D6090015E1062374F59989D00305143FF0C67087ED365E50031003765E5002E",
        strlen("0891683108705505F011000D91688125801135F20008005660A85F53524D5E1062374F59989D0034002E003700305143FF0C51764E2D57FA672C5E1062374F59989D0034002E003700305143FF0C8D6090015E1062374F59989D00305143FF0C67087ED365E50031003765E5002E"));
  * ptr_tmp = &tmp; 
  * tmp = 0x1a;
  * tx_gsm_string(ptr_tmp, 1);
  * 发送中文时，须用ucs-2编码 
  */
void send_data_to_gsm(uint8_t *tx_buf, uint16_t tx_len)
{
    uint8_t at_buf[64] = {0};
    
    switch (g_gsm_ctrl.at_index)
    {
        case GPRS_AT_CIPSTATUS:           
            exec_last_at_over();
            strcpy((char *)at_buf, "AT+CIPSTATUS\r");
            exec_gprs_send_data(at_buf, strlen((const char *)at_buf), SECOND_0, AT_ACK_DEFAULT);
        case GPRS_AT_CIPSEND:
            sprintf((char *)at_buf, "AT+CIPSEND=%d\r", tx_len);
            exec_gprs_send_data(at_buf, strlen((const char *)at_buf), SECOND_3, AT_ACK_STATE_CONNECT_OK);
            break;
        case GPRS_SEND_DATA:
            exec_gprs_send_data(tx_buf, tx_len, SECOND_10, AT_ACK_GPRS_SEND_ENABLE);
            break;
        case GPRS_SEND_OVER:
            exec_gprs_send_data(NULL, 0, SECOND_10, AT_ACK_GPRS_SEND_OK);
            break;
            
        case SMS_AT_CMGS:
            exec_last_at_over();
#ifdef SMS_TEXT
            sprintf((char *)at_buf, "AT+CMGS=\"18520811532\"\r"); //手机APP电话号码13827762835
#else
            sprintf((char *)at_buf, "AT+CMGS=%d\r", (tx_len + SMS_SEND_HEADER_LEN));
#endif
            exec_sms_send_data(at_buf, strlen((const char *)at_buf), SECOND_0, AT_ACK_DEFAULT);
            break;
        case SMS_SEND_DATA:
            exec_sms_send_data(tx_buf, tx_len, SECOND_10, AT_ACK_SMS_SEND_ENABLE);
            break;
        case SMS_SEND_OVER:
            exec_sms_send_data(NULL, 0, SECOND_10, AT_ACK_OK);
            break;
        default:
            break;
    }
}

void main_gsm(void)
{
    deal_with_gsm_usart_rx(); //每次发送前先处理接收数据

    if (g_gsm_ctrl.gsm_init_status != GSM_INIT_OK)
    {
        init_gsm_at();
        return; 
    }

    if (g_gsm_shared_buf.ctrl_flag == GSM_SHARED_BUF_SEND_DOING) //共享缓存区有数据
    {
#ifndef NEW_PROTOCOL
        if (g_local_para.main_commu_mode == BY_SMS)
#else
        if (g_network_manage_para.main_commu_mode == BY_SMS) //主通信方式为SMS方式下，当前发送通讯方式也只能走短信
#endif
        {
            g_gsm_ctrl.send_commu_method = BY_SMS;
        }
        
        if (g_gsm_ctrl.send_commu_method == BY_GPRS) 
        {
            build_gprs_link();
        }
        else //BY_SMS下将at_index不是出于发送短信的状态下，直接定位到短信模式
        {
            if (g_gsm_ctrl.at_index < SMS_AT_CMGS)
            {
                g_gsm_ctrl.at_index = SMS_AT_CMGS;
            }
        }
        
        send_data_to_gsm(g_gsm_shared_buf.buf, g_gsm_shared_buf.len);
    }
    else //GSM_SHARED_BUF_DEFAULT_STATUS
    {
        if (pop_gsm_ring_buf(&g_gsm_ring_buf, &g_gsm_shared_buf) == SUCCESS)  //如果环形缓冲区有数据，则读至共享缓冲区
        {
            g_gsm_shared_buf.ctrl_flag = GSM_SHARED_BUF_SEND_DOING;
        }
    }
}

void print_gsm(void)
{
#ifdef NEW_PROTOCOL
    MY_PRINT(GSM_PRINT, "\r\n\tg_commu_packet_seq = 0x%x\r\n", g_commu_packet_seq);    
#endif
    MY_PRINT(GSM_PRINT, "\r\n\t[g_gsm_ctrl] at_index = 0x%x\r\n", g_gsm_ctrl.at_index);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] last_at_ack = %d\r\n", g_gsm_ctrl.last_at_ack);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] at_exec_timeout = %d\r\n", g_gsm_ctrl.at_exec_timeout);
#ifdef NEW_PROTOCOL
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] send_commu_method = %d[1:SMS,2:GPRS]\r\n", g_gsm_ctrl.send_commu_method);
#else
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] send_commu_method = %d[0:SMS,15:GPRS]\r\n", g_gsm_ctrl.send_commu_method);
#endif
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] gsm_init_status = %d\r\n", g_gsm_ctrl.gsm_init_status);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] gprs_link_status = %d\r\n", g_gsm_ctrl.gprs_link_status);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] gprs_link_failed_times = %d\r\n", g_gsm_ctrl.gprs_link_failed_times);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] gprs_link_failed_loops = %d\r\n", g_gsm_ctrl.gprs_link_failed_loops);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] gprs_send_enable_failed_times = %d\r\n", g_gsm_ctrl.gprs_send_enable_failed_times);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] gprs_send_enable_failed_loops = %d\r\n", g_gsm_ctrl.gprs_send_enable_failed_loops);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] gprs_send_data_failed_times = %d\r\n", g_gsm_ctrl.gprs_send_data_failed_times);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] gprs_send_data_failed_loops = %d\r\n", g_gsm_ctrl.gprs_send_data_failed_loops);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] sms_send_enable_failed_times = %d\r\n", g_gsm_ctrl.sms_send_enable_failed_times);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] sms_send_enable_failed_loops = %d\r\n", g_gsm_ctrl.sms_send_enable_failed_loops);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] sms_send_data_failed_times = %d\r\n", g_gsm_ctrl.sms_send_data_failed_times);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] sms_send_data_failed_loops = %d\r\n", g_gsm_ctrl.sms_send_data_failed_loops);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ctrl] gsm_power_off_times = %d\r\n", g_gsm_ctrl.gsm_power_off_times);
#ifndef NEW_PROTOCOL
    MY_PRINT(GSM_PRINT, "\t[g_report_value] csq_value = %d\r\n", g_report_value.csq_value); 
#else
    MY_PRINT(GSM_PRINT, "\t[g_sample_value] csq_value = %d\r\n", g_sample_value.csq_value); 
#endif
    MY_PRINT(GSM_PRINT, "\t[g_gsm_ring_buf] front_read = %d, tail_write = %d\r\n", g_gsm_ring_buf.front_read, g_gsm_ring_buf.tail_write);
    MY_PRINT(GSM_PRINT, "\t[g_gsm_shared_buf] len = %d, times = %d, type = %d, ctrl_flag = %d\r\n", 
                                            g_gsm_shared_buf.len,  g_gsm_shared_buf.send_times,  g_gsm_shared_buf.type,  g_gsm_shared_buf.ctrl_flag);
}

void test_at(void)
{
    uint8_t len;
    uint8_t buf[32] = {0};
   
    MY_PRINT(GSM_PRINT, "\t[%s] 输入at指令:(命令后不要输入回车)\r\n", __FUNCTION__);

    USART_ITConfig(USART_DUG_USART_POTR, USART_IT_RXNE, DISABLE); //禁止接收中断
    scanf("%s", buf); //如"atd18520811532;"
    USART_ITConfig(USART_DUG_USART_POTR, USART_IT_RXNE, ENABLE); //开启接收中断 

    len = strlen((const char *)buf);
    if (len < 32)
    {
        buf[len] = '\r';
    }

    if (tx_gsm_string_reply(buf, "OK", SECOND_5) == TRUE)
    {
        MY_PRINT(GSM_PRINT, "\t[%s] 执行GSM命令成功!\r\n", __FUNCTION__);
    }
    else
    {
        MY_PRINT(GSM_PRINT, "\t[%s] 执行GSM命令失败!\r\n", __FUNCTION__);
    }
}

void send_test_data(void)
{
    uint8_t type = '0';
    
    MY_PRINT(GSM_PRINT, "\r\n\t请输入:定时数据'0',定时刻数据'1',报警数据'2',退出'q':");
    
    USART_ITConfig(USART_DUG_USART_POTR, USART_IT_RXNE, DISABLE); //禁止接收中断
    scanf("%c", &type);
    USART_ITConfig(USART_DUG_USART_POTR, USART_IT_RXNE, ENABLE); //开启接收中断

    switch (type)
    {
        case '0':
#ifndef NEW_PROTOCOL
            send_terminal_status_packet(STATUS_PACKET, NULL, FRAME_ID_COMMON);
#else
            new_send_active_report(CYCLE_REPORT);
#endif
            break;
        case '1':
#ifndef NEW_PROTOCOL
            send_key_report_clock_packet(FRAME_ID_COMMON);
#else
            new_send_active_report(KEY_CLOCK_REPORT);
#endif
            break;           
        case '2':
#ifndef NEW_PROTOCOL
            send_alarm_packet();
#else
            new_send_active_report(ALARM_REPORT);
#endif
            break;
        case 'q':
            break;
        default:
            break;
    }
}

#endif

