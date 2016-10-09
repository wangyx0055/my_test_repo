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

/* �Զ������ */
struct gsm_ctrl_struct g_gsm_ctrl;
struct gsm_ring_buf_struct g_gsm_ring_buf;
struct gsm_send_packet_struct g_gsm_shared_buf;
struct at_list_struct g_at_list[] =
{
    {"AT\r",                                             SECOND_0,   AT_ACK_DEFAULT}, //ATָ��
    {"ATE0\r",                                         SECOND_3,   AT_ACK_OK}, //0:�رջ���,1:�򿪻���
    { "AT+IPR=0\r",                                 SECOND_3,   AT_ACK_OK}, //���ò�����Ϊ�Զ�����ģʽ
    {"AT&W\r",                                        SECOND_3,   AT_ACK_OK}, //��������
    {"ATS0=0\r",                                     SECOND_3,   AT_ACK_OK}, //0=��ֹ��1~255��������Զ�����
#ifdef SMS_TEXT
    { "AT+CMGF=1\r",                              SECOND_3,   AT_ACK_OK}, //ѡ�����Ϣ��ʽΪPDU��ʽ(0:PDU��1:�ı�)
    {"AT+CSCS=\"GSM\"\r",                      SECOND_3,   AT_ACK_OK}, //ѡ���ı���ʽ��GSM��ʽ
#else
    {"AT+CMGF=0\r",                               SECOND_3,   AT_ACK_OK}, //ѡ�����Ϣ��ʽΪPDU��ʽ(0:PDU��1:�ı�)
#endif
    {"AT+CNMI=2,1,0,0,0\r",                     SECOND_3,  AT_ACK_OK}, //��������Ϣָʾ��ʽ�������Ƕ��Ŵ�SIM��
    {"AT+CSCA?\r",                                  SECOND_10, AT_ACK_OK}, //��ѯSMS���ŷ������ĺ���
    {"AT+CIPHEAD=1\r",                           SECOND_3,  AT_ACK_CSCA}, //0=��IPͷ��1=��ʽ ��ʽ: +IPD,data length:
    {"AT+CSCLK=1\r",                              SECOND_3,  AT_ACK_OK}, //Ϊ1��ʾʹ������ģʽ��DTR����ʱ��������ģʽ��DTR����ʱ�˳�����ģʽ
    {"AT+CLIP=1\r",                                 SECOND_3,  AT_ACK_OK}, //ָʾ������룬Ϊ1����ʾ
    {"AT+CGREG=1\r",                             SECOND_3,  AT_ACK_OK}, //Ϊ1��ʾ��������ע��״̬����������: +CGREG:<stat>
    {"AT+CGDCONT=1,\"IP\",\"CMNET\"\r", SECOND_3,  AT_ACK_OK}, //0=��IPͷ��1=��ʽ ��ʽ: +IPD,data length:
    {"AT+CIPMUX=0\r",                             SECOND_3,  AT_ACK_OK}, //0��ʾ������
    {"AT+CIPMODE=0\r",                          SECOND_3,  AT_ACK_OK}, //0��ʾ��͸������
    {"AT+CSQ\r",                                     SECOND_3,  AT_ACK_OK}, //��ѯ��ǿ
    {"",                                                    SECOND_3,  AT_ACK_CSQ}, //gsm atָ�����
};

void init_gsm_at(void)
{   
    uint8_t at_list_index;
    
    switch (g_gsm_ctrl.at_index)
    {
        case GSM_POWER_OFF:
            MODEM_POWER_OFF;
            MODEM_PWRKEY_H; //��powerkey�ܽ�����
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
        clean_gsm_usart_buf(); //����֮ǰ����GSM���ڻ���
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

/* ע������switch��û��break��˵���ǴӸ�λ����λ�𲽼��� */
void get_server_ip_and_port(struct server_ip_and_port_struct * ptr_server_ip_and_port)
{
    uint8_t i;
    uint8_t j = 0;
    uint8_t k = 0;
    uint16_t ip;
    uint16_t port;
    uint8_t *server_ip = ptr_server_ip_and_port->server_ip;
    uint8_t *server_port = ptr_server_ip_and_port->server_port;
        
    for (i = 0; i < 4; ++i) //����ip��ַ
    {
#ifndef NEW_PROTOCOL
        ip = g_local_para.ip_port_apn[i];
#else
        ip = g_network_manage_para.server_ip_addr[i];
#endif

        switch (ip > 99) //�����λ
        {
            case 1: //�а�λ�ȴ����λ���ټ�������ʮλ
                {
                    server_ip[j++] = (ip / 100 + '0'); //ȡ��λ
                }
            case 0: //�ް�λ����ʮλ
               {
                    switch (ip > 9) //����ʮλ
                    {
                        case 1: //��ʮλ�ȴ���ʮλ���ٴ�������ĸ�λ
                            {
                                server_ip[j++] = ((ip % 100) / 10) + '0'; //ȡʮλ
                            }
                        case 0: //��ʮλֱ�Ӵ����λ
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

    switch (port > 9999) //������λ
    {
        case 1:
            server_port[k++] = (port / 10000 + '0'); //ȡ��λ
        case 0:
            switch (port > 999) //����ǧλ
            {
                case 1:
                    server_port[k++] = ((port % 10000) / 1000) + '0'; //ȡǧλ
                case 0:
                    {
                        switch (port > 99) //�����λ
                        {
                            case 1:
                                server_port[k++] = ((port % 1000) / 100) + '0'; //ȡ��λ
                            case 0:
                                switch (port > 9) //����ʮλ
                                {
                                    case 1:
                                        server_port[k++] = ((port % 100) / 10) + '0'; //ȡʮλ
                                    case 0:
                                        server_port[k++] = ((port % 10) / 1) + '0'; //ȡ��λ
                                }
                        }
                    }
            }
    }
}

/**
  * +IPD,85: 
  * ����comma��ʾ����','��colon��ʾð��':'.
  */
void parse_rx_gprs_packet(uint8_t *rx_buf, uint16_t rx_len)
{ 
    uint16_t i;
    uint8_t payload_len;
    uint16_t comma_index = 0;
    uint16_t colon_index = 0;
    uint8_t *payload;
    uint8_t payload_len_buf[16];

    //MY_PRINT(GSM_PRINT, "\t[%s] GPRS���մ��ڳ���:%d,���մ�������:", __FUNCTION__, rx_len);
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

    if ( (comma_index == 0) || (colon_index == 0) || (comma_index >= colon_index) ) //��Ҫ�������ݺ�����У�鴦��
    {
        MY_PRINT(GSM_PRINT, "\t[%s] ��ȡ��GPRS���ݷǷ�,comma_index = %d, colon_index = %d\r\n", __FUNCTION__, comma_index, colon_index);
        return;
    }
    
    memcpy(payload_len_buf, &(rx_buf[comma_index + 1]), (colon_index - comma_index + 1 - 2));
    payload_len = atoi((char const*)payload_len_buf);  
    payload = (rx_buf + colon_index + 1);
    
    MY_PRINT(GSM_PRINT, "\t[%s] GPRS���վ��ɳ���:%d,����:", __FUNCTION__, payload_len);
    print_buf(payload, payload_len, HEX_FLAG);

#ifndef NEW_PROTOCOL    
    parse_protocol(payload, payload_len);
#else
    parse_new_protocol(GPRS_METHOD, payload, payload_len);
#endif
}

#ifdef SMS_TEXT
/**
  * ����Ҫ��:
  * 1���������ݰ�֮ǰ��������CRCУ��ֵ���ٲ��á�ASCII���ִ�����
  * 2���ڽ��յ����ݰ����Ƚ��С�ASCII���ִ����ķ������ٽ���CRCУ�顣
  */
void parse_text_sms_packet(uint8_t *rx_buf, uint16_t rx_len)
{
    uint16_t i;
    uint16_t sms_start_flag = 0;
    uint16_t sms_end_flag = 0;
    uint16_t sms_len;
    uint8_t payload[180] = {0};
    
    MY_PRINT(GSM_PRINT, "\t[%s] SMS���մ��ڳ���:%d,���մ�������:", __FUNCTION__, rx_len);
    print_buf(rx_buf, rx_len, HEX_FLAG);

#ifdef NEW_PROTOCOL
    parse_sms_num(rx_buf, rx_len, g_network_manage_para.recent_user_sms_num);
#endif
   
    for (i = 0; i < (rx_len - 1); ++i)
    {
        if (rx_buf[i] == SMS_START_FLAG) //SMS������Э�����ʼ��־
        {
            sms_start_flag = i;
            break;
        }
    }

    for (i = (rx_len - 1); i > 0; --i)
    {
        if (rx_buf[i] == SMS_END_FLAG) //SMS������Э��Ľ�����־
        {
            sms_end_flag = i;
            break;
        }
    }

    if ( (sms_start_flag == 0) || (sms_end_flag == 0) || (sms_start_flag >= sms_end_flag) ) //��Ҫ�������ݺ�����У�鴦��
    {
        MY_PRINT(GSM_PRINT, "\t[%s] ��ȡ��SMS���ݷǷ�,sms_start_flag = %d, sms_end_flag = %d\r\n", __FUNCTION__, sms_start_flag, sms_end_flag);
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

    MY_PRINT(GSM_PRINT, "\t[%s] SMS���մ��ڳ���:%d,���մ�������:", __FUNCTION__, rx_len);
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
        || ((protocol_sms_tailer - protocol_sms_header) <= 1) )  //��Ҫ�������ݺ�����У�鴦��
    {
        MY_PRINT(GSM_PRINT, "\t[%s] ��ȡ�Ķ������ݷǷ�,protocol_sms_header:%d,protocol_sms_tailer:%d\r\n", 
                                            __FUNCTION__, protocol_sms_header, protocol_sms_header);
        return;
    }

    protocol_sms_len = protocol_sms_tailer - protocol_sms_header + 1;   
    MY_PRINT(GSM_PRINT, "\t[%s] Э�����ͷ:%d,����β:%d,���ų���:%d\r\n", 
                                        __FUNCTION__, protocol_sms_header, protocol_sms_tailer, protocol_sms_len);

    ascii_to_hex(rx_buf + protocol_sms_header, payload, protocol_sms_len);
    payload_len = protocol_sms_len / 2;
    
    MY_PRINT(GSM_PRINT, "\t[%s] Э�鳤��:%d,Э������:", __FUNCTION__, payload_len);
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
    uint16_t first_LF = 0; //��һ������
    uint16_t second_LF = 0; //�ڶ�������
    uint8_t *sms;
    uint16_t sms_len;
    uint8_t *sms_payload;
    uint16_t sms_payload_len;
    uint16_t payload_len;
    uint8_t payload[180] = {0};

    MY_PRINT(GSM_PRINT, "\r\n\t[%s] SMS���մ��ڳ���:%d,���մ�������:", __FUNCTION__, rx_len);
    print_buf(rx_buf, rx_len, CHAR_FLAG);

    /* ���ҵ�һ��',' */
    for (i = 0; i < rx_len; ++i)
    {
        if (rx_buf[i] == ',') //0x27
        {
            break;
        }
    }
    
    /* ���ҵڶ���',' */
    for (i = i + 1; i < rx_len; ++i) 
    {
        if (rx_buf[i] == ',') //0x27
        {
            break;
        }
    }
    
    /* ���ҵ�һ�����з�'\n'(0x0a) */
    for (i = i + 1; i < rx_len; ++i)
    {
        if (rx_buf[i] == LF_CHAR)
        {
            first_LF = i;
            break;
        }
    }
    
    /* ���ҵڶ������з�'\n'(0x0a) */
    for (i = (first_LF + 1); i < rx_len; ++i)
    {
        if (rx_buf[i] == LF_CHAR)
        {
            second_LF = i;
            break;
        }
    }

    if ( ((second_LF - first_LF) <= 1) || (first_LF == 0) || (second_LF == 0) )  //��Ҫ�������ݺ�����У�鴦��
    {
        MY_PRINT(GSM_PRINT, "\r\n\t[%s] ��ȡ�Ķ������ݷǷ�,first_LF:%d,second_LF:%d\r\n", 
                                            __FUNCTION__, first_LF, second_LF);
        return;
    }
    
    sms = rx_buf + first_LF + 1;
    sms_len = (second_LF - first_LF + 1) - 3;

    MY_PRINT(GSM_PRINT, "\r\n\t[%s] first_LF:%d,second_LF:%d,sms_len:%d\r\n", 
                                        __FUNCTION__, first_LF, second_LF, sms_len);
    
    sms_payload = sms + PDU_SMS_HEADER;
    sms_payload_len = sms_len - PDU_SMS_HEADER;

    MY_PRINT(GSM_PRINT, "\t[%s] ���ž��ɳ���:%d,��������:", __FUNCTION__, sms_payload_len);
    print_buf(sms_payload, sms_payload_len, CHAR_FLAG);

    ascii_to_hex(sms_payload, payload, sms_payload_len);
    payload_len = sms_payload_len / 2;

    MY_PRINT(GSM_PRINT, "\r\n\t[%s] ��ȡ��Э�鳤��:%d,Э������:", __FUNCTION__, payload_len);
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
    
    MY_PRINT(GSM_PRINT, "\r\n\t[%s] ��ʼɾ�����ű��Ϊ%d�Ķ���...\r\n", __FUNCTION__, sms_index);
    
    if (tx_gsm_string_reply(at_cmgd_buf, "OK", SECOND_5) == TRUE)
    {
        MY_PRINT(GSM_PRINT, "\t[%s] ɾ�����ű��Ϊ%d�Ķ��ųɹ�!\r\n", __FUNCTION__, sms_index);
    }
    else
    {
        MY_PRINT(GSM_PRINT, "\t[%s] ɾ�����ű��Ϊ%d�Ķ���ʧ��!\r\n", __FUNCTION__, sms_index);
    }
}

void read_sms(uint8_t sms_index)
{
    uint8_t at_cmgr_buf[32];

    memset(at_cmgr_buf, 0, sizeof(at_cmgr_buf));
    sprintf((char *)at_cmgr_buf, "AT+CMGR=%d\r", sms_index);
   
    MY_PRINT(GSM_PRINT, "\t[%s] ��ʼ��ȡ���ű��Ϊ%d�Ķ���......\r\n", __FUNCTION__, sms_index);
    
    if (tx_gsm_string_reply(at_cmgr_buf, "OK", SECOND_5) == TRUE)
    {
        MY_PRINT(GSM_PRINT, "\t[%s] ��ȡ���ű��Ϊ%d�Ķ��ųɹ�!\r\n", __FUNCTION__, sms_index);
#ifdef SMS_TEXT
        parse_text_sms_packet(g_gsm_usart_buf.rx_buf, g_gsm_usart_buf.rx_len);
#else
        parse_pdu_sms_packet(g_gsm_usart_buf.rx_buf, g_gsm_usart_buf.rx_len);
#endif
        delete_sms(sms_index);
    }
    else
    {
        MY_PRINT(GSM_PRINT, "\t[%s] ��ȡ���ű��Ϊ%d�Ķ���ʧ��!\r\n", __FUNCTION__, sms_index);
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
    uint16_t comma_index; //����,
    uint16_t CR_index; //�س�\r

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

    read_sms(sms_index); //��ȡ����
}

void deal_with_gsm_usart_rx(void)
{
    uint8_t rx_buf[MAX_GSM_RX_BUF_LEN] = {0};
    uint8_t rx_len;

    /* �����������ݵĻ�������д��ڻ����ȡ */
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
                MY_PRINT(GSM_PRINT, "\r\n\t[%s] GPRS���ӳɹ�!\r\n", __FUNCTION__); 
                g_gsm_ctrl.last_at_ack = AT_ACK_CONNECT_OK;
            }
        }
        
        if (find_string(rx_buf, "SEND OK") != NULL)
        {
            MY_PRINT(GSM_PRINT, "\r\n\t[%s] ����GPRS���ݳɹ�!\r\n\r\n", __FUNCTION__); 
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
                MY_PRINT(GSM_PRINT, "\r\n\t[%s] ��ȡGPRS����ʹ�ܳɹ�!\r\n", __FUNCTION__); 
                g_gsm_ctrl.last_at_ack = AT_ACK_GPRS_SEND_ENABLE;
            }
            else
            {
                MY_PRINT(GSM_PRINT, "\r\n\t[%s] ��ȡSMS����ʹ�ܳɹ�!\r\n", __FUNCTION__); 
                g_gsm_ctrl.last_at_ack = AT_ACK_SMS_SEND_ENABLE;
            }
        }
        
        if (find_string(rx_buf, "+CSCA:") != NULL) //�����������ĺ���
        {
#ifndef NEW_PROTOCOL
            parse_sms_num(rx_buf, rx_len, &g_local_para.sms_center_num[1]);
#else
            parse_sms_num(rx_buf, rx_len, g_network_manage_para.sms_center_num);
#endif
            g_gsm_ctrl.last_at_ack = AT_ACK_CSCA;
        }
        
        if (find_string(rx_buf, "+CSQ:") != NULL) //����CSQ
        {
            parse_csq(rx_buf, rx_len);
            g_gsm_ctrl.last_at_ack = AT_ACK_CSQ;
        }
        
        if (find_string(rx_buf, "+PDP: DEACT") != NULL) //�յ���λ����GPRS�ͷ��ź�
        {
            MY_PRINT(GSM_PRINT, "\r\n\r\n\t[%s] �յ���λ���ͷ�PDP�����ź�!\r\n", __FUNCTION__);
        }
        
        if (find_string(rx_buf, "+IPD,") != NULL) //�������յ���GPRS����
        {
            MY_PRINT(GSM_PRINT, "\r\n\r\n\t[%s] �յ�GPRS����!\r\n", __FUNCTION__);
            parse_rx_gprs_packet(rx_buf, rx_len);
        }
               
        /* ��ʽΪ\r\n+CMTI: "SM",sms_index\r\n */
        if (find_string(rx_buf, "+CMTI: \"SM\",") != NULL) //�յ����ű���
        {
            MY_PRINT(GSM_PRINT, "\r\n\r\n\t[%s] �յ����ű���!\r\n", __FUNCTION__);
            parse_rx_sms_index(rx_buf, rx_len);
        }
        
        if (find_string(rx_buf, "RING") != NULL) //���������¼�
        {
            g_gsm_ctrl.ring_times++;
            if (g_gsm_ctrl.ring_times >= 3)
            {			
                g_gsm_ctrl.ring_times = 0;
                MY_PRINT(GSM_PRINT, "\r\n\r\n\t[%s] ���������һ�!\r\n", __FUNCTION__);
                
                MODEM_DTR_WAKEUP;
                delay_ms(1000);
                tx_gsm_string("ATH\r", 4); 
                delay_ms(3000);
                MY_PRINT(GSM_PRINT, "\r\n\r\n\t[%s] �һ��ɹ�!\r\n", __FUNCTION__);
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
  * 1��at_cmd:����Ҫִ�е�ָ��
  * 2��at_cmd_len:����Ҫִ��ָ��ĳ���
  * 3��last_at_exec_timeout:����atָ��ִ�еĳ�ʱʱ��
  * 4��last_at_ack:����atָ��ķ��ؽ��
  */
void exec_gsm_at(uint8_t *at_cmd, uint8_t at_cmd_len, uint16_t last_at_exec_timeout, uint8_t needed_last_at_ack)
{
    uint8_t last_at_index = g_gsm_ctrl.at_index - 1;
    
    if (g_gsm_ctrl.last_at_ack == needed_last_at_ack) //�ϴ�ָ��ִ�гɹ�
    {  
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == GSM_INIT_OVER) //ָ��GSM���һ��ATָ��(AT + CSQ)�ɹ�
        {
            MY_PRINT(GSM_PRINT, "\r\n\tGSM AT��ʼ���ɹ�!\r\n"); 
            g_gsm_ctrl.at_failed_times[last_at_index] = 0;
            g_gsm_ctrl.gsm_power_off_times = 0;            
            g_gsm_ctrl.gsm_init_status = GSM_INIT_OK;
            g_gsm_ctrl.at_index++;
        }
        else //ִ��GSMһ��ָ��
        {
            g_gsm_ctrl.at_failed_times[last_at_index] = 0;
            tx_gsm_string(at_cmd, at_cmd_len);
            g_gsm_ctrl.at_index++;
        }
    }
    else if (g_gsm_ctrl.at_exec_timeout > last_at_exec_timeout) //�ϴ�ָ��ִ�г�ʱ
    {
        exec_last_at_over();
        g_gsm_ctrl.at_failed_times[last_at_index]++;
        if (g_gsm_ctrl.at_failed_times[last_at_index] < AT_FAILED_TIMES) //����AT_FAIL_TIMES�Σ�ֻ�����´�ͷִ��ATָ��
        {
            g_gsm_ctrl.at_index = GSM_AT; 
        }
        else //�ﵽAT_FAIL_TIMES��������GSMģ��
        {
            g_gsm_ctrl.at_failed_times[last_at_index] = 0;
            g_gsm_ctrl.at_index = GSM_POWER_OFF; 
            g_gsm_ctrl.gsm_power_off_times++;
            MY_PRINT(GSM_PRINT, "\r\n\tִ��AT���Ϊ0x%x��ָ��ʧ�ܴ����ﵽ%d��,���е�%d��GSM���µ����!\r\n", 
                                                last_at_index, AT_FAILED_TIMES, g_gsm_ctrl.gsm_power_off_times);                      
            if (g_gsm_ctrl.gsm_power_off_times >= GSM_POWER_OFF_TIMES) //�ﵽGSM_POWER_OFF_TIMES�ξ�����RTU
            {
                g_gsm_ctrl.gsm_power_off_times = 0;
                MY_PRINT(GSM_PRINT, "\r\n\r\n\tGSM���µ�����ﵽ%d��,��������RTU!\r\n", GSM_POWER_OFF_TIMES);
                reboot_rtu(APP_RESET_GSM);
            }
        }        
    }    
    else //�ϴ�ָ������ִ�й�����
    {
        //exec doing
    }
}

/**
  * 1��at_cmd:����Ҫִ�е�ָ��
  * 2��at_cmd_len:����Ҫִ��ָ��ĳ���
  * 3��last_at_exec_timeout:����atָ��ִ�еĳ�ʱʱ��
  * 4��last_at_ack:����atָ��ķ��ؽ��
  */
void exec_gprs_at(uint8_t *at_cmd, uint16_t at_cmd_len, uint16_t last_at_exec_timeout, uint8_t needed_last_at_ack)
{
    uint8_t last_at_index = g_gsm_ctrl.at_index - 1;

    if (g_gsm_ctrl.last_at_ack == needed_last_at_ack) //�ϴ�ָ��ִ�гɹ�
    {
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == GPRS_LINK_OVER)  //ִ��GPRS����ָ��ɹ�
        {
            g_gsm_ctrl.gprs_link_failed_times = 0;
            g_gsm_ctrl.gprs_link_failed_loops = 0;
            g_gsm_ctrl.gprs_link_status = GPRS_CONNECTED; 
            g_gsm_ctrl.at_index++;
        }
        else //ִ��GPRSһ��ָ��(��GPRS����ָ��)�ɹ�
        {
            g_gsm_ctrl.gprs_at_failed_times[last_at_index] = 0;
            tx_gsm_string(at_cmd, at_cmd_len);
            g_gsm_ctrl.at_index++;
        }        
    }
    else if (g_gsm_ctrl.at_exec_timeout > last_at_exec_timeout) //�ϴ�ָ��ִ�г�ʱ
    {       
        g_gsm_ctrl.gprs_link_status = GPRS_NOT_CONNECTED;       
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == GPRS_LINK_OVER) //ִ��GPRS����ָ��ʧ��
        {
            g_gsm_ctrl.gprs_link_failed_times++;
            if (g_gsm_ctrl.gprs_link_failed_times < GPRS_LINK_FAILED_TIMES) //����GPRS_LINK_FAILED_TIMES�Σ������´�ͷִ��GPRS��ʼ��ָ��
            {
                MY_PRINT(GSM_PRINT, "\r\n\tִ��GPRS����ָ��ʧ�ܴ���(%d)С��%d��,��ͷִ�л���GPRSָ��!\r\n", 
                                                     g_gsm_ctrl.gprs_link_failed_times, GPRS_LINK_FAILED_TIMES); 
                g_gsm_ctrl.at_index = GPRS_AT_CIPSHUT;
            }
            else //�ﵽGPRS_LINK_FAILED_TIMES��
            {
                g_gsm_ctrl.gprs_link_failed_times = 0;
                g_gsm_ctrl.gprs_link_failed_loops++;
                if (g_gsm_ctrl.gprs_link_failed_loops < GPRS_LINK_FAILED_LOOPS) //����GPRS_LINK_FAILED_LOOPS�֣����ʼ��GSMģ���ATָ��
                {
                    MY_PRINT(GSM_PRINT, "\r\n\tִ��GPRS����ָ��ʧ������[%d]С��%d��,��ͷִ�л���ATָ��!\r\n", 
                                                        g_gsm_ctrl.gprs_link_failed_loops, GPRS_LINK_FAILED_TIMES); 
                    g_gsm_ctrl.gsm_init_status = GSM_INIT_NO_OK;
                    g_gsm_ctrl.at_index = GSM_AT; 
                }
                else //�ﵽGPRS_LINK_FAILED_LOOPS�֣����л����ͷ�ʽΪ����
                {
                    MY_PRINT(GSM_PRINT, "\r\n\tִ��GPRS����ָ��ʧ�������ﵽ%d��,�л������ŷ���!\r\n", 
                                                        GPRS_LINK_FAILED_LOOPS); 
                    g_gsm_ctrl.gprs_link_failed_loops = 0;
                    g_gsm_ctrl.at_index = SMS_AT_CMGS;
                    g_gsm_ctrl.send_commu_method = BY_SMS;
                }
            }
        }
        else //ִ��GPRS��һ��ָ�(������ָ��)ʧ��
        {
            g_gsm_ctrl.gprs_at_failed_times[last_at_index]++;
            if (g_gsm_ctrl.gprs_at_failed_times[last_at_index] < GPRS_AT_FAILED_TIMES) //С��GPRS_AT_FAILED_TIMES�Σ�������ִ��GPRSָ��
            {  
                MY_PRINT(GSM_PRINT, "\r\n\tִ��GPRS���Ϊ0x%xָ��ʧ�ܴ���(%d)С��%d��,��ͷִ�л���GPRSָ��!\r\n", 
                                                    last_at_index, g_gsm_ctrl.gprs_at_failed_times[last_at_index], GPRS_AT_FAILED_TIMES); 
                g_gsm_ctrl.at_index = GPRS_AT_CIPSHUT;
            }
            else //�ﵽGPRS_AT_FAILED_TIMES��,���л����ͷ�ʽΪ����
            {
                MY_PRINT(GSM_PRINT, "\r\n\tִ��GPRS���Ϊ0x%xָ��ʧ�ܴﵽ%d��,�л������ŷ���!\r\n", 
                                                    last_at_index, GPRS_AT_FAILED_TIMES); 
                g_gsm_ctrl.gprs_at_failed_times[last_at_index] = 0;
                g_gsm_ctrl.at_index = SMS_AT_CMGS;
                g_gsm_ctrl.send_commu_method = BY_SMS;
            }
        }
    }
    else //ִ�й�����
    {
        //exec doing
    }
}

void exec_gprs_send_data(uint8_t *at_cmd, uint16_t at_cmd_len, uint16_t last_at_exec_timeout, uint8_t needed_last_at_ack)
{
    if (g_gsm_ctrl.last_at_ack == needed_last_at_ack) //�ϴ�ָ��ִ�гɹ�
    {   
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == GPRS_SEND_OVER) //�������ݳɹ�
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
        else if (g_gsm_ctrl.at_index == GPRS_SEND_DATA) //��ȡ����������ʹ��
        {
            g_gsm_ctrl.gprs_send_enable_failed_times = 0;
            g_gsm_ctrl.gprs_send_enable_failed_loops = 0;
            g_gsm_ctrl.at_index++;
            
            MY_PRINT(GSM_PRINT, "\r\n\t[%s] GPRS�������ݳ���:%d,����:", __FUNCTION__, at_cmd_len);
            print_buf(at_cmd, at_cmd_len, HEX_FLAG);
            tx_gsm_string(at_cmd, at_cmd_len);
        }
        else //ִ��AT+CIPSTATUS����AT+CIPSEND
        {
            g_gsm_ctrl.at_index++;
            tx_gsm_string(at_cmd, at_cmd_len);
        }
    }
    else if (g_gsm_ctrl.at_exec_timeout > last_at_exec_timeout) //�ϴ�ָ��ִ�г�ʱ��ʧ��
    {
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == GPRS_SEND_OVER) //send dataʧ��
        {
            g_gsm_ctrl.gprs_send_data_failed_times++;
            if (g_gsm_ctrl.gprs_send_data_failed_times < GPRS_SEND_DATA_FAILED_TIMES) //С��GPRS_SEND_DATA_FAILED_TIMES�Σ������·�������
            {
                MY_PRINT(GSM_PRINT, "\r\n\t����GPRS����ʧ�ܴ���(%d)С��%d��,��ͷִ�л���GPRS��������ָ��!\r\n", 
                                                     g_gsm_ctrl.gprs_send_data_failed_times, GPRS_SEND_DATA_FAILED_TIMES); 
                g_gsm_ctrl.at_index = GPRS_AT_CIPSTATUS;
            }
            else //�ﵽGPRS_SEND_DATA_FAILED_TIMES��
            {
                g_gsm_ctrl.gprs_send_data_failed_times = 0;
                g_gsm_ctrl.gprs_send_data_failed_loops++;
                if (g_gsm_ctrl.gprs_send_data_failed_loops < GPRS_SEND_DATA_FAILED_LOOPS) //С��GPRS_SEND_DATA_FAILED_LOOPS�֣������GPRS��ʼ��
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t����GPRS����ʧ������[%d]С��%d��,��ͷִ�л���GPRSָ��!\r\n", 
                                                        g_gsm_ctrl.gprs_send_data_failed_loops, GPRS_SEND_DATA_FAILED_LOOPS); 
                    g_gsm_ctrl.at_index = GPRS_AT_CIPSHUT;
                }
                else //�ﵽGPRS_SEND_DATA_FAILED_LOOPS�֣����л����ͷ�ʽΪ����
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t����GPRS����ʧ�������ﵽ%d��,�л������ŷ���!\r\n", 
                                                        GPRS_SEND_DATA_FAILED_LOOPS); 
                    g_gsm_ctrl.gprs_send_data_failed_loops = 0;
                    g_gsm_ctrl.at_index = SMS_AT_CMGS;
                    g_gsm_ctrl.send_commu_method = BY_SMS;
                }
            }
        }
        else if (g_gsm_ctrl.at_index == GPRS_SEND_DATA) //ִ�л�ȡ>��ָ��ʧ��
        {
            g_gsm_ctrl.gprs_send_enable_failed_times++;
            if (g_gsm_ctrl.gprs_send_enable_failed_times < GPRS_SEND_ENABLE_FAILED_TIMES) //����GPRS_SEND_ENABLE_FAILED_TIMES�Σ�������ִ�з�����������
            {
                MY_PRINT(GSM_PRINT, "\r\n\t��ȡGPRS����ʹ��ʧ�ܴ���(%d)С��%d��,��ͷִ�л���GPRS��������ָ��!\r\n", 
                                                    g_gsm_ctrl.gprs_send_enable_failed_times, GPRS_SEND_ENABLE_FAILED_TIMES); 
                g_gsm_ctrl.at_index = GPRS_AT_CIPSTATUS;
            }
            else //�ﵽGPRS_SEND_ENABLE_FAILED_TIMES��
            {
                g_gsm_ctrl.gprs_send_enable_failed_times = 0;
                g_gsm_ctrl.gprs_send_enable_failed_loops++;
                if (g_gsm_ctrl.gprs_send_enable_failed_loops < GPRS_SEND_ENABLE_FAILED_LOOPS) //С��GPRS_SEND_ENABLE_FAILED_LOOPS�֣������GPRS��ʼ��
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t��ȡGPRS����ʹ��ʧ������[%d]С��%d��,��ͷִ�л���GPRSָ��!\r\n", 
                                                        g_gsm_ctrl.gprs_send_enable_failed_loops, GPRS_SEND_ENABLE_FAILED_LOOPS); 
                    g_gsm_ctrl.at_index = GPRS_AT_CIPSHUT;
                }
                else //�ﵽGPRS_SEND_ENABLE_FAILED_LOOPS�֣����л����ͷ�ʽΪ����
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t��ȡGPRS����ʹ��ʧ�������ﵽ%d��,�л������ŷ���!\r\n", 
                                                        GPRS_SEND_ENABLE_FAILED_LOOPS); 
                    g_gsm_ctrl.gprs_send_enable_failed_loops = 0;
                    g_gsm_ctrl.at_index = SMS_AT_CMGS;
                    g_gsm_ctrl.send_commu_method = BY_SMS;
                }
            }
        }
        else //��ȡִ��AT+CIPSTATUS��ָ���ȡ"connect ok"ʧ��
        {
            MY_PRINT(GSM_PRINT, "\r\n\t����GPRS����ǰ��⵽GPRS���ӶϿ�,��ͷִ�л���GPRSָ��!\r\n"); 
            g_gsm_ctrl.at_index = GPRS_AT_CIPSHUT;
        }        
    }   
    else //ִ�й�����
    {
        //exec doing
    }
}

/** 
  * ��PDU ģʽ�շ�����Ϣ����ʹ�����ֱ���: 7-bit ���롢8-bit �����UCS2 ���롣
  * 7-bit�������ڷ�����ͨ��ASCII �ַ���8-bit ����ͨ�����ڷ���������Ϣ,��ͼƬ�������ȣ�
  * UCS2�������ڷ���Unicode �ַ���
  * �ο�http://blog.csdn.net/linux_xiaomugua/article/details/7085374
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
   
    MY_PRINT(GSM_PRINT, "\r\n\t[%s] ����Ϣ���ɳ���:%d,����:", __FUNCTION__, len);
    print_buf(buf, len, HEX_FLAG);

    if (len >= MAX_SMS_SEND_LEN)
    {
        MY_PRINT(GSM_PRINT, "\r\n\t[%s]����Ϣ���ɳ��ȳ���%u�ַ�,�˳�����Ϣ����!\r\n", __FUNCTION__, MAX_SMS_SEND_LEN);
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
    
    /* �������ĺ��� */
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

    /* Ŀ���ֻ����� */
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
    
    /* ʹ��8-bit���룬�������ģ����뷽ʽΪUCS-2,��������000800 */
    memcpy(&tmp_buf[index], "000400", 6);        
    index += 6;
    
    /* ���ž��ɳ��� */
    if ((len / 16) < 10)
    {
        tmp_buf[index++] = (len / 16) + '0'; //����
    }
    else
    {
        tmp_buf[index++] = (len / 16) - 10 + 65; //��ĸ
    }

    if ((len % 16) < 10)
    {
        tmp_buf[index++] = (len % 16) + '0'; //����
    }
    else
    {
        tmp_buf[index++] = (len % 16) - 10 + 65; //��ĸ
    }
    
    /* ���ž��� */
    hex_to_ascii(buf, ascii_buf, len);
    memcpy(&tmp_buf[index], ascii_buf, 2 * len);
    index += 2 * len;

    MY_PRINT(GSM_PRINT, "\r\n\t[%s] ����Ϣ����:%d,����:", __FUNCTION__, len);
    print_buf(tmp_buf, strlen((const char *)tmp_buf), CHAR_FLAG);

    /* ���Ͷ������ݵ�gsm���� */
    tx_gsm_string(tmp_buf, strlen((const char *)tmp_buf));
        
   /* ���ͽ�����־ */		
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
    
    MY_PRINT(GSM_PRINT, "\r\n\t[%s] ����Ϣ����:%d,����:", __FUNCTION__, len);
    print_buf(buf, len, HEX_FLAG);

    if (len >= MAX_SMS_SEND_LEN)
    {
        MY_PRINT(GSM_PRINT, "\r\n\t[%s] ����Ϣ���ȳ���%u�ַ�,�˳�����Ϣ����\r\n", 
                                            __FUNCTION__, MAX_SMS_SEND_LEN);
        return;
    }
    
    /* ���Ͷ������ݵ�gsm���� */
    tx_gsm_string(buf, len);
        
   /* ���ͽ�����־ */		
    ptr_tmp = &tmp; 
    tmp = 0x1a;
    tx_gsm_string(ptr_tmp, 1);
}

void exec_sms_send_data(uint8_t *at_cmd, uint16_t at_cmd_len, uint16_t last_at_exec_timeout, uint8_t needed_last_at_ack)
{
    if (g_gsm_ctrl.last_at_ack == needed_last_at_ack) //�ϴ�ָ��ִ�гɹ�
    {    
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == SMS_SEND_OVER) //�������ݳɹ�
        {
            MY_PRINT(GSM_PRINT, "\r\n\t����SMS���ݳɹ�!\r\n"); 
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
            MY_PRINT(GSM_PRINT, "\r\n\t��ȡ��SMS����ʹ��!\r\n"); 
            g_gsm_ctrl.sms_send_enable_failed_times = 0;
            g_gsm_ctrl.sms_send_enable_failed_loops = 0;
            g_gsm_ctrl.at_index++;
#ifdef SMS_TEXT
            send_text_sms(at_cmd, at_cmd_len);
#else
            send_pdu_sms(at_cmd, at_cmd_len);
#endif
        }
        else //����ʹ��ָ��
        {
            g_gsm_ctrl.at_index++;
            tx_gsm_string(at_cmd, at_cmd_len);
        }
    }
    else if (g_gsm_ctrl.at_exec_timeout > last_at_exec_timeout)
    {     
        exec_last_at_over();
        if (g_gsm_ctrl.at_index == SMS_SEND_OVER) //��������ʧ��
        {
            g_gsm_ctrl.sms_send_data_failed_times++;
            if (g_gsm_ctrl.sms_send_data_failed_times < SMS_SEND_DATA_FAILED_TIMES) //С��SMS_SEND_DATA_FAILED_TIMES�Σ������·�������
            {
                MY_PRINT(GSM_PRINT, "\r\n\t����SMS����ʧ�ܴ���(%d)С��%d��,��ͷִ��SMS������������ָ��!\r\n", 
                                                    g_gsm_ctrl.sms_send_data_failed_times, SMS_SEND_DATA_FAILED_TIMES); 
                g_gsm_ctrl.at_index = SMS_AT_CMGS;
            }
            else //�ﵽSMS_SEND_DATA_FAILED_TIMES��
            {
                g_gsm_ctrl.sms_send_data_failed_times = 0;
                g_gsm_ctrl.sms_send_data_failed_loops++;
                if (g_gsm_ctrl.sms_send_data_failed_loops < SMS_SEND_DATA_FAILED_LOOPS) //С��SMS_SEND_DATA_FAILED_LOOPS�֣������GSM ATָ���ʼ��
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t����SMS����ʧ������[%d]С��%d��,��ͷִ�л���ATָ��!\r\n", 
                                                        g_gsm_ctrl.sms_send_data_failed_loops, SMS_SEND_DATA_FAILED_LOOPS); 
                    g_gsm_ctrl.gsm_init_status = GSM_INIT_NO_OK;
                    g_gsm_ctrl.at_index = GSM_AT;
                }
                else //�ﵽSMS_SEND_DATA_FAILED_LOOPS�֣����л����ͷ�ʽΪGPRS
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t����SMS����ʧ�������ﵽ%d��,�л���GPRS����!\r\n", 
                                                        SMS_SEND_DATA_FAILED_LOOPS); 
                    g_gsm_ctrl.sms_send_data_failed_loops = 0;
                    g_gsm_ctrl.at_index = GPRS_AT_CIPSTATUS;
                    g_gsm_ctrl.send_commu_method = BY_GPRS;
                }
            }
        }
        else //ִ�л�ȡ>��ָ��ʧ��
        {
            g_gsm_ctrl.sms_send_enable_failed_times++;
            if (g_gsm_ctrl.sms_send_enable_failed_times < SMS_SEND_ENABLE_FAILED_TIMES) //С��SMS_SEND_ENABLE_FAILED_TIMES�Σ�������
            {
                MY_PRINT(GSM_PRINT, "\r\n\t��ȡSMS����ʹ��ʧ�ܴ���(%d)С��%d��,��ͷִ�л���SMS��������ָ��!\r\n", 
                                                    g_gsm_ctrl.sms_send_enable_failed_times, SMS_SEND_ENABLE_FAILED_TIMES); 
                g_gsm_ctrl.at_index = SMS_AT_CMGS;
            }
            else //�ﵽSMS_SEND_ENABLE_FAILED_TIMES��
            {
                g_gsm_ctrl.sms_send_enable_failed_times = 0;
                g_gsm_ctrl.sms_send_enable_failed_loops++;
                if (g_gsm_ctrl.sms_send_enable_failed_loops < SMS_SEND_ENABLE_FAILED_LOOPS) //С��SMS_SEND_ENABLE_FAILED_LOOPS�֣������GSM ATָ���ʼ��
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t��ȡSMS����ʹ��ʧ������[%d]С��%d��,��ͷִ�л���ATָ��!\r\n", 
                                                        g_gsm_ctrl.sms_send_enable_failed_loops, SMS_SEND_ENABLE_FAILED_LOOPS); 
                    g_gsm_ctrl.gsm_init_status = GSM_INIT_NO_OK;
                    g_gsm_ctrl.at_index = GSM_AT;
                }
                else //�ﵽSMS_SEND_ENABLE_FAILED_LOOPS�֣����л����ͷ�ʽΪGPRS
                {
                    MY_PRINT(GSM_PRINT, "\r\n\t��ȡSMS����ʹ��ʧ�������ﵽ%d��,�л���GPRS����!\r\n", 
                                                        SMS_SEND_ENABLE_FAILED_LOOPS); 
                    g_gsm_ctrl.sms_send_enable_failed_loops = 0;
                    g_gsm_ctrl.at_index = GPRS_AT_CIPSTATUS;
                    g_gsm_ctrl.send_commu_method = BY_GPRS;
                }
            }
        }        
    }  
    else //ִ�й�����
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
            exec_gprs_at(at_buf, strlen((const char *)at_buf), SECOND_15, AT_ACK_SHUT_OK); //����gprs�����
            break;
        case GPRS_AT_CIICR: 
            strcpy((char *)at_buf, "AT+CIICR\r");
            exec_gprs_at(at_buf, strlen((const char *)at_buf), SECOND_10, AT_ACK_OK); //���������ӣ�GPRS ���� CSD��
            break;
        case GPRS_AT_CIFSR:
            strcpy((char *)at_buf, "AT+CIFSR\r");
            exec_gprs_at(at_buf, strlen((const char *)at_buf), SECOND_20, AT_ACK_OK); //��ȡ����IP��ַ
            break;
        case GPRS_AT_CIPSTART:
            memset(&server_ip_and_port, 0x0, sizeof(struct server_ip_and_port_struct));
            get_server_ip_and_port(&server_ip_and_port);
            sprintf((char *)at_buf, "AT+CIPSTART=\"TCP\",\"%s\",%s\r", server_ip_and_port.server_ip, server_ip_and_port.server_port);
            MY_PRINT(GSM_PRINT, "\r\n\t[%s] ִ������ָ��:%s\r\n", __FUNCTION__, at_buf);
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
  * ��������ʱ������ucs-2���� 
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
            sprintf((char *)at_buf, "AT+CMGS=\"18520811532\"\r"); //�ֻ�APP�绰����13827762835
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
    deal_with_gsm_usart_rx(); //ÿ�η���ǰ�ȴ����������

    if (g_gsm_ctrl.gsm_init_status != GSM_INIT_OK)
    {
        init_gsm_at();
        return; 
    }

    if (g_gsm_shared_buf.ctrl_flag == GSM_SHARED_BUF_SEND_DOING) //��������������
    {
#ifndef NEW_PROTOCOL
        if (g_local_para.main_commu_mode == BY_SMS)
#else
        if (g_network_manage_para.main_commu_mode == BY_SMS) //��ͨ�ŷ�ʽΪSMS��ʽ�£���ǰ����ͨѶ��ʽҲֻ���߶���
#endif
        {
            g_gsm_ctrl.send_commu_method = BY_SMS;
        }
        
        if (g_gsm_ctrl.send_commu_method == BY_GPRS) 
        {
            build_gprs_link();
        }
        else //BY_SMS�½�at_index���ǳ��ڷ��Ͷ��ŵ�״̬�£�ֱ�Ӷ�λ������ģʽ
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
        if (pop_gsm_ring_buf(&g_gsm_ring_buf, &g_gsm_shared_buf) == SUCCESS)  //������λ����������ݣ��������������
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
   
    MY_PRINT(GSM_PRINT, "\t[%s] ����atָ��:(�����Ҫ����س�)\r\n", __FUNCTION__);

    USART_ITConfig(USART_DUG_USART_POTR, USART_IT_RXNE, DISABLE); //��ֹ�����ж�
    scanf("%s", buf); //��"atd18520811532;"
    USART_ITConfig(USART_DUG_USART_POTR, USART_IT_RXNE, ENABLE); //���������ж� 

    len = strlen((const char *)buf);
    if (len < 32)
    {
        buf[len] = '\r';
    }

    if (tx_gsm_string_reply(buf, "OK", SECOND_5) == TRUE)
    {
        MY_PRINT(GSM_PRINT, "\t[%s] ִ��GSM����ɹ�!\r\n", __FUNCTION__);
    }
    else
    {
        MY_PRINT(GSM_PRINT, "\t[%s] ִ��GSM����ʧ��!\r\n", __FUNCTION__);
    }
}

void send_test_data(void)
{
    uint8_t type = '0';
    
    MY_PRINT(GSM_PRINT, "\r\n\t������:��ʱ����'0',��ʱ������'1',��������'2',�˳�'q':");
    
    USART_ITConfig(USART_DUG_USART_POTR, USART_IT_RXNE, DISABLE); //��ֹ�����ж�
    scanf("%c", &type);
    USART_ITConfig(USART_DUG_USART_POTR, USART_IT_RXNE, ENABLE); //���������ж�

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

