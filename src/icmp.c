#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    buf_t buf;
    buf_init(&buf, req_buf->len);
    memcpy(buf.data, req_buf->data, req_buf->len);
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *) buf.data;
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
    icmp_hdr->checksum16 = 0;
    icmp_flip_endianness(icmp_hdr);
    icmp_hdr->checksum16 = swap16(checksum16((uint16_t *) buf.data, buf.len / sizeof(uint16_t)));
    ip_out(&buf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    if (buf->len < sizeof(icmp_hdr_t))
    {
        return;
    }
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *) buf->data;
    icmp_flip_endianness(icmp_hdr);
    uint16_t checksum = icmp_hdr->checksum16;
    icmp_hdr->checksum16 = 0;
    icmp_flip_endianness(icmp_hdr);
    if (checksum16((uint16_t *) buf->data, buf->len / sizeof(uint16_t)) != checksum)
    {
        return;
    }
    icmp_flip_endianness(icmp_hdr);
    icmp_hdr->checksum16 = checksum;
    switch (icmp_hdr->type)
    {
        case ICMP_TYPE_ECHO_REQUEST:
            if (icmp_hdr->code != 0)
            {
                return;
            }
            icmp_resp(buf, src_ip);
            break;
        default:
            break;
    }
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    buf_t buf;
    buf_init(&buf, ((ip_hdr_t *) recv_buf->data)->hdr_len * IP_HDR_LEN_PER_BYTE + 8);
    memcpy(buf.data, recv_buf->data, ((ip_hdr_t *) recv_buf->data)->hdr_len * IP_HDR_LEN_PER_BYTE + 8);
    buf_add_header(&buf, sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *) buf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->checksum16 = 0;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;
    icmp_flip_endianness(icmp_hdr);
    icmp_hdr->checksum16 = swap16(checksum16((uint16_t *) buf.data, buf.len / sizeof(uint16_t)));
    ip_out(&buf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}

void icmp_flip_endianness(icmp_hdr_t *icmp_hdr)
{
    icmp_hdr->checksum16 = swap16(icmp_hdr->checksum16);
    icmp_hdr->id16 = swap16(icmp_hdr->id16);
    icmp_hdr->seq16 = swap16(icmp_hdr->seq16);
}