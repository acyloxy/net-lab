#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    if (buf->len < sizeof(ip_hdr_t))
    {
        return;
    }
    ip_hdr_t *ip_hdr = (ip_hdr_t *) buf->data;
    ip_flip_endianness(ip_hdr);
    int length_valid = buf->len >= ip_hdr->total_len16 &&
            ip_hdr->total_len16 >= ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE &&
            ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE >= sizeof(ip_hdr_t);
    if (!length_valid)
    {
        return;
    }
    buf_remove_padding(buf, buf->len - ip_hdr->total_len16);
    if (ip_hdr->version != IP_VERSION_4)
    {
        return;
    }
    if (ip_hdr->ttl == 0)
    {
        return;
    }
    uint16_t checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    ip_flip_endianness(ip_hdr);
    if (checksum16((uint16_t *) buf->data, sizeof(ip_hdr_t) / sizeof(uint16_t)) != checksum)
    {
        return;
    }
    ip_flip_endianness(ip_hdr);
    ip_hdr->hdr_checksum16 = checksum;
    if (!is_if_ip(ip_hdr->dst_ip))
    {
        return;
    }
    switch (ip_hdr->protocol)
    {
        case NET_PROTOCOL_ICMP:
            buf_remove_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
            icmp_in(buf, ip_hdr->src_ip);
            break;
        case NET_PROTOCOL_UDP:
            buf_remove_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
            udp_in(buf, ip_hdr->src_ip);
            break;
        default:
            ip_flip_endianness(ip_hdr);
            icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
            break;
    }
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr = (ip_hdr_t *) buf->data;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = buf->len;
    ip_hdr->id16 = id;
    ip_hdr->flags_fragment16 = (offset / IP_HDR_OFFSET_PER_BYTE) | (mf ? IP_MORE_FRAGMENT : 0);
    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    ip_flip_endianness(ip_hdr);
    ip_hdr->hdr_checksum16 = swap16(checksum16((uint16_t *) buf->data, sizeof(ip_hdr_t) / sizeof(uint16_t)));
    arp_out(buf, ip);
}

static int ip_id = 0;

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
#define IP_MAX_BODY_SIZE (ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t))
    for (size_t offset = 0; offset < buf->len; offset += IP_MAX_BODY_SIZE)
    {
        int mf = offset + IP_MAX_BODY_SIZE < buf->len;
        buf_t fragment;
        buf_init(&fragment, mf ? IP_MAX_BODY_SIZE : buf->len - offset);
        memcpy(fragment.data, buf->data + offset, fragment.len);
        ip_fragment_out(&fragment, ip, protocol, ip_id, offset, mf);
    }
    ++ip_id;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}

void ip_flip_endianness(ip_hdr_t *ip_hdr)
{
    ip_hdr->total_len16 = swap16(ip_hdr->total_len16);
    ip_hdr->id16 = swap16(ip_hdr->id16);
    ip_hdr->flags_fragment16 = swap16(ip_hdr->flags_fragment16);
    ip_hdr->hdr_checksum16 = swap16(ip_hdr->hdr_checksum16);
}