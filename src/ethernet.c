#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    if (buf->len < sizeof(ether_hdr_t))
    {
        return;
    }
    ether_hdr_t *ether_hdr = (ether_hdr_t *) buf->data;
    buf_remove_header(buf, sizeof(ether_hdr_t));
    net_in(buf, swap16(ether_hdr->protocol16), ether_hdr->src);
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    if (buf->len < 46)
    {
        buf_add_padding(buf, 46 - buf->len);
    }
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *ether_hdr = (ether_hdr_t *) buf->data;
    memcpy(ether_hdr->src, net_if_mac, 6);
    memcpy(ether_hdr->dst, mac, 6);
    ether_hdr->protocol16 = swap16(protocol);
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
