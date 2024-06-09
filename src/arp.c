#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    buf_t buf;
    buf_init(&buf, sizeof(arp_pkt_t));
    arp_pkt_t *arp_pkt = (arp_pkt_t *) buf.data;
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    arp_pkt->opcode16 = swap16(ARP_REQUEST);
    memcpy(arp_pkt->target_mac, net_null_mac, NET_MAC_LEN);
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    ethernet_out(&buf, net_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    buf_t buf;
    buf_init(&buf, sizeof(arp_pkt_t));
    arp_pkt_t *arp_pkt = (arp_pkt_t *) buf.data;
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    arp_pkt->opcode16 = swap16(ARP_REPLY);
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    ethernet_out(&buf, target_mac, NET_PROTOCOL_ARP);
}

static void on_arp_table_update(void *ip, void *mac)
{
    buf_t *buf = map_get(&arp_buf, ip);
    if (buf != NULL)
    {
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, ip);
    }
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    if (buf->len < sizeof(arp_pkt_t))
    {
        return;
    }
    buf_remove_padding(buf, buf->len - sizeof(arp_pkt_t));
    arp_pkt_t *arp_pkt = (arp_pkt_t *) buf->data;
    arp_flip_endianness(arp_pkt);
    if (arp_pkt->hw_type16 != ARP_HW_ETHER)
    {
        return;
    }
    if (arp_pkt->pro_type16 != NET_PROTOCOL_IP)
    {
        return;
    }
    if (arp_pkt->hw_len != NET_MAC_LEN)
    {
        return;
    }
    if (arp_pkt->pro_len != NET_IP_LEN)
    {
        return;
    }
    if (memcmp(src_mac, arp_pkt->sender_mac, NET_MAC_LEN) != 0)
    {
        return;
    }
    switch (arp_pkt->opcode16)
    {
        case ARP_REQUEST:
            if (!is_null_mac(arp_pkt->target_mac))
            {
                return;
            }
            map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);
            on_arp_table_update(arp_pkt->sender_ip, arp_pkt->sender_mac);
            if (is_if_ip(arp_pkt->target_ip))
            {
                arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
            }
            break;
        case ARP_REPLY:
            if (!is_if_mac(arp_pkt->target_mac))
            {
                return;
            }
            if (!is_if_ip(arp_pkt->target_ip))
            {
                return;
            }
            map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);
            on_arp_table_update(arp_pkt->sender_ip, arp_pkt->sender_mac);
            break;
        default:
            break;
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    uint8_t *mac = map_get(&arp_table, ip);
    if (mac != NULL)
    {
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    }
    else
    {
        map_set(&arp_buf, ip, buf);
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}

void arp_flip_endianness(arp_pkt_t *arp_pkt)
{
    arp_pkt->hw_type16 = swap16(arp_pkt->hw_type16);
    arp_pkt->pro_type16 = swap16(arp_pkt->pro_type16);
    arp_pkt->opcode16 = swap16(arp_pkt->opcode16);
}