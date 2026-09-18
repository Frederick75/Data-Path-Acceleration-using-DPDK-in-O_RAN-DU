/*
 * dpdk_oran_du.c
 *
 * Standalone educational DPDK O-RAN DU fronthaul RX example.
 *
 * Data path:
 *
 *        O-RU
 *         |
 *         | Ethernet / VLAN / eCPRI
 *         v
 *      NIC / VF
 *         |
 *         v
 *   rte_eth_rx_burst()
 *         |
 *         +-------------------+
 *         |                   |
 *         v                   v
 *     U-Plane             C-Plane
 *    eCPRI 0x00          eCPRI 0x02
 *         |                   |
 *         v                   v
 *   Parse O-RAN           Parse O-RAN
 *   radio header          control header
 *         |
 *         v
 *      rte_ring
 *         |
 *         v
 *     PHY Worker
 *         |
 *         v
 *  IQ/L1 processing stub
 *
 *
 * Supported by this sample:
 *
 *   Ethernet II
 *   802.1Q VLAN
 *   802.1ad QinQ (up to two VLAN tags)
 *   eCPRI common header
 *   eCPRI IQ Data             0x00
 *   eCPRI RT Control Data     0x02
 *   eCPRI Delay Measurement   0x05
 *   IEEE-1588 PTP EtherType   0x88F7
 *
 * O-RAN radio application timing decoding:
 *
 *   dataDirection
 *   payloadVersion
 *   filterIndex
 *   frameId
 *   subframeId
 *   slotId
 *   symbolId/startSymbolId
 *
 * U-plane first section:
 *
 *   sectionId
 *   rb
 *   symInc
 *   startPrbu
 *   numPrbu
 *
 * IMPORTANT:
 *
 * This is a complete compilable DPDK application, but it is NOT a complete
 * O-RAN WG4 compliant O-DU. A production O-DU normally uses the O-RAN
 * Fronthaul Interface library and implements complete C/U plane formats,
 * compression, timing windows, section extensions, PRACH, beamforming,
 * multiple eAxCs, PTP/SyncE integration, etc.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdatomic.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_pause.h>
#include <rte_byteorder.h>


/* -------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------
 */

#define RX_DESC_DEFAULT       1024
#define TX_DESC_DEFAULT       1024

#define NUM_MBUFS             32767
#define MBUF_CACHE_SIZE       256

#define RX_BURST_SIZE         32
#define PHY_BURST_SIZE        32

#define PHY_RING_SIZE         4096

/*
 * Large enough for most O-RAN jumbo-frame experiments.
 *
 * rte_pktmbuf_pool_create() data room includes the headroom.
 */
#define MBUF_DATA_ROOM_SIZE \
        (10240 + RTE_PKTMBUF_HEADROOM)


/* Ethernet protocol identifiers */

#define ETH_P_8021Q           0x8100
#define ETH_P_8021AD          0x88A8

#define ETH_P_ECPRI           0xAEFE
#define ETH_P_PTP             0x88F7


/* eCPRI message types */

#define ECPRI_MSG_IQ_DATA         0x00
#define ECPRI_MSG_RT_CONTROL      0x02
#define ECPRI_MSG_DELAY_MEASURE   0x05


/* -------------------------------------------------------------------------
 * Global configuration
 * -------------------------------------------------------------------------
 */

static uint16_t g_port_id = 0;

static uint16_t g_mtu = 1500;

static bool g_promiscuous = false;

static uint32_t g_dump_packets = 10;

static volatile sig_atomic_t g_force_quit = 0;

static struct rte_ring *g_phy_ring = NULL;


/* -------------------------------------------------------------------------
 * Statistics
 * -------------------------------------------------------------------------
 */

struct du_statistics {

    uint64_t rx_packets;
    uint64_t rx_bytes;

    uint64_t uplane_packets;
    uint64_t cplane_packets;

    uint64_t delay_packets;

    uint64_t ptp_packets;

    uint64_t other_packets;

    uint64_t malformed_packets;

    uint64_t phy_ring_drops;

    _Atomic uint64_t phy_processed;
};

static struct du_statistics g_stats;


/* -------------------------------------------------------------------------
 * Parsed packet information
 * -------------------------------------------------------------------------
 */

enum oran_plane {
    ORAN_PLANE_NONE = 0,
    ORAN_PLANE_UPLANE,
    ORAN_PLANE_CPLANE,
    ORAN_PLANE_DELAY,
    ORAN_PLANE_PTP
};


struct oran_packet_info {

    enum oran_plane plane;

    uint16_t vlan_id[2];
    uint8_t  vlan_count;

    uint8_t ecpri_revision;
    uint8_t ecpri_concat;
    uint8_t ecpri_type;

    uint16_t ecpri_payload_size;

    uint16_t eaxc_id;
    uint16_t sequence_id;

    /*
     * O-RAN Radio Application Common Header
     */

    uint8_t direction;
    uint8_t payload_version;
    uint8_t filter_index;

    uint8_t frame_id;
    uint8_t subframe_id;

    uint8_t slot_id;
    uint8_t symbol_id;

    /*
     * C-plane
     */

    uint8_t number_of_sections;
    uint8_t section_type;

    /*
     * U-plane first section
     */

    uint16_t section_id;

    uint8_t rb;
    uint8_t sym_inc;

    uint16_t start_prbu;
    uint8_t num_prbu;
};


/* -------------------------------------------------------------------------
 * Utility functions
 * -------------------------------------------------------------------------
 */

static inline uint16_t
read_be16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) |
            (uint16_t)p[1];
}


static void
signal_handler(int signum)
{
    if (signum == SIGINT ||
        signum == SIGTERM) {

        g_force_quit = 1;
    }
}


/*
 * Example eAxC decode.
 *
 * O-RAN SC permits these bit widths to be configurable.
 *
 * This demonstration assumes:
 *
 *  CU_Port_ID     = 4 bits
 *  BandSector_ID  = 4 bits
 *  CC_ID          = 4 bits
 *  RU_Port_ID     = 4 bits
 */

static void
print_eaxc(uint16_t eaxc)
{
    uint8_t cu_port;
    uint8_t band_sector;
    uint8_t cc_id;
    uint8_t ru_port;

    cu_port =
        (eaxc >> 12) & 0x0f;

    band_sector =
        (eaxc >> 8) & 0x0f;

    cc_id =
        (eaxc >> 4) & 0x0f;

    ru_port =
        eaxc & 0x0f;

    printf(" eAxC=0x%04x"
           " [CU=%u BS=%u CC=%u RU=%u]",
           eaxc,
           cu_port,
           band_sector,
           cc_id,
           ru_port);
}


/* -------------------------------------------------------------------------
 * Ethernet / VLAN parser
 * -------------------------------------------------------------------------
 */

static int
parse_ethernet(const uint8_t *data,
               uint32_t len,
               uint32_t *payload_offset,
               uint16_t *ether_type,
               struct oran_packet_info *info)
{
    uint32_t off;

    uint16_t type;

    if (len < 14)
        return -1;

    type = read_be16(data + 12);

    off = 14;

    info->vlan_count = 0;

    /*
     * Support:
     *
     *  Ethernet
     *  Ethernet + 802.1Q
     *  Ethernet + QinQ
     */

    while ((type == ETH_P_8021Q ||
            type == ETH_P_8021AD) &&
           info->vlan_count < 2) {

        uint16_t tci;

        if (len < off + 4)
            return -1;

        tci = read_be16(data + off);

        info->vlan_id[info->vlan_count] =
            tci & 0x0fff;

        info->vlan_count++;

        type =
            read_be16(data + off + 2);

        off += 4;
    }

    *payload_offset = off;
    *ether_type = type;

    return 0;
}


/* -------------------------------------------------------------------------
 * Radio Application Header parser
 * -------------------------------------------------------------------------
 */

static int
parse_radio_app_header(const uint8_t *p,
                       uint32_t len,
                       struct oran_packet_info *info)
{
    if (len < 4)
        return -1;

    /*
     * Octet 0
     *
     * bit 7       dataDirection
     * bits 6:4    payloadVersion
     * bits 3:0    filterIndex
     */

    info->direction =
        (p[0] >> 7) & 0x01;

    info->payload_version =
        (p[0] >> 4) & 0x07;

    info->filter_index =
        p[0] & 0x0f;

    /*
     * Octet 1
     */

    info->frame_id =
        p[1];

    /*
     * Octets 2/3
     *
     * subframeId = 4 bits
     * slotId     = 6 bits
     * symbolId   = 6 bits
     */

    info->subframe_id =
        (p[2] >> 4) & 0x0f;

    info->slot_id =
        ((p[2] & 0x0f) << 2) |
        ((p[3] >> 6) & 0x03);

    info->symbol_id =
        p[3] & 0x3f;

    return 0;
}


/* -------------------------------------------------------------------------
 * U-plane section parser
 * -------------------------------------------------------------------------
 */

static int
parse_uplane_section(const uint8_t *p,
                     uint32_t len,
                     struct oran_packet_info *info)
{
    if (len < 4)
        return -1;

    /*
     * 32-bit section header:
     *
     * sectionId : 12
     * rb        : 1
     * symInc    : 1
     * startPrbu : 10
     * numPrbu   : 8
     */

    info->section_id =
        ((uint16_t)p[0] << 4) |
        ((p[1] >> 4) & 0x0f);

    info->rb =
        (p[1] >> 3) & 0x01;

    info->sym_inc =
        (p[1] >> 2) & 0x01;

    info->start_prbu =
        ((uint16_t)(p[1] & 0x03) << 8) |
        p[2];

    info->num_prbu =
        p[3];

    return 0;
}


/* -------------------------------------------------------------------------
 * eCPRI/O-RAN parser
 * -------------------------------------------------------------------------
 */

static enum oran_plane
parse_oran_packet(struct rte_mbuf *m,
                  struct oran_packet_info *info)
{
    uint32_t pkt_len;

    const uint8_t *data;

    uint8_t scratch[128];

    uint32_t l2_offset;

    uint16_t ether_type;

    memset(info,
           0,
           sizeof(*info));

    pkt_len =
        rte_pktmbuf_pkt_len(m);

    /*
     * Read only the headers.
     *
     * rte_pktmbuf_read() also handles the case where
     * packet headers span multiple mbuf segments.
     */

    uint32_t read_len =
        pkt_len < sizeof(scratch) ?
        pkt_len :
        sizeof(scratch);

    data =
        rte_pktmbuf_read(
            m,
            0,
            read_len,
            scratch);

    if (data == NULL) {
        g_stats.malformed_packets++;
        return ORAN_PLANE_NONE;
    }

    if (parse_ethernet(
            data,
            read_len,
            &l2_offset,
            &ether_type,
            info) != 0) {

        g_stats.malformed_packets++;

        return ORAN_PLANE_NONE;
    }


    /*
     * IEEE-1588 PTP
     */

    if (ether_type == ETH_P_PTP) {

        info->plane =
            ORAN_PLANE_PTP;

        return info->plane;
    }


    /*
     * Not eCPRI.
     */

    if (ether_type != ETH_P_ECPRI) {

        info->plane =
            ORAN_PLANE_NONE;

        return info->plane;
    }


    /*
     * eCPRI common header = 4 bytes
     */

    if (read_len < l2_offset + 4) {

        g_stats.malformed_packets++;

        return ORAN_PLANE_NONE;
    }

    const uint8_t *ecpri =
        data + l2_offset;

    /*
     * Byte 0:
     *
     * bits 7:4 protocol revision
     * bits 3:1 reserved
     * bit 0    concatenation
     */

    info->ecpri_revision =
        (ecpri[0] >> 4) & 0x0f;

    info->ecpri_concat =
        ecpri[0] & 0x01;

    info->ecpri_type =
        ecpri[1];

    info->ecpri_payload_size =
        read_be16(ecpri + 2);


    /*
     * O-RAN normally uses eCPRI revision 1.
     */

    if (info->ecpri_revision != 1) {

        g_stats.malformed_packets++;

        return ORAN_PLANE_NONE;
    }


    /*
     * Validate declared eCPRI payload against total
     * packet size.
     */

    if (pkt_len <
        l2_offset +
        4 +
        info->ecpri_payload_size) {

        g_stats.malformed_packets++;

        return ORAN_PLANE_NONE;
    }


    /*
     * IQ Data and RT Control both contain a
     * 4-byte message-specific header:
     *
     * PC_ID / RTC_ID : 16 bits
     * Sequence ID    : 16 bits
     */

    if (info->ecpri_type ==
            ECPRI_MSG_IQ_DATA ||

        info->ecpri_type ==
            ECPRI_MSG_RT_CONTROL) {

        if (info->ecpri_payload_size < 4 ||
            read_len < l2_offset + 8) {

            g_stats.malformed_packets++;

            return ORAN_PLANE_NONE;
        }

        info->eaxc_id =
            read_be16(ecpri + 4);

        info->sequence_id =
            read_be16(ecpri + 6);


        const uint8_t *app =
            ecpri + 8;

        uint32_t app_available =
            read_len -
            (l2_offset + 8);


        if (parse_radio_app_header(
                app,
                app_available,
                info) != 0) {

            g_stats.malformed_packets++;

            return ORAN_PLANE_NONE;
        }


        /*
         * U-Plane
         */

        if (info->ecpri_type ==
            ECPRI_MSG_IQ_DATA) {

            info->plane =
                ORAN_PLANE_UPLANE;

            /*
             * Common radio header is 4 bytes.
             *
             * Parse first U-plane section.
             */

            if (app_available >= 8) {

                parse_uplane_section(
                    app + 4,
                    app_available - 4,
                    info);
            }

            return info->plane;
        }


        /*
         * C-Plane
         */

        if (info->ecpri_type ==
            ECPRI_MSG_RT_CONTROL) {

            info->plane =
                ORAN_PLANE_CPLANE;

            /*
             * C-plane:
             *
             * bytes 0..3 radio common header
             * byte 4     numberOfSections
             * byte 5     sectionType
             */

            if (app_available >= 6) {

                info->number_of_sections =
                    app[4];

                info->section_type =
                    app[5];
            }

            return info->plane;
        }
    }


    /*
     * Delay Measurement
     */

    if (info->ecpri_type ==
        ECPRI_MSG_DELAY_MEASURE) {

        info->plane =
            ORAN_PLANE_DELAY;

        return info->plane;
    }


    return ORAN_PLANE_NONE;
}


/* -------------------------------------------------------------------------
 * Packet information output
 * -------------------------------------------------------------------------
 */

static void
dump_packet_info(const struct rte_mbuf *m,
                 const struct oran_packet_info *info)
{
    printf("\n----------------------------------------\n");

    printf("Packet length : %u bytes\n",
           rte_pktmbuf_pkt_len(m));

    if (info->vlan_count) {

        printf("VLAN");

        for (unsigned i = 0;
             i < info->vlan_count;
             i++) {

            printf(" %u",
                   info->vlan_id[i]);
        }

        printf("\n");
    }


    switch (info->plane) {

    case ORAN_PLANE_UPLANE:

        printf("Plane         : O-RAN U-Plane\n");

        printf("eCPRI Type    : IQ Data 0x00\n");

        break;


    case ORAN_PLANE_CPLANE:

        printf("Plane         : O-RAN C-Plane\n");

        printf("eCPRI Type    : RT Control 0x02\n");

        break;


    case ORAN_PLANE_DELAY:

        printf("Plane         : eCPRI Delay Measurement\n");

        break;


    case ORAN_PLANE_PTP:

        printf("Plane         : IEEE-1588 PTP\n");

        return;


    default:

        printf("Plane         : Other\n");

        return;
    }


    printf("eCPRI Rev     : %u\n",
           info->ecpri_revision);

    printf("Payload Size  : %u\n",
           info->ecpri_payload_size);


    if (info->plane ==
            ORAN_PLANE_UPLANE ||

        info->plane ==
            ORAN_PLANE_CPLANE) {

        printf("eAxC/RTC ID   :");

        print_eaxc(info->eaxc_id);

        printf("\n");

        printf("Sequence ID   : 0x%04x\n",
               info->sequence_id);

        printf("Direction     : %s\n",
               info->direction ?
               "DL / gNB TX" :
               "UL / gNB RX");

        printf("Payload Ver   : %u\n",
               info->payload_version);

        printf("Filter Index  : %u\n",
               info->filter_index);

        printf("Frame         : %u\n",
               info->frame_id);

        printf("Subframe      : %u\n",
               info->subframe_id);

        printf("Slot          : %u\n",
               info->slot_id);

        printf("Symbol        : %u\n",
               info->symbol_id);
    }


    if (info->plane ==
        ORAN_PLANE_UPLANE) {

        printf("Section ID    : %u\n",
               info->section_id);

        printf("Start PRB     : %u\n",
               info->start_prbu);

        printf("Number PRBs   : %u\n",
               info->num_prbu);

        printf("RB flag       : %u\n",
               info->rb);

        printf("symInc        : %u\n",
               info->sym_inc);
    }


    if (info->plane ==
        ORAN_PLANE_CPLANE) {

        printf("Num Sections  : %u\n",
               info->number_of_sections);

        printf("Section Type  : %u\n",
               info->section_type);
    }
}


/* -------------------------------------------------------------------------
 * PHY worker
 * -------------------------------------------------------------------------
 *
 * In a real DU this would normally pass IQ data into:
 *
 *   decompression
 *       ->
 *   PRB mapping
 *       ->
 *   FFT / iFFT
 *       ->
 *   channel estimation
 *       ->
 *   equalization
 *       ->
 *   LDPC / FEC
 *       ->
 *   MAC/PHY interface
 *
 * This demo simply represents ownership transfer to L1.
 */

static inline void
process_uplane_in_phy(struct rte_mbuf *m)
{
    /*
     * Real implementation would NOT immediately free
     * this packet.
     *
     * IQ payload would be decoded/copied/referenced
     * by a PHY buffer or accelerator.
     */

    atomic_fetch_add_explicit(
        &g_stats.phy_processed,
        1,
        memory_order_relaxed);

    rte_pktmbuf_free(m);
}


static int
phy_worker(void *arg)
{
    (void)arg;

    struct rte_mbuf *pkts[PHY_BURST_SIZE];

    printf("PHY worker running on lcore %u\n",
           rte_lcore_id());

    while (!g_force_quit ||
           !rte_ring_empty(g_phy_ring)) {

        unsigned count =
            rte_ring_dequeue_burst(
                g_phy_ring,
                (void **)pkts,
                PHY_BURST_SIZE,
                NULL);

        if (count == 0) {

            rte_pause();

            continue;
        }

        for (unsigned i = 0;
             i < count;
             i++) {

            process_uplane_in_phy(
                pkts[i]);
        }
    }

    printf("PHY worker stopped\n");

    return 0;
}


/* -------------------------------------------------------------------------
 * Port initialization
 * -------------------------------------------------------------------------
 */

static int
port_init(uint16_t port_id,
          struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf;

    struct rte_eth_dev_info dev_info;

    struct rte_eth_rxconf rx_conf;

    struct rte_eth_txconf tx_conf;

    uint16_t rx_desc =
        RX_DESC_DEFAULT;

    uint16_t tx_desc =
        TX_DESC_DEFAULT;

    int ret;


    if (!rte_eth_dev_is_valid_port(
            port_id)) {

        fprintf(stderr,
                "Invalid port %u\n",
                port_id);

        return -1;
    }


    memset(&port_conf,
           0,
           sizeof(port_conf));

    port_conf.rxmode.mq_mode =
        RTE_ETH_MQ_RX_NONE;


    ret =
        rte_eth_dev_info_get(
            port_id,
            &dev_info);

    if (ret != 0) {

        fprintf(stderr,
                "rte_eth_dev_info_get failed: %d\n",
                ret);

        return ret;
    }


    /*
     * One RX queue.
     *
     * TX queue is initialized as well because a real O-DU
     * needs DL C/U plane transmission.
     */

    ret =
        rte_eth_dev_configure(
            port_id,
            1,
            1,
            &port_conf);

    if (ret < 0) {

        fprintf(stderr,
                "rte_eth_dev_configure failed: %d\n",
                ret);

        return ret;
    }


    ret =
        rte_eth_dev_adjust_nb_rx_tx_desc(
            port_id,
            &rx_desc,
            &tx_desc);

    if (ret < 0)
        return ret;


    /*
     * Set MTU before starting device.
     */

    if (g_mtu != 0) {

        ret =
            rte_eth_dev_set_mtu(
                port_id,
                g_mtu);

        if (ret < 0) {

            fprintf(stderr,
                    "Warning: could not set MTU %u: %d\n",
                    g_mtu,
                    ret);
        }
    }


    rx_conf =
        dev_info.default_rxconf;

    rx_conf.offloads =
        port_conf.rxmode.offloads;


    ret =
        rte_eth_rx_queue_setup(
            port_id,
            0,
            rx_desc,
            rte_eth_dev_socket_id(
                port_id),
            &rx_conf,
            mbuf_pool);

    if (ret < 0) {

        fprintf(stderr,
                "RX queue setup failed: %d\n",
                ret);

        return ret;
    }


    tx_conf =
        dev_info.default_txconf;

    tx_conf.offloads =
        port_conf.txmode.offloads;


    ret =
        rte_eth_tx_queue_setup(
            port_id,
            0,
            tx_desc,
            rte_eth_dev_socket_id(
                port_id),
            &tx_conf);

    if (ret < 0) {

        fprintf(stderr,
                "TX queue setup failed: %d\n",
                ret);

        return ret;
    }


    ret =
        rte_eth_dev_start(
            port_id);

    if (ret < 0) {

        fprintf(stderr,
                "Device start failed: %d\n",
                ret);

        return ret;
    }


    if (g_promiscuous) {

        ret =
            rte_eth_promiscuous_enable(
                port_id);

        if (ret != 0) {

            fprintf(stderr,
                    "Warning: promiscuous mode failed\n");
        }
    }


    struct rte_ether_addr mac;

    rte_eth_macaddr_get(
        port_id,
        &mac);


    printf("\nO-RAN DPDK port initialized\n");

    printf("Port       : %u\n",
           port_id);

    printf("MAC        : "
           RTE_ETHER_ADDR_PRT_FMT
           "\n",
           RTE_ETHER_ADDR_BYTES(&mac));

    printf("MTU        : %u\n",
           g_mtu);

    printf("RX desc    : %u\n",
           rx_desc);

    printf("TX desc    : %u\n",
           tx_desc);


    struct rte_eth_link link;

    memset(&link,
           0,
           sizeof(link));

    rte_eth_link_get_nowait(
        port_id,
        &link);

    printf("Link       : %s\n",
           link.link_status ?
           "UP" :
           "DOWN");

    if (link.link_status) {

        printf("Speed      : %u Mbps\n",
               link.link_speed);
    }

    return 0;
}


/* -------------------------------------------------------------------------
 * Statistics output
 * -------------------------------------------------------------------------
 */

static void
print_statistics(void)
{
    printf("\n========== O-DU Statistics ==========\n");

    printf("RX packets       : %" PRIu64 "\n",
           g_stats.rx_packets);

    printf("RX bytes         : %" PRIu64 "\n",
           g_stats.rx_bytes);

    printf("U-plane          : %" PRIu64 "\n",
           g_stats.uplane_packets);

    printf("C-plane          : %" PRIu64 "\n",
           g_stats.cplane_packets);

    printf("Delay measure    : %" PRIu64 "\n",
           g_stats.delay_packets);

    printf("PTP              : %" PRIu64 "\n",
           g_stats.ptp_packets);

    printf("Other            : %" PRIu64 "\n",
           g_stats.other_packets);

    printf("Malformed        : %" PRIu64 "\n",
           g_stats.malformed_packets);

    printf("PHY ring drops   : %" PRIu64 "\n",
           g_stats.phy_ring_drops);

    printf("PHY processed    : %" PRIu64 "\n",
           atomic_load_explicit(
               &g_stats.phy_processed,
               memory_order_relaxed));

    printf("=====================================\n");
}


/* -------------------------------------------------------------------------
 * O-DU RX loop
 * -------------------------------------------------------------------------
 */

static void
oran_du_rx_loop(bool have_phy_worker)
{
    struct rte_mbuf *pkts[RX_BURST_SIZE];

    uint64_t last_stats =
        rte_get_tsc_cycles();

    const uint64_t hz =
        rte_get_tsc_hz();


    printf("\nStarting O-RAN DU fronthaul RX\n");

    printf("RX lcore : %u\n",
           rte_lcore_id());


    while (!g_force_quit) {

        uint16_t nb_rx =
            rte_eth_rx_burst(
                g_port_id,
                0,
                pkts,
                RX_BURST_SIZE);


        if (nb_rx == 0) {

            rte_pause();

            goto periodic_stats;
        }


        for (uint16_t i = 0;
             i < nb_rx;
             i++) {

            struct rte_mbuf *m =
                pkts[i];

            struct oran_packet_info info;

            uint32_t len =
                rte_pktmbuf_pkt_len(m);


            g_stats.rx_packets++;

            g_stats.rx_bytes +=
                len;


            enum oran_plane plane =
                parse_oran_packet(
                    m,
                    &info);


            switch (plane) {

            /*
             * ------------------------------------------------
             * O-RAN U-Plane
             * ------------------------------------------------
             */

            case ORAN_PLANE_UPLANE:

                g_stats.uplane_packets++;


                if (g_dump_packets > 0) {

                    dump_packet_info(
                        m,
                        &info);

                    g_dump_packets--;
                }


                /*
                 * Zero-copy ownership transfer:
                 *
                 * RX lcore
                 *    |
                 *    | mbuf pointer
                 *    v
                 * rte_ring
                 *    |
                 *    v
                 * PHY worker
                 */

                if (have_phy_worker) {

                    if (rte_ring_enqueue(
                            g_phy_ring,
                            m) != 0) {

                        g_stats.phy_ring_drops++;

                        rte_pktmbuf_free(m);
                    }
                }
                else {

                    /*
                     * Single-core fallback.
                     */

                    process_uplane_in_phy(m);
                }

                break;


            /*
             * ------------------------------------------------
             * O-RAN C-Plane
             * ------------------------------------------------
             */

            case ORAN_PLANE_CPLANE:

                g_stats.cplane_packets++;


                if (g_dump_packets > 0) {

                    dump_packet_info(
                        m,
                        &info);

                    g_dump_packets--;
                }


                /*
                 * Real implementation:
                 *
                 * update section database
                 * update beam information
                 * update PRB mapping
                 * update symbol scheduling
                 */

                rte_pktmbuf_free(m);

                break;


            /*
             * ------------------------------------------------
             * eCPRI delay measurement
             * ------------------------------------------------
             */

            case ORAN_PLANE_DELAY:

                g_stats.delay_packets++;

                rte_pktmbuf_free(m);

                break;


            /*
             * ------------------------------------------------
             * IEEE-1588 PTP
             * ------------------------------------------------
             */

            case ORAN_PLANE_PTP:

                g_stats.ptp_packets++;

                /*
                 * Normally handled by NIC/PTP subsystem
                 * rather than the L1 packet worker.
                 */

                rte_pktmbuf_free(m);

                break;


            /*
             * ------------------------------------------------
             * Other traffic
             * ------------------------------------------------
             */

            default:

                g_stats.other_packets++;

                rte_pktmbuf_free(m);

                break;
            }
        }


periodic_stats:

        uint64_t now =
            rte_get_tsc_cycles();

        if (now - last_stats >= hz) {

            printf("\r"
                   "RX=%" PRIu64
                   " U=%" PRIu64
                   " C=%" PRIu64
                   " PTP=%" PRIu64
                   " Drop=%" PRIu64
                   " PHY=%" PRIu64
                   "        ",
                   g_stats.rx_packets,
                   g_stats.uplane_packets,
                   g_stats.cplane_packets,
                   g_stats.ptp_packets,
                   g_stats.phy_ring_drops,
                   atomic_load_explicit(
                       &g_stats.phy_processed,
                       memory_order_relaxed));

            fflush(stdout);

            last_stats = now;
        }
    }

    printf("\nRX loop stopping...\n");
}


/* -------------------------------------------------------------------------
 * Command-line handling
 * -------------------------------------------------------------------------
 */

static void
usage(const char *prog)
{
    printf(
        "\nUsage:\n"
        "\n"
        "  %s <EAL options> -- [application options]\n"
        "\n"
        "Application options:\n"
        "\n"
        "  --port N        DPDK fronthaul port (default 0)\n"
        "  --mtu N         Ethernet MTU (default 1500)\n"
        "  --promisc       Enable promiscuous mode\n"
        "  --dump N        Dump first N O-RAN packets (default 10)\n"
        "\n"
        "Example:\n"
        "\n"
        "  sudo %s -l 2-3 -n 4 -- "
        "--port 0 --mtu 9600 --promisc --dump 20\n"
        "\n",
        prog,
        prog);
}


static int
parse_app_args(int argc,
               char **argv)
{
    for (int i = 1;
         i < argc;
         i++) {

        if (strcmp(argv[i],
                   "--port") == 0) {

            if (++i >= argc)
                return -1;

            g_port_id =
                (uint16_t)strtoul(
                    argv[i],
                    NULL,
                    0);
        }

        else if (strcmp(argv[i],
                        "--mtu") == 0) {

            if (++i >= argc)
                return -1;

            g_mtu =
                (uint16_t)strtoul(
                    argv[i],
                    NULL,
                    0);
        }

        else if (strcmp(argv[i],
                        "--dump") == 0) {

            if (++i >= argc)
                return -1;

            g_dump_packets =
                (uint32_t)strtoul(
                    argv[i],
                    NULL,
                    0);
        }

        else if (strcmp(argv[i],
                        "--promisc") == 0) {

            g_promiscuous = true;
        }

        else if (strcmp(argv[i],
                        "--help") == 0) {

            return 1;
        }

        else {

            fprintf(stderr,
                    "Unknown argument: %s\n",
                    argv[i]);

            return -1;
        }
    }

    return 0;
}


/* -------------------------------------------------------------------------
 * main()
 * -------------------------------------------------------------------------
 */

int
main(int argc,
     char **argv)
{
    int ret;

    unsigned worker_lcore =
        RTE_MAX_LCORE;

    bool have_phy_worker =
        false;


    signal(SIGINT,
           signal_handler);

    signal(SIGTERM,
           signal_handler);


    /*
     * ----------------------------------------------------------
     * DPDK EAL
     * ----------------------------------------------------------
     */

    ret =
        rte_eal_init(
            argc,
            argv);

    if (ret < 0) {

        rte_exit(
            EXIT_FAILURE,
            "Cannot initialize DPDK EAL\n");
    }


    argc -= ret;
    argv += ret;


    ret =
        parse_app_args(
            argc,
            argv);

    if (ret != 0) {

        usage("dpdk_oran_du");

        if (ret > 0)
            return EXIT_SUCCESS;

        return EXIT_FAILURE;
    }


    memset(&g_stats,
           0,
           sizeof(g_stats));


    /*
     * ----------------------------------------------------------
     * Mbuf pool
     * ----------------------------------------------------------
     */

    struct rte_mempool *mbuf_pool =
        rte_pktmbuf_pool_create(
            "ORAN_DU_MBUF_POOL",

            NUM_MBUFS,

            MBUF_CACHE_SIZE,

            0,

            MBUF_DATA_ROOM_SIZE,

            rte_socket_id());


    if (mbuf_pool == NULL) {

        rte_exit(
            EXIT_FAILURE,
            "Cannot create mbuf pool: %s\n",
            rte_strerror(rte_errno));
    }


    /*
     * ----------------------------------------------------------
     * PHY ring
     * ----------------------------------------------------------
     */

    g_phy_ring =
        rte_ring_create(
            "ORAN_PHY_RING",

            PHY_RING_SIZE,

            rte_socket_id(),

            RING_F_SP_ENQ |
            RING_F_SC_DEQ);


    if (g_phy_ring == NULL) {

        rte_exit(
            EXIT_FAILURE,
            "Cannot create PHY ring: %s\n",
            rte_strerror(rte_errno));
    }


    /*
     * ----------------------------------------------------------
     * Ethernet port
     * ----------------------------------------------------------
     */

    if (port_init(
            g_port_id,
            mbuf_pool) != 0) {

        rte_exit(
            EXIT_FAILURE,
            "Cannot initialize port %u\n",
            g_port_id);
    }


    /*
     * ----------------------------------------------------------
     * Launch PHY worker
     * ----------------------------------------------------------
     */

    RTE_LCORE_FOREACH_WORKER(
        worker_lcore) {

        ret =
            rte_eal_remote_launch(
                phy_worker,
                NULL,
                worker_lcore);

        if (ret == 0) {

            have_phy_worker = true;

            break;
        }
    }


    if (!have_phy_worker) {

        printf(
            "WARNING: no worker lcore available.\n"
            "U-plane PHY processing will execute "
            "on RX lcore.\n");
    }


    /*
     * ----------------------------------------------------------
     * Run O-DU fronthaul RX
     * ----------------------------------------------------------
     */

    oran_du_rx_loop(
        have_phy_worker);


    /*
     * ----------------------------------------------------------
     * Wait for PHY worker
     * ----------------------------------------------------------
     */

    if (have_phy_worker) {

        rte_eal_wait_lcore(
            worker_lcore);
    }


    /*
     * Drain anything left in ring.
     */

    struct rte_mbuf *m;

    while (rte_ring_dequeue(
            g_phy_ring,
            (void **)&m) == 0) {

        rte_pktmbuf_free(m);
    }


    /*
     * ----------------------------------------------------------
     * Shutdown
     * ----------------------------------------------------------
     */

    rte_eth_dev_stop(
        g_port_id);

    rte_eth_dev_close(
        g_port_id);


    print_statistics();


    rte_ring_free(
        g_phy_ring);


    rte_eal_cleanup();


    printf("O-RAN DU DPDK application terminated\n");

    return EXIT_SUCCESS;
}
