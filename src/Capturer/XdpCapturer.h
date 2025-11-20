#pragma once

#include <cstdint>

#include <atomic>

// XDP headers
#if __has_include(<xdp/xsk.h>)
    #include <xdp/xsk.h>
#elif __has_include(<bpf/xsk.h>)
    #include <bpf/xsk.h>
#endif

#include <bpf/libbpf.h>

#include <linux/if_link.h>

#include "Resources/DpdkResourceManager.h"

namespace PacketReader
{

/**
 * @brief Packet metadata structure
 *
 * This structure is passed between the capture thread and worker threads
 * via DPDK ring buffer. It contains a pointer to the packet data in UMEM
 * and associated metadata.
 */
struct packet_metadata {
    uint8_t* data;       ///< Pointer to packet data in UMEM
    std::uint32_t length;     ///< Packet length in bytes
    std::uint64_t timestamp;  ///< TSC timestamp when packet was received
    std::uint64_t umem_addr;  ///< UMEM address for buffer recycling
} __rte_cache_aligned;

/**
 * @brief XDP packet capturer with DPDK integration
 *
 * This class implements a producer-consumer architecture for high-performance
 * packet capture:
 * - Producer thread: Captures packets via XDP and enqueues to DPDK ring
 * - Consumer threads: Dequeue packets from ring and process them
 *
 * Features:
 * - Universal NIC support via XDP generic mode
 * - DPDK hugepages for UMEM allocation
 * - Lock-free ring buffer for inter-thread communication
 * - Zero-copy capable (if NIC supports native XDP)
 * - Multi-core scaling with worker threads
 */
class XdpCapturer {
public:
    /**
     * @brief XDP operating mode
     */
    enum class XDPMode {
        GENERIC,   ///< Works with ANY NIC (XDP_FLAGS_SKB_MODE)
        NATIVE,    ///< Requires driver support (XDP_FLAGS_DRV_MODE)
        AUTO       ///< Try native, fallback to generic
    };

    /**
     * @brief Constructor
     * @param iface Network interface name (e.g., "eth0")
     * @param queue RX queue ID (default: 0)
     * @param mode XDP operating mode (default: AUTO)
     * @param zero_copy Enable zero-copy mode if supported (default: false)
     * @param workers Number of worker threads (default: 1)
     */
    XdpCapturer(const char* iface, std::uint32_t queue = 0,
                      XDPMode mode = XDPMode::AUTO, bool zero_copy = false,
                      std::uint32_t workers = 1);

    /**
     * @brief Destructor - automatically cleans up resources
     */
    ~XdpCapturer();

    // Delete copy constructor and assignment
    XdpCapturer(const XdpCapturer&) = delete;
    XdpCapturer& operator=(const XdpCapturer&) = delete;

    /**
     * @brief Initialize DPDK EAL and resources
     * @param argc Argument count from main()
     * @param argv Argument vector from main()
     * @return true if successful, false otherwise
     */
    bool init_dpdk(int argc, char** argv);

    /**
     * @brief Initialize XDP socket and UMEM
     * @return true if successful, false otherwise
     */
    bool initialize();

    /**
     * @brief Launch worker threads on available lcores
     *
     * Workers will continuously dequeue packets from the ring buffer
     * and process them. The actual processing logic should be implemented
     * in the worker_thread() function.
     */
    void launch_workers();

    /**
     * @brief Start packet capture (producer loop)
     *
     * This function runs the main capture loop on the current lcore.
     * It captures packets via XDP and enqueues metadata to the DPDK ring
     * for worker threads to process.
     *
     * This function blocks until force_quit is set (e.g., via signal handler).
     */
    void capture();

    /**
     * @brief Wait for all worker threads to finish
     */
    void wait_workers();

    /**
     * @brief Get capture statistics
     */
    struct {
        std::atomic<std::uint64_t> rx_packets;          ///< Total packets received
        std::atomic<std::uint64_t> rx_bytes;            ///< Total bytes received
        std::atomic<std::uint64_t> ring_full_drops;     ///< Packets dropped (ring full)
        std::atomic<std::uint64_t> processed_packets;   ///< Packets processed by workers
    } stats;

private:
    // XDP structures
    struct xsk_umem_info {
        xsk_ring_prod fq;            ///< Fill queue
        xsk_ring_cons cq;            ///< Completion queue
        xsk_umem* umem;              ///< UMEM handle
        void* buffer;                ///< UMEM buffer pointer
        size_t buffer_size;          ///< UMEM buffer size
        bool from_dpdk_hugepages;    ///< True if allocated from DPDK
    };

    struct xsk_socket_info {
        xsk_ring_cons rx;            ///< RX queue
        xsk_ring_prod tx;            ///< TX queue (unused for capture)
        xsk_umem_info* umem;         ///< Associated UMEM
        xsk_socket* xsk;             ///< XDP socket handle
        std::uint32_t outstanding_tx;     ///< Outstanding TX packets (unused)
    };

    // Configuration
    static constexpr std::uint32_t NUM_FRAMES = 4096;
    static constexpr std::uint32_t FRAME_SIZE = 2048;
    static constexpr std::uint32_t RX_BATCH_SIZE = 64;
    static constexpr std::uint32_t UMEM_SIZE = NUM_FRAMES * FRAME_SIZE;
    static constexpr std::uint32_t RING_SIZE = 2048;

    // Member variables
    const char* _interface;
    std::uint16_t _bind_flags;
    std::uint32_t _xdp_flags;
    std::uint32_t _queue_id;
    bool _use_zero_copy;
    std::uint32_t _num_workers;

    // DPDK Resource Manager reference
    std::shared_ptr<Resources::DPDKResourceManager> _dpdk_mgr;

    // XSK structures
    xsk_socket_info* _xsk_info;
    xsk_umem_info* _umem;

    // DPDK resources
    struct rte_ring* _packet_ring;
    struct rte_mempool* _metadata_pool;

    // Internal methods
    void* allocate_dpdk_hugepage_memory(size_t size);
    xsk_umem_info* allocate_umem();
    void populate_fill_ring(xsk_umem_info* umem);
    xsk_socket_info* create_xsk_socket(const char* iface, std::uint32_t queue_id);
    void cleanup();

    // Worker thread function (must be static for DPDK launch)
    static int worker_thread(void* arg);
};

} // namespace PacketReader