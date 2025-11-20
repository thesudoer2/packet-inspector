#include "XdpCapturer.h"
#include "XdpCapturer.h"
#include <atomic>
#include <dpdk/rte_build_config.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

namespace PacketReader
{

// External global flag for graceful shutdown
extern std::atomic<bool> force_quit;

// ============================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================

XdpCapturer::XdpCapturer(const char* iface, std::uint32_t queue,
                  XDPMode mode, bool zero_copy, std::uint32_t workers)
    : _interface(iface), _queue_id(queue), _use_zero_copy(zero_copy),
      _num_workers(workers), _dpdk_mgr(Resources::DPDKResourceManager::getInstance()),
      _xsk_info(nullptr), _umem(nullptr),
      _packet_ring(nullptr), _metadata_pool(nullptr) {

    stats.rx_packets = 0;
    stats.rx_bytes = 0;
    stats.ring_full_drops = 0;
    stats.processed_packets = 0;

    _xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

    if (mode == XDPMode::GENERIC) {
        _xdp_flags |= XDP_FLAGS_SKB_MODE;
        if (zero_copy) {
            std::cout << "Warning: Zero-copy not supported in GENERIC mode" << std::endl;
            _use_zero_copy = false;
        }
    } else if (mode == XDPMode::NATIVE) {
        _xdp_flags |= XDP_FLAGS_DRV_MODE;
    }

    _bind_flags = XDP_USE_NEED_WAKEUP;
    if (_use_zero_copy) {
        _bind_flags |= XDP_ZEROCOPY;
    } else {
        _bind_flags |= XDP_COPY;
    }
}

XdpCapturer::~XdpCapturer() {
    cleanup();
}

// ============================================================
// DPDK INITIALIZATION
// ============================================================

bool XdpCapturer::init_dpdk(int argc, char** argv) {
    // Initialize DPDK using resource manager
    if (!_dpdk_mgr->initialize(argc, argv)) {
        return false;
    }

    // Validate worker count
    if (_num_workers >= _dpdk_mgr->getNumLcores()) {
        std::cerr << "Error: Not enough lcores. Need " << (_num_workers + 1)
                 << " (1 for RX + " << _num_workers << " workers)" << std::endl;
        return false;
    }

    // Create DPDK ring for packet passing
    try {
        _packet_ring = _dpdk_mgr->createRing(
            "packet_ring",
            RING_SIZE,
            Resources::DPDKResourceManager::SINGLE_PRODUCER_MULTI_CONSUMER
        );
    } catch (const std::exception& e) {
        std::cerr << "Failed to create ring: " << e.what() << std::endl;
        return false;
    }

    // Create mempool for packet metadata
    try {
        _metadata_pool = _dpdk_mgr->createMempool(
            "metadata_pool",
            RING_SIZE * 2,
            sizeof(packet_metadata),
            256
        );
    } catch (const std::exception& e) {
        std::cerr << "Failed to create metadata pool: " << e.what() << std::endl;
        return false;
    }

    return true;
}

// ============================================================
// UMEM ALLOCATION
// ============================================================

void* XdpCapturer::allocate_dpdk_hugepage_memory(size_t size) {
    std::cout << "Allocating UMEM from DPDK hugepages..." << std::endl;

    try {
        void* buffer = _dpdk_mgr->mallocSocket(
            "xdp_umem",
            size,
            RTE_CACHE_LINE_SIZE,
            _dpdk_mgr->getCurrentSocket()
        );

        std::cout << "✓ Allocated " << (size >> 20) << "MB from DPDK hugepages" << std::endl;
        std::cout << "  Address: " << buffer << std::endl;
        std::cout << "  NUMA socket: " << _dpdk_mgr->getCurrentSocket() << std::endl;

        memset(buffer, 0, size);
        return buffer;

    } catch (const std::exception& e) {
        std::cerr << "Failed to allocate from DPDK: " << e.what() << std::endl;
        return nullptr;
    }
}

XdpCapturer::xsk_umem_info* XdpCapturer::allocate_umem() {
    xsk_umem_info* umem = new xsk_umem_info();
    umem->buffer = nullptr;
    umem->buffer_size = UMEM_SIZE;
    umem->from_dpdk_hugepages = false;

    if (_dpdk_mgr->isInitialized()) {
        umem->buffer = allocate_dpdk_hugepage_memory(UMEM_SIZE);
        if (umem->buffer) {
            umem->from_dpdk_hugepages = true;
        }
    }

    if (!umem->buffer) {
        std::cout << "Falling back to posix_memalign allocation" << std::endl;
        if (posix_memalign(&umem->buffer, getpagesize(), UMEM_SIZE)) {
            std::cerr << "Failed to allocate UMEM buffer" << std::endl;
            delete umem;
            return nullptr;
        }
    }

    xsk_umem_config cfg = {
        .fill_size = NUM_FRAMES / 2,
        .comp_size = NUM_FRAMES / 2,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XDP_PACKET_HEADROOM,
        .flags = 0
    };

    int ret = xsk_umem__create(&umem->umem, umem->buffer, UMEM_SIZE,
                               &umem->fq, &umem->cq, &cfg);
    if (ret) {
        std::cerr << "Failed to create UMEM: " << strerror(-ret) << std::endl;
        if (umem->from_dpdk_hugepages) {
            _dpdk_mgr->free(umem->buffer);
        } else {
            free(umem->buffer);
        }
        delete umem;
        return nullptr;
    }

    return umem;
}

void XdpCapturer::populate_fill_ring(xsk_umem_info* umem) {
    std::uint32_t idx;
    int ret = xsk_ring_prod__reserve(&umem->fq, NUM_FRAMES / 2, &idx);
    if (ret != NUM_FRAMES / 2) {
        std::cerr << "Failed to reserve fill ring" << std::endl;
        return;
    }

    for (std::uint32_t i = 0; i < NUM_FRAMES / 2; i++) {
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * FRAME_SIZE;
    }

    xsk_ring_prod__submit(&umem->fq, NUM_FRAMES / 2);
}

// ============================================================
// XDP SOCKET CREATION
// ============================================================

XdpCapturer::xsk_socket_info* XdpCapturer::create_xsk_socket(
    const char* iface, std::uint32_t queue_id) {

    xsk_socket_info* xsk_info = new xsk_socket_info();
    xsk_info->umem = _umem;

    xsk_socket_config cfg = {
        .rx_size = NUM_FRAMES / 2,
        .tx_size = NUM_FRAMES / 2,
        .libbpf_flags = 0,
        .xdp_flags = _xdp_flags,
        .bind_flags = _bind_flags
    };

    std::cout << "\nCreating XDP socket on " << iface << " queue " << queue_id << std::endl;
    std::cout << "  Mode: ";
    if (_xdp_flags & XDP_FLAGS_SKB_MODE) {
        std::cout << "GENERIC";
    } else if (_xdp_flags & XDP_FLAGS_DRV_MODE) {
        std::cout << "NATIVE";
    } else {
        std::cout << "AUTO";
    }

    if (_bind_flags & XDP_ZEROCOPY) {
        std::cout << " + ZERO-COPY";
    }
    std::cout << std::endl;

    int ret = xsk_socket__create(&xsk_info->xsk, iface, queue_id,
                                 _umem->umem, &xsk_info->rx,
                                 &xsk_info->tx, &cfg);
    if (ret) {
        std::cerr << "Failed to create XSK socket: " << strerror(-ret) << std::endl;
        delete xsk_info;
        return nullptr;
    }

    // Check if zero-copy succeeded
    // int actual_bind_flags = xsk_socket__get_bind_flags(xsk_info->xsk);
    // if (_use_zero_copy) {
    //     if (actual_bind_flags & XDP_ZEROCOPY) {
    //         std::cout << "✓ ZERO-COPY enabled!" << std::endl;
    //     } else {
    //         std::cout << "⚠ Zero-copy fallback to copy mode" << std::endl;
    //     }
    // }

    xsk_info->outstanding_tx = 0;
    return xsk_info;
}

// ============================================================
// INITIALIZATION
// ============================================================

bool XdpCapturer::initialize() {
    std::cout << "\n=== Initializing XDP Capturer ===" << std::endl;

    _umem = allocate_umem();
    if (!_umem) {
        return false;
    }

    populate_fill_ring(_umem);

    _xsk_info = create_xsk_socket(_interface, _queue_id);
    if (!_xsk_info) {
        return false;
    }

    std::cout << "\n✓ XDP socket initialized successfully" << std::endl;
    return true;
}

// ============================================================
// WORKER THREAD
// ============================================================

int XdpCapturer::worker_thread(void* arg) {
    XdpCapturer* capturer = (XdpCapturer*)arg;
    unsigned lcore_id = rte_lcore_id();
    unsigned socket_id = rte_socket_id();

    std::cout << "Worker thread started on lcore " << lcore_id
              << " (socket " << socket_id << ")" << std::endl;

    std::uint64_t processed = 0;
    std::uint64_t last_print = 0;

    // Batch processing
    packet_metadata* pkts[32];

    while (!force_quit) {
        // Dequeue batch of packets from ring
        unsigned nb_rx = rte_ring_dequeue_burst(
            capturer->_packet_ring,
            (void**)pkts,
            32,
            nullptr
        );

        if (nb_rx == 0) {
            rte_pause();
            continue;
        }

        // Process each packet
        for (unsigned i = 0; i < nb_rx; i++) {
            packet_metadata* pkt = pkts[i];

            // ============================================
            // YOUR PROCESSING HERE
            // ============================================
            // Example: Parse Ethernet header
            if (pkt->length >= 14) {
                // Access packet data
                std::uint8_t* eth_hdr = pkt->data;

                // Example: Extract MAC addresses, EtherType, etc.
                // Add your detunneling/dissection here
                (void)eth_hdr; // Suppress unused warning
            }
            // ============================================

            processed++;

            // Return metadata to pool
            rte_mempool_put(capturer->_metadata_pool, pkt);
        }

        capturer->stats.processed_packets += nb_rx;

        // Print stats every 1M packets
        if (processed - last_print >= 1000000) {
            std::cout << "[Lcore " << lcore_id << "] Processed "
                     << processed << " packets" << std::endl;
            last_print = processed;
        }
    }

    std::cout << "Worker thread on lcore " << lcore_id
              << " finished (processed " << processed << " packets)" << std::endl;
    return 0;
}

// ============================================================
// LAUNCH WORKERS
// ============================================================

void XdpCapturer::launch_workers() {
    std::cout << "\n=== Launching Worker Threads ===" << std::endl;

    auto workers = _dpdk_mgr->getWorkerLcores();
    unsigned workers_launched = 0;

    for (auto lcore_id : workers) {
        if (workers_launched >= _num_workers) {
            break;
        }

        std::cout << "Launching worker " << workers_launched
                 << " on lcore " << lcore_id << std::endl;
        _dpdk_mgr->launchWorker(worker_thread, this, lcore_id);
        workers_launched++;
    }

    if (workers_launched < _num_workers) {
        std::cerr << "Warning: Only launched " << workers_launched
                 << " workers (requested " << _num_workers << ")" << std::endl;
    }

    std::cout << "✓ " << workers_launched << " worker(s) launched\n" << std::endl;
}

// ============================================================
// CAPTURE (PRODUCER)
// ============================================================

void XdpCapturer::capture() {
    std::uint32_t idx_rx = 0, idx_fq = 0;
    int rcvd;

    struct pollfd fds[1];
    fds[0].fd = xsk_socket__fd(_xsk_info->xsk);
    fds[0].events = POLLIN;

    std::cout << "=== Capture Thread Started (Producer) ===" << std::endl;
    std::cout << "Lcore: " << _dpdk_mgr->getCurrentLcore() << std::endl;
    std::cout << "Workers: " << _num_workers << std::endl;
    std::cout << "Ring size: " << RING_SIZE << " slots" << std::endl;
    std::cout << "Press Ctrl+C to stop\n" << std::endl;

    std::uint64_t start_tsc = _dpdk_mgr->getTscCycles();
    std::uint64_t last_stats_tsc = start_tsc;
    std::uint64_t tsc_hz = _dpdk_mgr->getTscHz();

    packet_metadata* metadata_batch[RX_BATCH_SIZE];

    while (!force_quit) {
        // Check if kernel needs wakeup
        if (xsk_ring_prod__needs_wakeup(&_xsk_info->umem->fq)) {
            recvfrom(xsk_socket__fd(_xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }

        // Poll for packets
        int ret = poll(fds, 1, 100);
        if (ret <= 0) {
            continue;
        }

        // Receive packets from XDP
        rcvd = xsk_ring_cons__peek(&_xsk_info->rx, RX_BATCH_SIZE, &idx_rx);
        if (!rcvd) {
            continue;
        }

        // Allocate metadata structures
        if (rte_mempool_get_bulk(_metadata_pool, (void**)metadata_batch, rcvd) < 0) {
            xsk_ring_cons__release(&_xsk_info->rx, rcvd);
            std::ignore = std::atomic_fetch_add(&stats.ring_full_drops, rcvd);
            continue;
        }

        // Reserve space in fill queue
        int ret_fq = xsk_ring_prod__reserve(&_xsk_info->umem->fq, rcvd, &idx_fq);

        // Fill metadata and enqueue to ring
        for (int i = 0; i < rcvd; i++) {
            const xdp_desc* desc = xsk_ring_cons__rx_desc(&_xsk_info->rx, idx_rx++);
            std::uint64_t addr = desc->addr;
            std::uint32_t len = desc->len;

            std::uint8_t* pkt = (std::uint8_t*)xsk_umem__get_data(_xsk_info->umem->buffer, addr);

            packet_metadata* meta = metadata_batch[i];
            meta->data = pkt;
            meta->length = len;
            meta->timestamp = _dpdk_mgr->getTscCycles();
            meta->umem_addr = addr;

            stats.rx_packets++;
            stats.rx_bytes += len;
        }

        // Enqueue to ring
        unsigned enqueued = rte_ring_enqueue_burst(
            _packet_ring,
            (void**)metadata_batch,
            rcvd,
            nullptr
        );

        if (enqueued < (unsigned)rcvd) {
            rte_mempool_put_bulk(_metadata_pool,
                                (void**)&metadata_batch[enqueued],
                                rcvd - enqueued);
            stats.ring_full_drops += (rcvd - enqueued);
        }

        xsk_ring_cons__release(&_xsk_info->rx, rcvd);

        if (ret_fq == rcvd) {
            for (int i = 0; i < rcvd; i++) {
                *xsk_ring_prod__fill_addr(&_xsk_info->umem->fq, idx_fq++) =
                    metadata_batch[i]->umem_addr;
            }
            xsk_ring_prod__submit(&_xsk_info->umem->fq, rcvd);
        }

        // Print statistics every second
        std::uint64_t current_tsc = _dpdk_mgr->getTscCycles();
        if (current_tsc - last_stats_tsc >= tsc_hz) {
            double elapsed = _dpdk_mgr->cyclesToSeconds(current_tsc - start_tsc);
            std::uint64_t rx_pkts = stats.rx_packets.load();
            std::uint64_t rx_bytes = stats.rx_bytes.load();
            std::uint64_t proc_pkts = stats.processed_packets.load();
            std::uint64_t drops = stats.ring_full_drops.load();

            double pps = rx_pkts / elapsed;
            double mbps = (rx_bytes * 8.0) / (elapsed * 1000000.0);

            std::cout << "\r[RX] " << rx_pkts << " pkts | "
                     << (std::uint64_t)pps << " pps | "
                     << (std::uint64_t)mbps << " Mbps | "
                     << "[Workers] " << proc_pkts << " processed | "
                     << "[Drops] " << drops
                     << "     " << std::flush;

            last_stats_tsc = current_tsc;
        }
    }

    std::cout << "\n\n=== Capture Statistics ===" << std::endl;
    std::cout << "RX packets: " << stats.rx_packets.load() << std::endl;
    std::cout << "RX bytes: " << stats.rx_bytes.load() << std::endl;
    std::cout << "Processed packets: " << stats.processed_packets.load() << std::endl;
    std::cout << "Ring full drops: " << stats.ring_full_drops.load() << std::endl;
}

// ============================================================
// WAIT / CLEANUP
// ============================================================

void XdpCapturer::wait_workers() {
    std::cout << "\nWaiting for workers to finish..." << std::endl;
    _dpdk_mgr->waitAllWorkers();
    std::cout << "All workers stopped" << std::endl;
}

void XdpCapturer::cleanup() {
    if (_xsk_info) {
        if (_xsk_info->xsk) {
            xsk_socket__delete(_xsk_info->xsk);
        }
        delete _xsk_info;
        _xsk_info = nullptr;
    }

    if (_umem) {
        if (_umem->umem) {
            xsk_umem__delete(_umem->umem);
        }
        if (_umem->buffer) {
            if (_umem->from_dpdk_hugepages) {
                _dpdk_mgr->free(_umem->buffer);
            } else {
                free(_umem->buffer);
            }
        }
        delete _umem;
        _umem = nullptr;
    }

    // DPDK resources cleaned up automatically by DPDKResourceManager
    _packet_ring = nullptr;
    _metadata_pool = nullptr;
}

} // namespace PacketReader