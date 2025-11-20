#include "DpdkResourceManager.h"

#include <iostream>

#include <dpdk/rte_mbuf.h>
#include <dpdk/rte_errno.h>

namespace Resources
{

// ============================================================
// SINGLETON
// ============================================================

DPDKResourceManager::DPDKResourceManager()
    : initialized_(false), main_lcore_(0), num_lcores_(0),
      socket_id_(0), tsc_hz_(0) {
}

DPDKResourceManager::~DPDKResourceManager() {
    cleanup();
}

// ============================================================
// INITIALIZATION
// ============================================================

bool DPDKResourceManager::initialize(int argc, char** argv) {
    if (initialized_) {
        std::cerr << "DPDK already initialized" << std::endl;
        return true;
    }

    std::cout << "=== Initializing DPDK EAL ===" << std::endl;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        std::cerr << "Failed to initialize DPDK EAL: "
                 << rte_strerror(rte_errno) << std::endl;
        return false;
    }

    initialized_ = true;

    // Store configuration
    main_lcore_ = rte_get_main_lcore();
    num_lcores_ = rte_lcore_count();
    socket_id_ = rte_socket_id();
    tsc_hz_ = rte_get_tsc_hz();

    std::cout << "✓ DPDK EAL initialized successfully" << std::endl;
    printConfiguration();

    return true;
}

void DPDKResourceManager::printConfiguration() const {
    std::cout << "\n--- DPDK Configuration ---" << std::endl;
    std::cout << "Main lcore: " << main_lcore_ << std::endl;
    std::cout << "Total lcores: " << num_lcores_ << std::endl;
    std::cout << "Socket ID: " << socket_id_ << std::endl;
    std::cout << "TSC frequency: " << (tsc_hz_ / 1000000) << " MHz" << std::endl;

    std::cout << "Available lcores: ";
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        std::cout << lcore_id << " ";
    }
    std::cout << std::endl;

    std::cout << "Worker lcores: ";
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        std::cout << lcore_id << " ";
    }
    std::cout << std::endl;
    std::cout << "--------------------------\n" << std::endl;
}

// ============================================================
// MEMPOOL MANAGEMENT
// ============================================================

struct rte_mempool* DPDKResourceManager::createMempool(
    const std::string& name,
    unsigned n_elements,
    unsigned element_size,
    unsigned cache_size,
    int socket_id
) {
    if (!initialized_) {
        throw std::runtime_error("DPDK not initialized");
    }

    if (socket_id < 0) {
        socket_id = socket_id_;
    }

    // Check if already exists
    if (mempools_.find(name) != mempools_.end()) {
        std::cerr << "Mempool '" << name << "' already exists" << std::endl;
        return mempools_[name];
    }

    std::cout << "Creating mempool: " << name << std::endl;
    std::cout << "  Elements: " << n_elements << std::endl;
    std::cout << "  Element size: " << element_size << " bytes" << std::endl;
    std::cout << "  Cache size: " << cache_size << std::endl;
    std::cout << "  Socket: " << socket_id << std::endl;

    struct rte_mempool* pool = rte_mempool_create(
        name.c_str(),
        n_elements,
        element_size,
        cache_size,
        0,  // private data size
        nullptr, nullptr,  // no constructor
        nullptr, nullptr,  // no initializer
        socket_id,
        0  // flags
    );

    if (!pool) {
        throw std::runtime_error("Failed to create mempool: " +
                               std::string(rte_strerror(rte_errno)));
    }

    mempools_[name] = pool;

    std::cout << "✓ Mempool created" << std::endl;
    std::cout << "  Available: " << rte_mempool_avail_count(pool) << std::endl;
    std::cout << "  In-use: " << rte_mempool_in_use_count(pool) << std::endl;

    return pool;
}

struct rte_mempool* DPDKResourceManager::createPacketMempool(
    const std::string& name,
    unsigned n_mbufs,
    unsigned cache_size,
    uint16_t data_room_size,
    int socket_id
) {
    if (!initialized_) {
        throw std::runtime_error("DPDK not initialized");
    }

    if (socket_id < 0) {
        socket_id = socket_id_;
    }

    if (mempools_.find(name) != mempools_.end()) {
        std::cerr << "Mempool '" << name << "' already exists" << std::endl;
        return mempools_[name];
    }

    std::cout << "Creating packet mempool: " << name << std::endl;

    struct rte_mempool* pool = rte_pktmbuf_pool_create(
        name.c_str(),
        n_mbufs,
        cache_size,
        0,  // private data size
        data_room_size,
        socket_id
    );

    if (!pool) {
        throw std::runtime_error("Failed to create packet mempool: " +
                               std::string(rte_strerror(rte_errno)));
    }

    mempools_[name] = pool;
    std::cout << "✓ Packet mempool created" << std::endl;

    return pool;
}

struct rte_mempool* DPDKResourceManager::getMempool(const std::string& name) {
    auto it = mempools_.find(name);
    if (it == mempools_.end()) {
        return nullptr;
    }
    return it->second;
}

// ============================================================
// RING BUFFER MANAGEMENT
// ============================================================

struct rte_ring* DPDKResourceManager::createRing(
    const std::string& name,
    unsigned size,
    RingType type,
    int socket_id
) {
    if (!initialized_) {
        throw std::runtime_error("DPDK not initialized");
    }

    if (socket_id < 0) {
        socket_id = socket_id_;
    }

    // Check if already exists
    if (rings_.find(name) != rings_.end()) {
        std::cerr << "Ring '" << name << "' already exists" << std::endl;
        return rings_[name];
    }

    // Determine flags based on type
    unsigned flags = 0;
    std::string type_str;

    switch (type) {
        case SINGLE_PRODUCER_SINGLE_CONSUMER:
            flags = RING_F_SP_ENQ | RING_F_SC_DEQ;
            type_str = "SP/SC";
            break;
        case SINGLE_PRODUCER_MULTI_CONSUMER:
            flags = RING_F_SP_ENQ;
            type_str = "SP/MC";
            break;
        case MULTI_PRODUCER_SINGLE_CONSUMER:
            flags = RING_F_SC_DEQ;
            type_str = "MP/SC";
            break;
        case MULTI_PRODUCER_MULTI_CONSUMER:
            flags = 0;
            type_str = "MP/MC";
            break;
    }

    std::cout << "Creating ring: " << name << std::endl;
    std::cout << "  Size: " << size << " slots" << std::endl;
    std::cout << "  Type: " << type_str << std::endl;
    std::cout << "  Socket: " << socket_id << std::endl;

    struct rte_ring* ring = rte_ring_create(
        name.c_str(),
        size,
        socket_id,
        flags
    );

    if (!ring) {
        throw std::runtime_error("Failed to create ring: " +
                               std::string(rte_strerror(rte_errno)));
    }

    rings_[name] = ring;
    std::cout << "✓ Ring created (capacity: " << rte_ring_get_capacity(ring) << ")" << std::endl;

    return ring;
}

struct rte_ring* DPDKResourceManager::getRing(const std::string& name) {
    auto it = rings_.find(name);
    if (it == rings_.end()) {
        return nullptr;
    }
    return it->second;
}

// ============================================================
// HASH TABLE MANAGEMENT
// ============================================================

struct rte_hash* DPDKResourceManager::createHashTable(
    const std::string& name,
    uint32_t max_entries,
    uint32_t key_size,
    rte_hash_function hash_func,
    int socket_id
) {
    if (!initialized_) {
        throw std::runtime_error("DPDK not initialized");
    }

    if (socket_id < 0) {
        socket_id = socket_id_;
    }

    // Check if already exists
    if (hash_tables_.find(name) != hash_tables_.end()) {
        std::cerr << "Hash table '" << name << "' already exists" << std::endl;
        return hash_tables_[name];
    }

    std::cout << "Creating hash table: " << name << std::endl;
    std::cout << "  Max entries: " << max_entries << std::endl;
    std::cout << "  Key size: " << key_size << " bytes" << std::endl;
    std::cout << "  Socket: " << socket_id << std::endl;

    struct rte_hash_parameters params = {
        .name = name.c_str(),
        .entries = max_entries,
        .reserved = 0,
        .key_len = key_size,
        .hash_func = hash_func,
        .hash_func_init_val = 0,
        .socket_id = socket_id,
        .extra_flag = 0
    };

    struct rte_hash* hash = rte_hash_create(&params);

    if (!hash) {
        throw std::runtime_error("Failed to create hash table: " +
                               std::string(rte_strerror(rte_errno)));
    }

    hash_tables_[name] = hash;
    std::cout << "✓ Hash table created" << std::endl;

    return hash;
}

struct rte_hash* DPDKResourceManager::getHashTable(const std::string& name) {
    auto it = hash_tables_.find(name);
    if (it == hash_tables_.end()) {
        return nullptr;
    }
    return it->second;
}

// ============================================================
// MEMORY ALLOCATION
// ============================================================

void* DPDKResourceManager::malloc(const std::string& type, size_t size, unsigned align) {
    if (!initialized_) {
        throw std::runtime_error("DPDK not initialized");
    }

    if (align == 0) {
        align = RTE_CACHE_LINE_SIZE;
    }

    void* ptr = rte_malloc(type.c_str(), size, align);
    if (!ptr) {
        throw std::runtime_error("Failed to allocate memory: " +
                               std::string(rte_strerror(rte_errno)));
    }

    // Track allocation
    allocations_[ptr] = {type, size};

    return ptr;
}

void* DPDKResourceManager::mallocSocket(const std::string& type, size_t size,
                  unsigned align, int socket_id) {
    if (!initialized_) {
        throw std::runtime_error("DPDK not initialized");
    }

    if (align == 0) {
        align = RTE_CACHE_LINE_SIZE;
    }

    void* ptr = rte_malloc_socket(type.c_str(), size, align, socket_id);
    if (!ptr) {
        throw std::runtime_error("Failed to allocate memory on socket: " +
                               std::string(rte_strerror(rte_errno)));
    }

    allocations_[ptr] = {type, size};

    return ptr;
}

void DPDKResourceManager::free(void* ptr) {
    if (ptr) {
        allocations_.erase(ptr);
        rte_free(ptr);
    }
}

// ============================================================
// LCORE MANAGEMENT
// ============================================================

std::vector<unsigned> DPDKResourceManager::getWorkerLcores() const {
    std::vector<unsigned> workers;
    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        workers.push_back(lcore_id);
    }
    return workers;
}

int DPDKResourceManager::launchWorker(lcore_function_t* f, void* arg, unsigned lcore_id) {
    if (!initialized_) {
        throw std::runtime_error("DPDK not initialized");
    }

    return rte_eal_remote_launch(f, arg, lcore_id);
}

void DPDKResourceManager::waitAllWorkers() {
    if (initialized_) {
        rte_eal_mp_wait_lcore();
    }
}

// ============================================================
// TIMING / PERFORMANCE
// ============================================================

double DPDKResourceManager::cyclesToSeconds(uint64_t cycles) const {
    return (double)cycles / tsc_hz_;
}

uint64_t DPDKResourceManager::secondsToCycles(double seconds) const {
    return (uint64_t)(seconds * tsc_hz_);
}

// ============================================================
// STATISTICS / DEBUGGING
// ============================================================

void DPDKResourceManager::printMemoryStats() const {
    std::cout << "\n=== DPDK Memory Statistics ===" << std::endl;

    // Hugepage info
    std::cout << "\nHugepage usage:" << std::endl;
    rte_dump_physmem_layout(stdout);

    // Mempool stats
    std::cout << "\nMempools:" << std::endl;
    for (const auto& pair : mempools_) {
        auto pool = pair.second;
        std::cout << "  " << pair.first << ":" << std::endl;
        std::cout << "    Available: " << rte_mempool_avail_count(pool) << std::endl;
        std::cout << "    In-use: " << rte_mempool_in_use_count(pool) << std::endl;
    }

    // Ring stats
    std::cout << "\nRings:" << std::endl;
    for (const auto& pair : rings_) {
        auto ring = pair.second;
        std::cout << "  " << pair.first << ":" << std::endl;
        std::cout << "    Count: " << rte_ring_count(ring) << std::endl;
        std::cout << "    Free: " << rte_ring_free_count(ring) << std::endl;
        std::cout << "    Capacity: " << rte_ring_get_capacity(ring) << std::endl;
    }

    // Malloc stats
    std::cout << "\nDirect allocations: " << allocations_.size() << std::endl;

    std::cout << "==============================\n" << std::endl;
}

void DPDKResourceManager::printResourceSummary() const {
    std::cout << "\n=== DPDK Resource Summary ===" << std::endl;
    std::cout << "Mempools: " << mempools_.size() << std::endl;
    std::cout << "Rings: " << rings_.size() << std::endl;
    std::cout << "Hash tables: " << hash_tables_.size() << std::endl;
    std::cout << "Direct allocations: " << allocations_.size() << std::endl;
    std::cout << "==============================\n" << std::endl;
}

// ============================================================
// CLEANUP
// ============================================================

void DPDKResourceManager::cleanup() {
    if (!initialized_) {
        return;
    }

    std::cout << "\n=== Cleaning up DPDK resources ===" << std::endl;

    // Free hash tables
    for (auto& pair : hash_tables_) {
        std::cout << "Freeing hash table: " << pair.first << std::endl;
        rte_hash_free(pair.second);
    }
    hash_tables_.clear();

    // Free rings
    for (auto& pair : rings_) {
        std::cout << "Freeing ring: " << pair.first << std::endl;
        rte_ring_free(pair.second);
    }
    rings_.clear();

    // Free mempools
    for (auto& pair : mempools_) {
        std::cout << "Freeing mempool: " << pair.first << std::endl;
        rte_mempool_free(pair.second);
    }
    mempools_.clear();

    // Free direct allocations
    std::cout << "Freeing " << allocations_.size() << " direct allocations" << std::endl;
    for (auto& pair : allocations_) {
        rte_free(pair.first);
    }
    allocations_.clear();

    // Cleanup EAL
    std::cout << "Cleaning up EAL" << std::endl;
    rte_eal_cleanup();

    initialized_ = false;
    std::cout << "✓ DPDK cleanup complete\n" << std::endl;
}

} // namespace Resources