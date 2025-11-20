#pragma once

#include <cinttypes>

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <stdexcept>

#include <dpdk/rte_eal.h>
#include <dpdk/rte_lcore.h>
#include <dpdk/rte_malloc.h>
#include <dpdk/rte_mempool.h>
#include <dpdk/rte_ring.h>
#include <dpdk/rte_hash.h>
#include <dpdk/rte_jhash.h>
#include <dpdk/rte_cycles.h>
#include <dpdk/rte_memory.h>
#include <dpdk/rte_launch.h>
#include <dpdk/rte_ring_core.h>
#include <dpdk/rte_mbuf_core.h>

#include "Patterns/Singleton.h"

namespace Resources
{

/**
 * @brief RAII wrapper for DPDK resources
 *
 * This class provides a singleton interface to manage DPDK EAL and all
 * associated resources (mempools, rings, hash tables, memory allocations).
 * All resources are automatically cleaned up when the manager is destroyed.
 */
class DPDKResourceManager : public ::Utility::SingletonBase<DPDKResourceManager>
{
    friend ::Utility::SingletonBase<DPDKResourceManager>;

public:
    /**
     * @brief Ring buffer type for producer/consumer patterns
     */
    enum RingType {
        SINGLE_PRODUCER_SINGLE_CONSUMER,   ///< SP/SC - one producer, one consumer
        SINGLE_PRODUCER_MULTI_CONSUMER,    ///< SP/MC - one producer, multiple consumers
        MULTI_PRODUCER_SINGLE_CONSUMER,    ///< MP/SC - multiple producers, one consumer
        MULTI_PRODUCER_MULTI_CONSUMER      ///< MP/MC - multiple producers, multiple consumers
    };

    // ============================================================
    // INITIALIZATION
    // ============================================================

    /**
     * @brief Initialize DPDK EAL
     * @param argc Argument count from main()
     * @param argv Argument vector from main()
     * @return true if successful, false otherwise
     */
    bool initialize(int argc, char** argv);

    /**
     * @brief Print current DPDK configuration
     */
    void printConfiguration() const;

    /**
     * @brief Check if DPDK is initialized
     * @return true if initialized, false otherwise
     */
    bool isInitialized() const { return initialized_; }

    // ============================================================
    // MEMPOOL MANAGEMENT
    // ============================================================

    /**
     * @brief Create a generic mempool
     * @param name Unique name for the mempool
     * @param n_elements Number of elements in the pool
     * @param element_size Size of each element in bytes
     * @param cache_size Per-lcore cache size (default: 256)
     * @param socket_id NUMA socket ID (-1 for current socket)
     * @return Pointer to created mempool
     * @throws std::runtime_error if creation fails
     */
    struct rte_mempool* createMempool(
        const std::string& name,
        unsigned n_elements,
        unsigned element_size,
        unsigned cache_size = 256,
        int socket_id = -1
    );

    /**
     * @brief Create a packet buffer mempool
     * @param name Unique name for the mempool
     * @param n_mbufs Number of mbufs in the pool (default: 8192)
     * @param cache_size Per-lcore cache size (default: 256)
     * @param data_room_size Size of data room in each mbuf
     * @param socket_id NUMA socket ID (-1 for current socket)
     * @return Pointer to created mempool
     * @throws std::runtime_error if creation fails
     */
    struct rte_mempool* createPacketMempool(
        const std::string& name,
        unsigned n_mbufs = 8192,
        unsigned cache_size = 256,
        uint16_t data_room_size = RTE_MBUF_DEFAULT_BUF_SIZE,
        int socket_id = -1
    );

    /**
     * @brief Get an existing mempool by name
     * @param name Name of the mempool
     * @return Pointer to mempool or nullptr if not found
     */
    struct rte_mempool* getMempool(const std::string& name);

    // ============================================================
    // RING BUFFER MANAGEMENT
    // ============================================================

    /**
     * @brief Create a ring buffer
     * @param name Unique name for the ring
     * @param size Number of elements (must be power of 2)
     * @param type Producer/consumer type (default: SP/MC)
     * @param socket_id NUMA socket ID (-1 for current socket)
     * @return Pointer to created ring
     * @throws std::runtime_error if creation fails
     */
    struct rte_ring* createRing(
        const std::string& name,
        unsigned size,
        RingType type = SINGLE_PRODUCER_MULTI_CONSUMER,
        int socket_id = -1
    );

    /**
     * @brief Get an existing ring by name
     * @param name Name of the ring
     * @return Pointer to ring or nullptr if not found
     */
    struct rte_ring* getRing(const std::string& name);

    // ============================================================
    // HASH TABLE MANAGEMENT
    // ============================================================

    /**
     * @brief Create a hash table
     * @param name Unique name for the hash table
     * @param max_entries Maximum number of entries
     * @param key_size Size of the key in bytes
     * @param hash_func Hash function (default: rte_jhash)
     * @param socket_id NUMA socket ID (-1 for current socket)
     * @return Pointer to created hash table
     * @throws std::runtime_error if creation fails
     */
    struct rte_hash* createHashTable(
        const std::string& name,
        uint32_t max_entries,
        uint32_t key_size,
        rte_hash_function hash_func = rte_jhash,
        int socket_id = -1
    );

    /**
     * @brief Get an existing hash table by name
     * @param name Name of the hash table
     * @return Pointer to hash table or nullptr if not found
     */
    struct rte_hash* getHashTable(const std::string& name);

    // ============================================================
    // MEMORY ALLOCATION
    // ============================================================

    /**
     * @brief Allocate memory from DPDK hugepages
     * @param type Type name for debugging
     * @param size Size in bytes
     * @param align Alignment (0 for cache line alignment)
     * @return Pointer to allocated memory
     * @throws std::runtime_error if allocation fails
     */
    void* malloc(const std::string& type, size_t size, unsigned align = 0);

    /**
     * @brief Allocate memory from specific NUMA socket
     * @param type Type name for debugging
     * @param size Size in bytes
     * @param align Alignment
     * @param socket_id NUMA socket ID
     * @return Pointer to allocated memory
     * @throws std::runtime_error if allocation fails
     */
    void* mallocSocket(const std::string& type, size_t size,
                      unsigned align, int socket_id);

    /**
     * @brief Free memory allocated by malloc/mallocSocket
     * @param ptr Pointer to memory to free
     */
    void free(void* ptr);

    // ============================================================
    // LCORE MANAGEMENT
    // ============================================================

    /**
     * @brief Get the main lcore ID
     * @return Main lcore ID
     */
    unsigned getMainLcore() const { return main_lcore_; }

    /**
     * @brief Get total number of lcores
     * @return Number of lcores
     */
    unsigned getNumLcores() const { return num_lcores_; }

    /**
     * @brief Get current lcore ID
     * @return Current lcore ID
     */
    unsigned getCurrentLcore() const { return rte_lcore_id(); }

    /**
     * @brief Get current NUMA socket ID
     * @return Current socket ID
     */
    unsigned getCurrentSocket() const { return rte_socket_id(); }

    /**
     * @brief Get list of all worker lcores
     * @return Vector of worker lcore IDs
     */
    std::vector<unsigned> getWorkerLcores() const;

    /**
     * @brief Launch a worker function on a specific lcore
     * @param f Function to launch
     * @param arg Argument to pass to function
     * @param lcore_id Lcore to launch on
     * @return 0 on success, negative on error
     */
    int launchWorker(lcore_function_t* f, void* arg, unsigned lcore_id);

    /**
     * @brief Wait for all worker lcores to finish
     */
    void waitAllWorkers();

    // ============================================================
    // TIMING / PERFORMANCE
    // ============================================================

    /**
     * @brief Get TSC frequency in Hz
     * @return TSC frequency
     */
    uint64_t getTscHz() const { return tsc_hz_; }

    /**
     * @brief Get current TSC cycles
     * @return Current TSC value
     */
    uint64_t getTscCycles() const { return rte_get_tsc_cycles(); }

    /**
     * @brief Convert TSC cycles to seconds
     * @param cycles Number of cycles
     * @return Time in seconds
     */
    double cyclesToSeconds(uint64_t cycles) const;

    /**
     * @brief Convert seconds to TSC cycles
     * @param seconds Time in seconds
     * @return Number of cycles
     */
    uint64_t secondsToCycles(double seconds) const;

    // ============================================================
    // STATISTICS / DEBUGGING
    // ============================================================

    /**
     * @brief Print detailed memory statistics
     */
    void printMemoryStats() const;

    /**
     * @brief Print summary of all resources
     */
    void printResourceSummary() const;

    /**
     * @brief Cleanup all DPDK resources
     */
    void cleanup();

    /**
     * @brief Destructor - automatically cleans up all resources
     */
    ~DPDKResourceManager();

private:
    // Private constructor (singleton)
    DPDKResourceManager();

    // State
    bool initialized_;
    unsigned main_lcore_;
    unsigned num_lcores_;
    int socket_id_;
    uint64_t tsc_hz_;

    // Resource tracking
    std::unordered_map<std::string, struct rte_mempool*> mempools_;
    std::unordered_map<std::string, struct rte_ring*> rings_;
    std::unordered_map<std::string, struct rte_hash*> hash_tables_;

    struct AllocInfo {
        std::string type;
        size_t size;
    };
    std::unordered_map<void*, AllocInfo> allocations_;
};

// Helper macro for singleton access
#define DPDK_MGR DPDKResourceManager::getInstance()

// ============================================================
// USAGE EXAMPLE
// ============================================================

// void example_usage() {
//     // Get singleton instance
//     auto& dpdk = DPDKResourceManager::getInstance();

//     // Initialize (only once per process)
//     // dpdk.initialize(argc, argv);

//     // Create resources
//     auto packet_pool = dpdk.createPacketMempool("packet_pool", 8192);
//     auto metadata_pool = dpdk.createMempool("metadata_pool", 4096, 128);
//     auto packet_ring = dpdk.createRing("packet_ring", 2048,
//                                        DPDKResourceManager::SINGLE_PRODUCER_MULTI_CONSUMER);
//     auto flow_table = dpdk.createHashTable("flow_table", 1000000, sizeof(uint64_t));

//     // Allocate memory
//     void* buffer = dpdk.malloc("packet_buffer", 2048);

//     // Get resources by name
//     auto ring = dpdk.getRing("packet_ring");
//     auto pool = dpdk.getMempool("metadata_pool");

//     // Print statistics
//     dpdk.printMemoryStats();
//     dpdk.printResourceSummary();

//     // Launch workers
//     auto workers = dpdk.getWorkerLcores();
//     for (auto lcore : workers) {
//         // dpdk.launchWorker(worker_func, arg, lcore);
//     }

//     // Wait for workers
//     dpdk.waitAllWorkers();

//     // Cleanup happens automatically in destructor
// }

} // namespace Resources