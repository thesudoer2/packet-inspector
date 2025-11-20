#pragma once

#include <memory>

namespace Utility {

/**
 * @class SingletonBase
 * @brief Thread-safe read-only singleton base for globally shared instances.
 *
 * This template provides a simple singleton pattern using `std::shared_ptr<T>`.
 * It is intended for scenarios where:
 * - The singleton instance is constructed exactly once (typically by the main thread).
 * - Other threads only *read* or *use* the already-created instance.
 *
 * @tparam T The derived class type (CRTP-style).
 *
 * @par Thread Safety
 * - Construction (`construct()`) must be called once, typically at program startup.
 * - After initialization, concurrent calls to `getInstance()` are thread-safe
 *   because `std::shared_ptr` provides thread-safe reference counting for reads.
 * - This implementation does **not** provide thread-safe lazy initialization.
 *
 * @code
 * // Example usage:
 * class ConfigManager : public Utility::SingletonBase<ConfigManager>
 * {
 * public:
 *     void load(const std::string& path);
 * };
 *
 * int main() {
 *     // Initialize singleton once in main thread
 *     auto config = ConfigManager::construct();
 *     config->load("config.json");
 *
 *     // Later in worker threads:
 *     auto cfg = ConfigManager::getInstance();
 *     cfg->use_configuration();
 * }
 * @endcode
 */
template<typename T>
class SingletonBase
{
public:
    /**
     * @brief Constructs the singleton instance.
     *
     * This should be called exactly once, typically from the main thread at startup.
     * Creates a new shared instance of `T` using the provided constructor arguments.
     * If an instance already exists, it will be replaced.
     *
     * @tparam Args Variadic template arguments forwarded to `T`'s constructor.
     * @param args Arguments used to construct the singleton instance.
     * @return A shared pointer to the created instance.
     */
    template<typename... Args>
    static std::shared_ptr<T> construct(Args&&... args)
    {
        _instance = std::shared_ptr<T>(new T(std::forward<Args>(args)...));
        return _instance;
    }

    /**
     * @brief Retrieves the singleton instance.
     *
     * Returns the previously constructed instance of `T`.
     * If `construct()` has not been called, this will return `nullptr`.
     *
     * @return A shared pointer to the singleton instance, or `nullptr` if not constructed.
     */
    static std::shared_ptr<T> getInstance()
    {
        return _instance;
    }

protected:
    SingletonBase() = default;
    virtual ~SingletonBase() = default;

private:
    SingletonBase(const SingletonBase&) = delete;
    SingletonBase& operator=(const SingletonBase&) = delete;

private:
    /// @brief Shared pointer holding the singleton instance.
    static std::shared_ptr<T> _instance;
};

template<typename T>
std::shared_ptr<T> SingletonBase<T>::_instance = nullptr;

} // namespace Utility
