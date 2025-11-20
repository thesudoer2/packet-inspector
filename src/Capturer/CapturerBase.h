#pragma once

#include <cinttypes>

namespace PacketReader
{

/**
 * @class NetworkCapturer
 * @brief Abstract interface for capturing network packets.
 *
 * This class defines the interface for network packet capturing components.
 * Derived classes must implement the initialization and packet capture logic.
 */
class NetworkCapturer
{
public:
    /**
     * @brief Type alias for the packet callback function.
     *
     * The callback is invoked for each captured packet.
     *
     * @param data Pointer to the raw packet data buffer.
     * @param len  Length of the captured packet in bytes.
     * @param context User-defined pointer passed through the capture call.
     */
    using PacketCallback = void(*)(const std::uint8_t* data, std::uint32_t len, void* context);

public:
    /// @brief Virtual destructor.
    virtual ~NetworkCapturer() = default;

    /**
     * @brief Initializes resources required for packet capture.
     *
     * This function should prepare the capture environment, such as opening
     * network interfaces or setting up internal buffers.
     *
     * @return `true` if initialization succeeds, otherwise `false`.
     */
    virtual bool initialize() noexcept = 0;

    /**
     * @brief Starts capturing network packets.
     *
     * This function enters a loop that continuously captures packets and
     * invokes the specified callback for each received packet.
     *
     * @param callback Function pointer called for every captured packet.
     * @param user_data User-defined pointer passed to the callback function.
     */
    virtual void capture(PacketCallback callback, void* user_data) noexcept = 0;
};

} // namespace PacketReader