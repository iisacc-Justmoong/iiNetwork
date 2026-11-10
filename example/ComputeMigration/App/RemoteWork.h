#pragma once
#include <iiNetwork/Peer.h>
#include <iiSDKCore/Runtime/MigratingWork.h>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ii::compute_migration {
// Adapter calls and callbacks are confined to the Peer owner loop. The Peer
// and target Runtime must outlive the receiver and its accepted work.
using Authorize = std::function<bool(const ii::network::PeerInfo&)>;
[[nodiscard]] std::string hex_encode(std::span<const std::byte>);

class RemoteReceiver final {
public:
    [[nodiscard]] static ii::network::Result<std::unique_ptr<RemoteReceiver>> install(
        ii::network::Peer&,ii::runtime::Runtime&,std::vector<ii::runtime::MigrationProgram>,Authorize,
        std::size_t maximum_checkpoint=256u*1024u,std::size_t maximum_receipts=64);
    ~RemoteReceiver();
    RemoteReceiver(const RemoteReceiver&)=delete;
    RemoteReceiver& operator=(const RemoteReceiver&)=delete;
    [[nodiscard]] std::size_t receipts() const;
    [[nodiscard]] std::optional<ii::runtime::MigrationStatus> status(std::string_view id) const;
    [[nodiscard]] std::expected<std::vector<std::byte>,ii::runtime::MigrationError> result(std::string_view id) const;
    // Deleting a receipt also deletes its in-memory replay protection.
    [[nodiscard]] ii::network::Result<void> release(std::string_view id);
private:
    struct State;
    RemoteReceiver(ii::network::Peer&,std::shared_ptr<State>);
    ii::network::Peer* peer_;
    std::shared_ptr<State> state_;
};

// Owns the sender's checkpoint until the peer explicitly acknowledges it.
// A transport error after admission is ambiguous; retry with the same id or
// reconcile externally instead of resuming the checkpoint locally.
class RemoteTransfer final {
public:
    using Completion=std::function<void(ii::network::Result<bool>)>;
    RemoteTransfer(std::string id,ii::runtime::WorkCheckpoint);
    [[nodiscard]] ii::network::Result<void> offer(std::shared_ptr<ii::network::PeerConnection>,Completion);
    [[nodiscard]] bool accepted() const;
    [[nodiscard]] bool uncertain() const;
    [[nodiscard]] bool has_checkpoint() const;
    [[nodiscard]] ii::network::Result<ii::runtime::WorkCheckpoint> reclaim();
private:
    struct State;
    std::shared_ptr<State> state_;
};
} // namespace ii::compute_migration
