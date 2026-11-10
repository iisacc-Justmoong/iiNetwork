#include <iiNetwork/Peer.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace ii::network;
using namespace std::chrono_literals;
namespace {
void check(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
std::string frame(std::string body) {
    const auto n=static_cast<std::uint32_t>(body.size());
    std::string result{char(n>>24),char(n>>16),char(n>>8),char(n)};
    return result+body;
}
class MemoryStream final : public ByteStream {
public:
    std::string incoming,output;
    bool opened=true;
    bool write(std::string_view bytes) override { output.append(bytes); return opened; }
    std::string read() override { return std::exchange(incoming,{}); }
    std::string read_some(std::size_t count) override {
        count=std::min(count,incoming.size()); auto value=incoming.substr(0,count); incoming.erase(0,count); return value;
    }
    std::string peek(std::size_t maximum) const override { return incoming.substr(0,maximum); }
    std::size_t available_bytes() const override { return incoming.size(); }
    std::size_t pending_bytes() const override { return 0; }
    void receive_limit(std::size_t) override {}
    void send_limit(std::size_t) override {}
    void close(bool=false) override { opened=false; }
    bool is_connected() const override { return opened; }
    SocketState state() const override { return opened ? SocketState::connected : SocketState::closed; }
    std::string error() const override { return {}; }
    StreamStatistics statistics() const override { return {}; }
    void inject(std::string data) { incoming+=std::move(data); if(readable) readable(); }
};
}
int main() {
    try {
        ii::runtime::EventLoop loop;
        Peer peer(loop,"local");
        auto stream=std::make_unique<MemoryStream>(); auto* raw=stream.get();
        auto connection=peer.attach(std::move(stream));
        check(bool(connection),"peer admission failed");
        std::this_thread::sleep_for(10ms); loop.poll();
        check(!raw->output.empty(),"initial hello was not sent");
        raw->inject(frame(R"({"type":"hello","version":1,"identity":"remote","session":"00000000-0000-4000-8000-000000000001","maximum_frame":4096})"));
        check((*connection)->state()==PeerState::ready,"peer negotiation failed");
        loop.poll(); const auto before=loop.stats().executed;
        std::this_thread::sleep_for(40ms); loop.poll();
        check(loop.stats().executed==before,"idle peer continued to poll");
        unsigned delivered=0;
        (*connection)->received=[&](PeerEvent) { ++delivered; };
        std::string batch;
        for(int i=0;i<130;++i) batch+=frame(R"({"type":"event","topic":"changed","value":1})");
        raw->inject(std::move(batch));
        for(int i=0;i<4 && delivered<130;++i) loop.poll();
        check(delivered==130,"buffered frames did not schedule continuations");
        bool expired=false;
        auto call=(*connection)->request("work",ii::core::Value{},[&](auto result) {
            expired=!result && result.error().code==ErrorCode::expired;
        },30ms);
        check(bool(call),"deadline request was not admitted");
        std::this_thread::sleep_for(40ms); loop.poll();
        check(expired,"request deadline was not delivered");
        ii::runtime::EventLoop tls_loop;
        TlsOptions tls_options; tls_options.policy.trusted_certificate_sha256=std::array<unsigned char,32>{};
        auto context=TlsContext::client(tls_options);
        check(bool(context),"TLS context was not created");
        TlsStreamOptions limits; limits.handshake_timeout=2s;
        TlsStream tls(tls_loop,*context,limits);
        auto transport=std::make_unique<MemoryStream>(); auto* endpoint=transport.get();
        check(bool(tls.attach(std::move(transport),"example.test")),"TLS transport was not admitted");
        std::this_thread::sleep_for(10ms); tls_loop.poll();
        check(!endpoint->output.empty(),"TLS handshake did not start");
        const auto tls_before=tls_loop.stats().executed;
        std::this_thread::sleep_for(40ms); tls_loop.poll();
        check(tls_loop.stats().executed==tls_before,"idle TLS continued to poll");
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
