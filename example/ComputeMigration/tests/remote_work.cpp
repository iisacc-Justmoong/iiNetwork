#include "RemoteWork.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace ii::runtime;
using namespace ii::network;
using namespace ii::compute_migration;
using namespace std::chrono_literals;
namespace {
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class T>T take(ii::network::Result<T> value){if(!value)throw std::runtime_error(value.error().message);return std::move(*value);}
template<class P>void until(EventLoop& loop,P predicate){const auto deadline=Clock::now()+5s;while(!predicate()&&Clock::now()<deadline){loop.poll();std::this_thread::sleep_for(1ms);}check(predicate(),"network transfer timed out");}
struct Gate final {std::mutex mutex;std::condition_variable cv;bool started=false,open=false;
    void run(){std::unique_lock lock(mutex);started=true;cv.notify_all();if(!cv.wait_for(lock,5s,[&]{return open;}))throw std::runtime_error("gate timeout");}
    void wait(){std::unique_lock lock(mutex);if(!cv.wait_for(lock,5s,[&]{return started;}))throw std::runtime_error("step did not start");}
    void release(){std::lock_guard lock(mutex);open=true;cv.notify_all();}
};
class AmbiguousStream final:public ByteStream {
public:
    std::string incoming,output;bool opened=true,fail_write=false,throw_next_write=false;
    bool write(std::string_view value) override {
        output.append(value);
        if(std::exchange(throw_next_write,false))throw std::runtime_error("injected response write exception");
        return opened&&!fail_write;
    }
    std::string read() override{return std::exchange(incoming,{});}
    std::string read_some(std::size_t n) override{n=std::min(n,incoming.size());auto value=incoming.substr(0,n);incoming.erase(0,n);return value;}
    std::string peek(std::size_t n) const override{return incoming.substr(0,n);}
    std::size_t available_bytes() const override{return incoming.size();}
    std::size_t pending_bytes() const override{return 0;}
    void receive_limit(std::size_t) override{} void send_limit(std::size_t) override{}
    void close(bool=false) override{opened=false;}
    bool is_connected() const override{return opened;}
    SocketState state() const override{return opened?SocketState::connected:SocketState::closed;}
    std::string error() const override{return {};}
    StreamStatistics statistics() const override{return {};}
    void inject(std::string value){incoming+=std::move(value);if(readable)readable();}
};
std::string frame(std::string body){const auto n=static_cast<std::uint32_t>(body.size());return std::string{char(n>>24),char(n>>16),char(n>>8),char(n)}+body;}
std::vector<std::byte> one(unsigned value){return {std::byte(value)};}
WorkCheckpoint checkpoint(Runtime& runtime,unsigned value){
    Gate gate;MigrationProgram program{"count",1,[&](std::span<const std::byte> input){gate.run();return MigrationStep{one(unsigned(input[0])+1),false};}};
    auto work=MigratingWork::start(runtime,std::move(program),one(value)).value();gate.wait();check(bool(work.pause()),"pause request");gate.release();
    check(work.wait(5s)->state==MigrationState::paused,"pause state");return work.take_checkpoint().value();
}
ii::core::Value offer_value(std::string id,std::string payload){return ii::core::Value(ii::core::Value::Object{{"id",ii::core::Value(std::move(id))},{"payload",ii::core::Value(std::move(payload))}});}
void duplex(){
    EventLoop loop;Peer a(loop,"alpha"),b(loop,"beta");Runtime one_runtime({.workers=1,.capacity=8}),two_runtime({.workers=1,.capacity=8});
    auto program=[](){return MigrationProgram{"count",1,[](std::span<const std::byte> input){return MigrationStep{one(unsigned(input[0])+1),true};}};};
    auto authorize=[](const PeerInfo&){return true;};
    auto first=take(RemoteReceiver::install(a,one_runtime,{program()},authorize));
    auto second=take(RemoteReceiver::install(b,two_runtime,{program()},authorize));
    const IpEndpoint endpoint{IpAddress::loopback(AddressFamily::ipv4),0};check(bool(b.listen(endpoint)),"listen");
    std::shared_ptr<PeerConnection> reverse;b.connected=[&](auto link){reverse=std::move(link);};
    auto forward=take(a.connect({IpAddress::loopback(AddressFamily::ipv4),b.port()}));
    until(loop,[&]{return reverse&&forward->state()==PeerState::ready;});
    auto cp=checkpoint(one_runtime,4);auto original=cp.encode();
    RemoteTransfer transfer("move-a",std::move(cp));bool confirmed=false;
    check(bool(transfer.offer(forward,[&](auto result){confirmed=result&&*result;})),"offer a to b");
    until(loop,[&]{return confirmed;});check(transfer.accepted()&&!transfer.has_checkpoint(),"source retained checkpoint after remote acceptance");
    until(loop,[&]{auto s=second->status("move-a");return s&&s->state==MigrationState::completed;});
    check(second->result("move-a").value()==one(6),"remote task lost state");
    bool duplicate=false;auto retry=take(forward->request("work.offer",offer_value("move-a",hex_encode(original)),[&](auto result){duplicate=bool(result);}));(void)retry;
    until(loop,[&]{return duplicate;});check(second->receipts()==1,"replayed offer executed a second task");
    auto conflicting=hex_encode(original);conflicting.back()=conflicting.back()=='0'?'1':'0';bool collision=false;
    take(forward->request("work.offer",offer_value("move-a",conflicting),[&](auto result){collision=!result;}));
    until(loop,[&]{return collision;});check(second->receipts()==1,"conflicting transfer id changed receipt");
    auto reverse_cp=checkpoint(two_runtime,8);RemoteTransfer back("move-b",std::move(reverse_cp));bool back_ok=false;
    check(bool(back.offer(reverse,[&](auto result){back_ok=result&&*result;})),"offer b to a");
    until(loop,[&]{return back_ok;});until(loop,[&]{auto s=first->status("move-b");return s&&s->state==MigrationState::completed;});
    check(first->result("move-b").value()==one(10),"reverse task lost state");
    bool released=false;take(forward->request("work.release",ii::core::Value(ii::core::Value::Object{{"id",ii::core::Value("move-a")}}),[&](auto result){released=bool(result);}));
    until(loop,[&]{return released;});check(second->receipts()==0,"explicit receipt release failed");
    Peer denied(loop,"denied");auto rejection=take(RemoteReceiver::install(denied,two_runtime,{program()},[](const PeerInfo&){return false;}));
    check(bool(denied.listen(endpoint)),"denied listener");auto denied_link=take(a.connect({IpAddress::loopback(AddressFamily::ipv4),denied.port()}));
    until(loop,[&]{return denied_link->state()==PeerState::ready;});
    auto denied_cp=checkpoint(one_runtime,2);RemoteTransfer blocked("denied-work",std::move(denied_cp));bool denied_answer=false;
    check(bool(blocked.offer(denied_link,[&](auto result){denied_answer=!result;})),"denied offer admission");
    until(loop,[&]{return denied_answer;});check(blocked.uncertain()&&blocked.has_checkpoint()&&!blocked.reclaim()&&rejection->receipts()==0,"denied remote work did not fail closed");
    denied.close();
    a.close();b.close();
}
void ambiguous_send(){
    EventLoop loop;Peer peer(loop,"sender");Runtime runtime({.workers=1,.capacity=8});
    auto stream=std::make_unique<AmbiguousStream>();auto* raw=stream.get();auto link=take(peer.attach(std::move(stream)));
    loop.poll();raw->inject(frame(R"({"type":"hello","version":1,"identity":"remote","session":"00000000-0000-4000-8000-000000000001","maximum_frame":4096})"));
    check(link->state()==PeerState::ready,"memory stream handshake");
    auto cp=checkpoint(runtime,4);RemoteTransfer transfer("ambiguous",std::move(cp));raw->fail_write=true;
    auto offered=transfer.offer(link,[](auto){});
    check(!offered&&raw->output.find("work.offer")!=std::string::npos,"test must fail after writing the frame");
    check(transfer.uncertain()&&transfer.has_checkpoint()&&!transfer.reclaim(),"failed send after write allowed unsafe local reclaim");
}
void response_exception(){
    EventLoop loop;Peer peer(loop,"receiver");Runtime runtime({.workers=1,.capacity=8});
    MigrationProgram program{"count",1,[](std::span<const std::byte> input){return MigrationStep{one(unsigned(input[0])+1),true};}};
    auto receiver=take(RemoteReceiver::install(peer,runtime,{program},[](const PeerInfo&){return true;}));
    auto stream=std::make_unique<AmbiguousStream>();auto* raw=stream.get();auto link=take(peer.attach(std::move(stream)));
    loop.poll();raw->inject(frame(R"({"type":"hello","version":1,"identity":"sender","session":"00000000-0000-4000-8000-000000000001","maximum_frame":4096})"));
    check(link->state()==PeerState::ready,"receiver handshake");
    auto cp=checkpoint(runtime,4);const auto payload=hex_encode(cp.encode());
    raw->throw_next_write=true;
    raw->inject(frame("{\"type\":\"call\",\"id\":\"1\",\"operation\":\"work.offer\",\"arguments\":{\"id\":\"exception-work\",\"payload\":\""+payload+"\"},\"timeout\":5000}"));
    check(receiver->receipts()==1&&receiver->status("exception-work").has_value(),"response exception erased accepted work receipt");
    until(loop,[&]{auto status=receiver->status("exception-work");return status&&status->state==MigrationState::completed;});
    check(receiver->result("exception-work").value()==one(6),"accepted work did not survive response exception");
}
int server(){
    EventLoop loop;Peer peer(loop,"server");Runtime runtime({.workers=1,.capacity=8});
    MigrationProgram program{"count",1,[](std::span<const std::byte> input){return MigrationStep{one(unsigned(input[0])+1),true};}};
    auto receiver=take(RemoteReceiver::install(peer,runtime,{program},[](const PeerInfo&){return true;}));
    bool stop=false;std::shared_ptr<PeerConnection> stopping_link;
    check(bool(peer.expose("test.stop",[&](PeerCall call,PeerReply reply){stopping_link=call.connection;(void)reply(ii::core::Value(true));stop=true;})),"install stop operation");
    check(bool(peer.listen({IpAddress::loopback(AddressFamily::ipv4),0})),"server listen");
    std::cout<<"PORT "<<peer.port()<<std::endl;
    until(loop,[&]{return stop&&stopping_link&&stopping_link->pending_bytes()==0;});
    check(receiver->receipts()==1,"server receipt count");return 0;
}
int client(std::uint16_t port){
    EventLoop loop;Peer peer(loop,"client");Runtime runtime({.workers=1,.capacity=8});
    auto connection=take(peer.connect({IpAddress::loopback(AddressFamily::ipv4),port}));
    until(loop,[&]{return connection->state()==PeerState::ready;});
    auto cp=checkpoint(runtime,40);RemoteTransfer transfer("process-move",std::move(cp));bool accepted=false;
    check(bool(transfer.offer(connection,[&](auto result){accepted=result&&*result;})),"process offer");until(loop,[&]{return accepted;});
    bool done=false;
    while(!done){
        bool answered=false;auto request=connection->request("work.result",ii::core::Value(ii::core::Value::Object{{"id",ii::core::Value("process-move")}}),
            [&](ii::network::Result<ii::core::Value> response){
                if(response){auto state=response->find("state");auto data=response->find("result");
                    if(state&&data){auto name=state->get().get<std::string>();auto value=data->get().get<std::string>();
                        if(name&&value&&name->get()=="completed"){check(value->get()=="2a","process migration result");done=true;}}}
                answered=true;
            });
        check(bool(request),"query process work");until(loop,[&]{return answered;});
    }
    bool stopped=false;take(connection->request("test.stop",ii::core::Value{},[&](auto response){stopped=bool(response);}));
    until(loop,[&]{return stopped;});std::cout<<"PROCESS_WORK_OK\n";return 0;
}
}
int main(int argc,char** argv){try{
    if(argc==2&&std::string_view(argv[1])=="--server")return server();
    if(argc==3&&std::string_view(argv[1])=="--client")return client(static_cast<std::uint16_t>(std::stoi(argv[2])));
    duplex();ambiguous_send();response_exception();std::cout<<"REMOTE_WORK_OK\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
