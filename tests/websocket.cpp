#include <iiNetwork/Network.h>
#include <cstdlib>
#include <iostream>
#include <thread>
using namespace ii::network;
using namespace std::chrono_literals;
#define CHECK(x) do { if (!(x)) { std::cerr << __LINE__ << ": " #x "\n"; std::exit(1); } } while(false)
const std::string request="GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat, superchat\r\nOrigin: https://example.com\r\n\r\n";
WebSocketSession opened_server(WebSocketLimits limits={}) {
    auto session=WebSocketSession::server(limits); CHECK(session);
    auto upgrade=session->receive(request); CHECK(upgrade && upgrade->size()==1);
    CHECK(session->take_output().empty()); CHECK(session->state()==WebSocketState::awaiting_acceptance);
    CHECK(session->accept("chat")); (void)session->take_output(); return std::move(*session);
}
std::string frame(unsigned opcode,bool fin,std::string_view payload,bool masked=true) {
    CHECK(payload.size()<126);
    std::string out{char((fin?128:0)|opcode),char((masked?128:0)|payload.size())};
    if(masked) out.append("abcd");
    for(std::size_t i=0;i<payload.size();++i) out.push_back(payload[i]^(masked?"abcd"[i%4]:0));
    return out;
}
void handshake() {
    auto s=WebSocketSession::server(); CHECK(s);
    std::vector<WebSocketEvent> events;
    for(char c:request) { auto e=s->receive(std::string(1,c)); CHECK(e); events.insert(events.end(),e->begin(),e->end()); }
    CHECK(events.size()==1 && events[0].kind==WebSocketEventKind::upgrade_request);
    CHECK(s->upgrade() && s->upgrade()->origin=="https://example.com" && s->upgrade()->target=="/chat");
    CHECK(!s->accept("not-offered")); CHECK(s->accept("chat"));
    CHECK(s->take_output().find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")!=std::string::npos);
    auto no=WebSocketSession::server(); CHECK(no && no->receive(request)); CHECK(no->reject()); CHECK(no->state()==WebSocketState::closed);
    CHECK(no->take_output().starts_with("HTTP/1.1 403"));
    auto bad=request; bad.insert(bad.find("\r\n\r\n"),"\r\nSec-WebSocket-Key: duplicate");
    auto duplicate=WebSocketSession::server(); CHECK(duplicate && !duplicate->receive(bad));
    WebSocketClient injected; injected.host="x\r\nInjected: y"; CHECK(!WebSocketSession::client(injected));
    WebSocketClient options; options.host="example.com"; options.protocols={"chat"};
    auto client=WebSocketSession::client(options); auto server=WebSocketSession::server(); CHECK(client && server);
    CHECK(server->receive(client->take_output())); CHECK(server->accept("chat"));
    auto connected=client->receive(server->take_output()); CHECK(connected && connected->size()==1 && client->state()==WebSocketState::open && client->protocol()=="chat");
    auto invalid=WebSocketSession::client(options); CHECK(invalid); (void)invalid->take_output();
    CHECK(!invalid->receive("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n"));
}
void frames() {
    auto s=opened_server();
    CHECK(s.receive(frame(1,false,"\xe3\x81")));
    auto ping=s.receive(frame(9,true,"hello")); CHECK(ping && ping->size()==1 && ping->front().kind==WebSocketEventKind::ping);
    CHECK(s.take_output()==frame(10,true,"hello",false));
    auto text=s.receive(frame(0,true,"\x82")); CHECK(text && text->size()==1 && text->front().payload=="あ");
    CHECK(s.send_text("가나다"));
    auto wrong=opened_server(); CHECK(!wrong.receive(frame(1,true,"x",false)));
    auto badUtf8=opened_server(); CHECK(!badUtf8.receive(frame(1,true,"\xc0\xaf")));
    auto continuation=opened_server(); CHECK(!continuation.receive(frame(0,true,"x")));
    auto reserved=opened_server(); CHECK(!reserved.receive(std::string{char(0xc1),char(0x80),'a','b','c','d'}));
    auto control=opened_server(); CHECK(!control.receive(frame(9,false,"x")));
    CHECK(!s.close(1005)); CHECK(s.close(1000,"bye")); CHECK(!s.send_text("after close"));
    auto closed=s.receive(frame(8,true,std::string("\x03\xe8",2)+"bye")); CHECK(closed && s.state()==WebSocketState::closed);
    WebSocketClient options; options.host="example.com";
    auto c=WebSocketSession::client(options); auto b=WebSocketSession::server(); CHECK(c && b);
    CHECK(b->receive(c->take_output())); CHECK(b->accept()); CHECK(c->receive(b->take_output()));
    for(auto size:{126,65535,65536}) {
        std::string bytes(size,'z'); CHECK(c->send_binary(bytes)); auto data=b->receive(c->take_output());
        CHECK(data && data->size()==1 && data->front().payload==bytes);
    }
}
void limits() {
    WebSocketLimits tiny; tiny.handshake_bytes=32; auto s=WebSocketSession::server(tiny); CHECK(s && !s->receive(request));
    tiny={}; tiny.message_bytes=3; auto small=opened_server(tiny);
    CHECK(small.receive(frame(9,true,"hello"))); // control frames have their own 125-byte bound
    CHECK(!small.receive(frame(1,true,"four")));
    auto fragments=opened_server(tiny); CHECK(fragments.receive(frame(1,false,"ab"))); CHECK(!fragments.receive(frame(0,true,"cd")));
    tiny={}; tiny.events=1; auto many=opened_server(tiny); CHECK(!many.receive(frame(1,true,"a")+frame(1,true,"b")));
    tiny={}; tiny.buffered_bytes=1; CHECK(!WebSocketSession::server(tiny));
    auto tooLarge=opened_server(); CHECK(!tooLarge.receive(std::string{char(0x82),char(0xff),char(0x80),0,0,0,0,0,0,0}));
    // Empty continuation floods consume the same per-call work budget.
    tiny={}; tiny.events=2; auto flood=opened_server(tiny);
    CHECK(!flood.receive(frame(1,false,"")+frame(0,false,"")+frame(0,false,"")));
    std::uint32_t random=0x71824;
    for(unsigned length=0;length<256;++length) {
        auto fuzz=opened_server(); std::string input;
        for(unsigned i=0;i<length;++i) { random=random*1664525+1013904223; input+=char(random>>24); }
        (void)fuzz.receive(input);
    }
}
void tcp() {
    ii::runtime::EventLoop loop; Listener listener(loop); Tcp clientSocket(loop); std::unique_ptr<Tcp> accepted;
    WebSocketClient options; options.host="localhost"; options.target="/chat";
    auto client=WebSocketSession::client(options); auto server=WebSocketSession::server(); CHECK(client && server);
    CHECK(listener.listen("127.0.0.1",0)); listener.accepted=[&](auto socket){accepted=std::move(socket);};
    CHECK(clientSocket.connect("127.0.0.1",listener.port()));
    bool sent=false,received=false,started=false;
    const auto deadline=std::chrono::steady_clock::now()+5s;
    while(!received && std::chrono::steady_clock::now()<deadline) {
        loop.poll();
        if(clientSocket.is_connected() && !started) { CHECK(clientSocket.write(client->take_output())); started=true; }
        if(accepted && accepted->available_bytes()) {
            auto events=server->receive(accepted->read()); CHECK(events);
            for(auto& event:*events) {
                if(event.kind==WebSocketEventKind::upgrade_request) { CHECK(server->upgrade()->target=="/chat"); CHECK(server->accept()); }
                if(event.kind==WebSocketEventKind::text) { CHECK(server->send_text(event.payload)); }
            }
            auto output=server->take_output(); if(!output.empty()) CHECK(accepted->write(output));
        }
        if(clientSocket.available_bytes()) {
            auto events=client->receive(clientSocket.read()); CHECK(events);
            for(auto& event:*events) if(event.kind==WebSocketEventKind::text) { CHECK(event.payload=="loopback"); received=true; }
        }
        if(client->state()==WebSocketState::open && !sent) { CHECK(client->send_text("loopback")); CHECK(clientSocket.write(client->take_output())); sent=true; }
        std::this_thread::sleep_for(1ms);
    }
    CHECK(received); clientSocket.close(); if(accepted) accepted->close(); listener.close();
}
int main(int argc,char** argv) { CHECK(argc==2); const std::string name=argv[1];
    if(name=="handshake") handshake(); else if(name=="frames") frames(); else if(name=="limits") limits(); else if(name=="tcp") tcp(); else CHECK(false);
    std::cout << "WebSocket " << name << " passed\n";
}
