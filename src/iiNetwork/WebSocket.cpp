#include <iiNetwork/WebSocket.h>
#include <iiNetwork/Wire.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <set>

namespace ii::network {
namespace {
auto error(ErrorCode code,std::string message) { return std::unexpected(Error{code,Layer::application,std::move(message)}); }
std::string lower(std::string text) { for(auto& c:text) if(c>='A' && c<='Z') c+=32; return text; }
std::string trim(std::string_view text) {
    while(!text.empty() && (text.front()==' ' || text.front()=='\t')) text.remove_prefix(1);
    while(!text.empty() && (text.back()==' ' || text.back()=='\t')) text.remove_suffix(1);
    return std::string(text);
}
bool token(std::string_view text) {
    if(text.empty()) return false;
    for(unsigned char c:text) if(!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') ||
        std::string_view("!#$%&'*+-.^_`|~").find(c)!=std::string_view::npos)) return false;
    return true;
}
bool field(std::string_view text) { return std::none_of(text.begin(),text.end(),[](unsigned char c){return c<32 || c==127;}); }
bool utf8(std::string_view text) {
    for(std::size_t i=0;i<text.size();) {
        auto first=static_cast<unsigned char>(text[i++]); if(first<128) continue;
        unsigned n=0; std::uint32_t c=0,minimum=0;
        if(first>=0xc2 && first<=0xdf) { n=1; c=first&31; minimum=0x80; }
        else if(first>=0xe0 && first<=0xef) { n=2; c=first&15; minimum=0x800; }
        else if(first>=0xf0 && first<=0xf4) { n=3; c=first&7; minimum=0x10000; } else return false;
        if(n>text.size()-i) return false;
        while(n--) { auto next=static_cast<unsigned char>(text[i++]); if((next&0xc0)!=0x80) return false; c=(c<<6)|(next&63); }
        if(c<minimum || c>0x10ffff || (c>=0xd800 && c<=0xdfff)) return false;
    }
    return true;
}
bool close_code(std::uint16_t code) {
    return (code>=1000 && code<=1014 && code!=1004 && code!=1005 && code!=1006) || (code>=3000 && code<=4999);
}
Result<std::vector<std::string>> tokens(std::string_view text) {
    std::vector<std::string> result; std::set<std::string> seen;
    while(!text.empty()) {
        auto comma=text.find(','); auto part=trim(text.substr(0,comma));
        if(!token(part) || !seen.insert(part).second) return error(ErrorCode::malformed,"Invalid or duplicate WebSocket token");
        result.push_back(std::move(part)); if(comma==text.npos) break;
        text.remove_prefix(comma+1); if(text.empty()) return error(ErrorCode::malformed,"Empty WebSocket token");
    }
    return result;
}
bool contains_token(std::string_view text,std::string_view wanted) {
    auto list=tokens(lower(std::string(text))); return list && std::ranges::find(*list,wanted)!=list->end();
}
struct Head final { std::string line; HeaderFields headers; };
Result<Head> parse_head(std::string_view bytes) {
    Head result; auto pos=bytes.find("\r\n");
    if(pos==bytes.npos || !field(bytes.substr(0,pos))) return error(ErrorCode::malformed,"Invalid HTTP upgrade line");
    result.line=bytes.substr(0,pos); bytes.remove_prefix(pos+2);
    while(!bytes.empty() && !bytes.starts_with("\r\n")) {
        pos=bytes.find("\r\n"); if(pos==bytes.npos) return error(ErrorCode::malformed,"Invalid upgrade line ending");
        auto line=bytes.substr(0,pos); auto colon=line.find(':');
        if(colon==line.npos || !token(line.substr(0,colon)) || result.headers.size()>=128) return error(ErrorCode::malformed,"Invalid upgrade header");
        auto name=std::string(line.substr(0,colon)); auto value=trim(line.substr(colon+1));
        if(!field(value) || result.headers.contains(name)) return error(ErrorCode::malformed,"Duplicate or invalid upgrade header");
        auto added=result.headers.append(std::move(name),std::move(value)); if(!added) return std::unexpected(added.error());
        bytes.remove_prefix(pos+2);
    }
    if(result.headers.contains("Content-Length") || result.headers.contains("Transfer-Encoding")) return error(ErrorCode::malformed,"WebSocket upgrades must not contain body framing");
    if(!contains_token(result.headers.get("Upgrade").value_or(""),"websocket") ||
        !contains_token(result.headers.get("Connection").value_or(""),"upgrade")) return error(ErrorCode::malformed,"Missing WebSocket upgrade headers");
    return result;
}
Result<std::string> acceptance(std::string_view key) {
    const auto challenge=std::string(key)+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::array<unsigned char,EVP_MAX_MD_SIZE> digest{}; unsigned length=0;
    if(EVP_Digest(challenge.data(),challenge.size(),digest.data(),&length,EVP_sha1(),nullptr)!=1) return error(ErrorCode::unavailable,"WebSocket challenge digest is unavailable");
    return wire::base64(std::string_view(reinterpret_cast<const char*>(digest.data()),length));
}
Result<void> limits_valid(WebSocketLimits limits) {
    if(!limits.message_bytes || limits.message_bytes>512ULL*1024*1024 || limits.handshake_bytes<16 || limits.handshake_bytes>1024*1024 ||
        limits.buffered_bytes<14 || limits.buffered_bytes>1024ULL*1024*1024 || limits.output_bytes<14 || limits.output_bytes>1024ULL*1024*1024 ||
        !limits.events || limits.events>100000) return error(ErrorCode::invalid_argument,"Invalid WebSocket limits");
    return {};
}
}
struct WebSocketSession::State final {
    bool client=false;
    WebSocketState state=WebSocketState::upgrading;
    WebSocketLimits limits;
    WebSocketClient options;
    std::optional<WebSocketUpgrade> upgrade;
    std::string input,output,key,selected,fragment;
    unsigned fragment_type=0;
    Result<void> append(std::string_view bytes) {
        if(bytes.size()>limits.output_bytes-output.size()) return error(ErrorCode::would_block,"WebSocket output budget is full");
        output.append(bytes); return {};
    }
    Result<void> frame(unsigned opcode,std::string_view payload) {
        const std::size_t header=2+(payload.size()<126?0:payload.size()<=65535?2:8)+(client?4:0);
        if(payload.size()>limits.output_bytes || header>limits.output_bytes-payload.size() ||
            header+payload.size()>limits.output_bytes-output.size()) return error(ErrorCode::would_block,"WebSocket output budget is full");
        std::string frame; frame.reserve(header+payload.size()); frame.push_back(char(128|opcode));
        auto size=payload.size(); frame.push_back(char((client?128:0)|(size<126?size:size<=65535?126:127)));
        if(size>=126) { unsigned count=size<=65535?2:8; for(unsigned i=count;i;--i) frame.push_back(char(std::uint64_t(size)>>((i-1)*8))); }
        std::array<unsigned char,4> mask{};
        if(client) { if(RAND_bytes(mask.data(),4)!=1) return error(ErrorCode::unavailable,"WebSocket masking entropy is unavailable"); frame.append(reinterpret_cast<const char*>(mask.data()),4); }
        for(std::size_t i=0;i<size;++i) frame.push_back(payload[i]^(client?mask[i%4]:0));
        return append(frame);
    }
};
WebSocketSession::WebSocketSession(std::unique_ptr<State> state):state_(std::move(state)){}
WebSocketSession::~WebSocketSession()=default;
WebSocketSession::WebSocketSession(WebSocketSession&&) noexcept=default;
WebSocketSession& WebSocketSession::operator=(WebSocketSession&&) noexcept=default;
Result<WebSocketSession> WebSocketSession::client(WebSocketClient options,WebSocketLimits limits) {
    if(auto valid=limits_valid(limits); !valid) return std::unexpected(valid.error());
    if(options.host.empty() || !field(options.host) || options.host.find(' ')!=options.host.npos || options.target.empty() ||
        !options.target.starts_with('/') || !field(options.target) || options.target.find_first_of(" #")!=options.target.npos || !field(options.origin))
        return error(ErrorCode::invalid_argument,"Invalid WebSocket host, target or origin");
    auto s=std::make_unique<State>(); s->client=true; s->limits=limits; s->options=std::move(options);
    std::array<unsigned char,16> nonce{}; if(RAND_bytes(nonce.data(),nonce.size())!=1) return error(ErrorCode::unavailable,"WebSocket key entropy is unavailable");
    s->key=wire::base64(std::string_view(reinterpret_cast<const char*>(nonce.data()),nonce.size()));
    std::string request="GET "+s->options.target+" HTTP/1.1\r\nHost: "+s->options.host+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+s->key+"\r\n";
    if(!s->options.origin.empty()) request+="Origin: "+s->options.origin+"\r\n";
    std::set<std::string> seen;
    if(!s->options.protocols.empty()) {
        request+="Sec-WebSocket-Protocol: ";
        for(const auto& protocol:s->options.protocols) {
            if(!token(protocol) || !seen.insert(protocol).second) return error(ErrorCode::invalid_argument,"Invalid WebSocket subprotocol");
            if(seen.size()>1) request+=", "; request+=protocol;
        }
        request+="\r\n";
    }
    for(const auto& [name,value]:s->options.headers.entries()) {
        auto key=lower(name);
        if(key=="host" || key=="connection" || key=="upgrade" || key=="origin" || key=="content-length" || key=="transfer-encoding" || key.starts_with("sec-websocket-"))
            return error(ErrorCode::invalid_argument,"Reserved WebSocket request header");
        request+=name+": "+value+"\r\n";
    }
    request+="\r\n";
    if(request.size()>limits.handshake_bytes) return error(ErrorCode::too_large,"WebSocket upgrade exceeds its byte budget");
    if(auto queued=s->append(request); !queued) return std::unexpected(queued.error());
    return WebSocketSession(std::move(s));
}
Result<WebSocketSession> WebSocketSession::server(WebSocketLimits limits) {
    if(auto valid=limits_valid(limits); !valid) return std::unexpected(valid.error());
    auto s=std::make_unique<State>(); s->limits=limits; return WebSocketSession(std::move(s));
}
const WebSocketUpgrade* WebSocketSession::upgrade() const noexcept { return state_ && state_->upgrade?&*state_->upgrade:nullptr; }
Result<void> WebSocketSession::accept(std::string_view protocol) {
    if(!state_ || state_->state!=WebSocketState::awaiting_acceptance) return error(ErrorCode::invalid_state,"No WebSocket upgrade awaiting acceptance");
    auto& s=*state_;
    if(!protocol.empty() && (!token(protocol) || std::ranges::find(s.upgrade->protocols,protocol)==s.upgrade->protocols.end())) return error(ErrorCode::invalid_argument,"Subprotocol was not offered");
    auto accept=acceptance(s.key); if(!accept) return std::unexpected(accept.error());
    std::string response="HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+*accept+"\r\n";
    if(!protocol.empty()) response+="Sec-WebSocket-Protocol: "+std::string(protocol)+"\r\n";
    response+="\r\n"; if(auto queued=s.append(response); !queued) return queued;
    s.selected=protocol; s.state=WebSocketState::open; return {};
}
Result<void> WebSocketSession::reject(unsigned status) {
    if(!state_ || state_->state!=WebSocketState::awaiting_acceptance || status<400 || status>599) return error(ErrorCode::invalid_state,"Invalid WebSocket rejection");
    auto& s=*state_; auto queued=s.append("HTTP/1.1 "+std::to_string(status)+" Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    if(!queued) return queued; s.state=WebSocketState::closed; s.input.clear(); return {};
}
Result<std::vector<WebSocketEvent>> WebSocketSession::receive(std::string_view bytes) {
    if(!state_ || state_->state==WebSocketState::closed || state_->state==WebSocketState::failed) return error(ErrorCode::closed,"WebSocket session is not receiving");
    auto& s=*state_;
    const auto fail=[&](ErrorCode code,std::string message)->Result<std::vector<WebSocketEvent>> {
        s.state=WebSocketState::failed; s.input.clear(); s.fragment.clear(); s.output.clear(); return error(code,std::move(message));
    };
    if(bytes.size()>s.limits.buffered_bytes-s.input.size()) return fail(ErrorCode::too_large,"WebSocket receive budget exceeded");
    s.input.append(bytes); std::vector<WebSocketEvent> events;
    if(s.state==WebSocketState::upgrading) {
        auto end=s.input.find("\r\n\r\n");
        if(end==s.input.npos) { if(s.input.size()>s.limits.handshake_bytes) return fail(ErrorCode::too_large,"WebSocket upgrade exceeds its budget"); return events; }
        end+=4; if(end>s.limits.handshake_bytes) return fail(ErrorCode::too_large,"WebSocket upgrade exceeds its budget");
        auto head=parse_head(std::string_view(s.input).substr(0,end)); if(!head) return fail(head.error().code,head.error().message);
        if(s.client) {
            auto accept=acceptance(s.key); if(!accept) return fail(accept.error().code,accept.error().message);
            if(!head->line.starts_with("HTTP/1.1 101 ") || head->headers.get("Sec-WebSocket-Accept")!=*accept || head->headers.contains("Sec-WebSocket-Extensions"))
                return fail(ErrorCode::authentication_failed,"Invalid WebSocket server upgrade");
            s.selected=head->headers.get("Sec-WebSocket-Protocol").value_or("");
            if(!s.selected.empty() && (!token(s.selected) || std::ranges::find(s.options.protocols,s.selected)==s.options.protocols.end())) return fail(ErrorCode::malformed,"Unoffered WebSocket subprotocol");
            s.state=WebSocketState::open; events.push_back({WebSocketEventKind::opened,{}});
        } else {
            if(!head->line.starts_with("GET ") || !head->line.ends_with(" HTTP/1.1")) return fail(ErrorCode::malformed,"Expected an HTTP/1.1 WebSocket GET");
            auto target=head->line.substr(4,head->line.size()-4-9);
            auto host=head->headers.get("Host").value_or(""); s.key=head->headers.get("Sec-WebSocket-Key").value_or("");
            auto nonce=wire::unbase64(s.key);
            if(target.empty() || !target.starts_with('/') || target.find_first_of(" #")!=target.npos || host.empty() || host.find(' ')!=host.npos ||
                head->headers.get("Sec-WebSocket-Version")!="13" || !nonce || nonce->size()!=16 || wire::base64(*nonce)!=s.key)
                return fail(ErrorCode::malformed,"Invalid WebSocket client upgrade");
            auto protocols=tokens(head->headers.get("Sec-WebSocket-Protocol").value_or("")); if(!protocols) return fail(protocols.error().code,protocols.error().message);
            s.upgrade=WebSocketUpgrade{std::move(host),std::move(target),head->headers.get("Origin").value_or(""),std::move(*protocols),std::move(head->headers)};
            s.state=WebSocketState::awaiting_acceptance; events.push_back({WebSocketEventKind::upgrade_request,{}});
        }
        s.input.erase(0,end);
    }
    if(s.state==WebSocketState::awaiting_acceptance) return events;
    std::size_t consumed=0,frames=0;
    while(s.input.size()-consumed>=2 && s.state!=WebSocketState::closed) {
        if(events.size()>=s.limits.events || ++frames>s.limits.events) return fail(ErrorCode::too_large,"WebSocket frame/event budget exceeded");
        auto* p=reinterpret_cast<const unsigned char*>(s.input.data()+consumed);
        const auto available=s.input.size()-consumed; const unsigned op=p[0]&15;
        const bool fin=(p[0]&128)!=0,masked=(p[1]&128)!=0; const unsigned marker=p[1]&127;
        if((p[0]&0x70) || (op!=0 && op!=1 && op!=2 && op!=8 && op!=9 && op!=10) || masked==s.client || (op>=8 && (!fin || marker>125)))
            return fail(ErrorCode::malformed,"Invalid WebSocket frame header");
        std::uint64_t length=marker; std::size_t header=2;
        if(marker>=126) {
            const unsigned count=marker==126?2:8; if(available<header+count) break;
            length=0; for(unsigned i=0;i<count;++i) length=(length<<8)|p[header++];
            if((count==8 && (p[2]&128)) || (count==2 && length<126) || (count==8 && length<=65535)) return fail(ErrorCode::malformed,"Invalid WebSocket frame length");
        }
        if(op<8 && length>s.limits.message_bytes) return fail(ErrorCode::too_large,"WebSocket frame exceeds its message budget");
        const std::size_t maskOffset=header; if(masked) header+=4;
        if(available<header || length>available-header) break;
        std::string payload; payload.resize(static_cast<std::size_t>(length));
        for(std::size_t i=0;i<length;++i) payload[i]=char(p[header+i]^(masked?p[maskOffset+i%4]:0));
        consumed+=header+static_cast<std::size_t>(length);
        if(op==8) {
            if(payload.size()==1) return fail(ErrorCode::malformed,"Invalid WebSocket close payload");
            std::uint16_t code=1005; std::string reason;
            if(payload.size()>=2) { code=(static_cast<unsigned char>(payload[0])<<8)|static_cast<unsigned char>(payload[1]); reason=payload.substr(2); if(!close_code(code) || !utf8(reason)) return fail(ErrorCode::malformed,"Invalid WebSocket close code or reason"); }
            if(s.state==WebSocketState::open) { auto queued=s.frame(8,payload); if(!queued) return fail(queued.error().code,queued.error().message); }
            s.state=WebSocketState::closed; s.fragment.clear(); events.push_back({WebSocketEventKind::closed,std::move(reason),code});
        } else if(op==9 || op==10) {
            if(op==9) { auto queued=s.frame(10,payload); if(!queued) return fail(queued.error().code,queued.error().message); }
            events.push_back({op==9?WebSocketEventKind::ping:WebSocketEventKind::pong,std::move(payload)});
        } else if(s.state==WebSocketState::open) {
            if((op==0 && !s.fragment_type) || (op!=0 && s.fragment_type)) return fail(ErrorCode::malformed,"Invalid WebSocket fragmentation sequence");
            if(op!=0) s.fragment_type=op;
            if(payload.size()>s.limits.message_bytes-s.fragment.size()) return fail(ErrorCode::too_large,"Fragmented WebSocket message exceeds its budget");
            s.fragment+=payload;
            if(fin) {
                if(s.fragment_type==1 && !utf8(s.fragment)) return fail(ErrorCode::malformed,"Invalid UTF-8 WebSocket message");
                events.push_back({s.fragment_type==1?WebSocketEventKind::text:WebSocketEventKind::binary,std::move(s.fragment)});
                s.fragment.clear(); s.fragment_type=0;
            }
        }
    }
    s.input.erase(0,consumed); if(s.state==WebSocketState::closed) s.input.clear(); return events;
}
Result<void> WebSocketSession::send_text(std::string_view text) {
    if(!state_ || state_->state!=WebSocketState::open) return error(ErrorCode::invalid_state,"WebSocket is not open");
    if(text.size()>state_->limits.message_bytes) return error(ErrorCode::too_large,"WebSocket message exceeds its budget");
    if(!utf8(text)) return error(ErrorCode::malformed,"WebSocket text is not UTF-8");
    return state_->frame(1,text);
}
Result<void> WebSocketSession::send_binary(std::string_view bytes) {
    if(!state_ || state_->state!=WebSocketState::open) return error(ErrorCode::invalid_state,"WebSocket is not open");
    if(bytes.size()>state_->limits.message_bytes) return error(ErrorCode::too_large,"WebSocket message exceeds its budget");
    return state_->frame(2,bytes);
}
Result<void> WebSocketSession::ping(std::string_view bytes) {
    if(!state_ || state_->state!=WebSocketState::open) return error(ErrorCode::invalid_state,"WebSocket is not open");
    if(bytes.size()>125) return error(ErrorCode::too_large,"WebSocket ping exceeds 125 bytes"); return state_->frame(9,bytes);
}
Result<void> WebSocketSession::close(std::uint16_t code,std::string_view reason) {
    if(!state_ || state_->state!=WebSocketState::open) return error(ErrorCode::invalid_state,"WebSocket is not open");
    if(!close_code(code) || reason.size()>123 || !utf8(reason)) return error(ErrorCode::invalid_argument,"Invalid WebSocket close code or reason");
    std::string bytes{char(code>>8),char(code&255)}; bytes+=reason;
    auto queued=state_->frame(8,bytes); if(queued) state_->state=WebSocketState::closing; return queued;
}
std::string WebSocketSession::take_output() { if(!state_) return {}; auto result=std::move(state_->output); state_->output.clear(); return result; }
WebSocketState WebSocketSession::state() const noexcept { return state_?state_->state:WebSocketState::closed; }
std::string WebSocketSession::protocol() const { return state_?state_->selected:std::string{}; }
}
