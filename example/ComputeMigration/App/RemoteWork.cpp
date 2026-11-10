#include "RemoteWork.h"
#include <algorithm>
#include <map>
#include <utility>

namespace ii::compute_migration {
using namespace ii::network;
using namespace ii::runtime;
using ii::core::Value;
namespace {
std::unexpected<Error> fail(ErrorCode code,std::string message){return std::unexpected(Error{code,Layer::application,std::move(message)});}
bool valid_id(std::string_view value){return !value.empty()&&value.size()<=128&&std::ranges::all_of(value,[](unsigned char c){
    return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.';});}
std::optional<std::string> field(const Value& value,std::string_view name){
    auto item=value.find(name);if(!item)return {};auto text=item->get().get<std::string>();if(!text)return {};return text->get();
}
int digit(char value){if(value>='0'&&value<='9')return value-'0';if(value>='a'&&value<='f')return value-'a'+10;return -1;}
std::optional<std::vector<std::byte>> unhex(std::string_view input,std::size_t maximum){
    if(input.size()%2||input.size()/2>maximum)return {};
    std::vector<std::byte> out;out.reserve(input.size()/2);
    for(std::size_t i=0;i<input.size();i+=2){const auto a=digit(input[i]),b=digit(input[i+1]);if(a<0||b<0)return {};out.push_back(std::byte(a*16+b));}
    return out;
}
bool authorized(const Authorize& authorize,const PeerCall& call){
    try {const auto info=call.connection?call.connection->info():std::optional<PeerInfo>{};return info&&authorize&&authorize(*info);} catch(...){return false;}
}
std::string state_name(MigrationState state){
    switch(state){case MigrationState::queued:return "queued";case MigrationState::running:return "running";
    case MigrationState::paused:return "paused";case MigrationState::completed:return "completed";
    case MigrationState::failed:return "failed";case MigrationState::cancelled:return "cancelled";
    case MigrationState::transferred:return "transferred";}return "failed";
}
}
std::string hex_encode(std::span<const std::byte> bytes){
    constexpr char digits[]="0123456789abcdef";std::string out;out.reserve(bytes.size()*2);
    for(auto byte:bytes){const auto value=std::to_integer<unsigned>(byte);out.push_back(digits[value>>4]);out.push_back(digits[value&15]);}return out;
}
struct RemoteReceiver::State final {
    struct Receipt final {std::string payload;std::optional<MigratingWork> work;};
    Runtime* runtime;
    std::vector<MigrationProgram> programs;
    Authorize authorize;
    std::size_t maximum_checkpoint,maximum_receipts;
    std::map<std::string,Receipt,std::less<>> entries;
};
RemoteReceiver::RemoteReceiver(Peer& peer,std::shared_ptr<State> state):peer_(&peer),state_(std::move(state)){}
RemoteReceiver::~RemoteReceiver(){if(peer_){peer_->remove_operation("work.offer");peer_->remove_operation("work.result");peer_->remove_operation("work.release");}}
Result<std::unique_ptr<RemoteReceiver>> RemoteReceiver::install(Peer& peer,Runtime& runtime,
    std::vector<MigrationProgram> programs,Authorize authorize,std::size_t maximum,std::size_t receipts){
    if(!authorize||!maximum||maximum>4u*1024u*1024u||!receipts||receipts>4096)return fail(ErrorCode::invalid_argument,"Invalid migration limits or authorization");
    for(std::size_t i=0;i<programs.size();++i){
        if(programs[i].kind.empty()||!programs[i].version||!programs[i].advance)return fail(ErrorCode::invalid_argument,"Invalid work program");
        for(std::size_t j=0;j<i;++j)if(programs[i].kind==programs[j].kind&&programs[i].version==programs[j].version)
            return fail(ErrorCode::invalid_argument,"Duplicate work program");
    }
    auto state=std::make_shared<State>();state->runtime=&runtime;state->programs=std::move(programs);state->authorize=std::move(authorize);
    state->maximum_checkpoint=maximum;state->maximum_receipts=receipts;
    auto receiver=std::unique_ptr<RemoteReceiver>(new RemoteReceiver(peer,state));receiver->peer_=nullptr;
    struct Registration final {
        Peer& peer;unsigned count=0;
        ~Registration(){if(count>=3)peer.remove_operation("work.release");if(count>=2)peer.remove_operation("work.result");if(count>=1)peer.remove_operation("work.offer");}
    } registration{peer};
    const auto offer=peer.expose("work.offer",[weak=std::weak_ptr<State>(state)](PeerCall call,PeerReply reply){
        auto state=weak.lock();if(!state){(void)reply(fail(ErrorCode::closed,"Receiver closed"));return;}
        if(!authorized(state->authorize,call)){(void)reply(fail(ErrorCode::permission_denied,"Work transfer denied"));return;}
        const auto id=field(call.arguments,"id"),payload=field(call.arguments,"payload");
        if(!id||!payload||!valid_id(*id)){(void)reply(fail(ErrorCode::invalid_argument,"Invalid transfer envelope"));return;}
        if(auto found=state->entries.find(*id);found!=state->entries.end()){
            if(found->second.payload!=*payload){(void)reply(fail(ErrorCode::replay,"Transfer id belongs to different data"));return;}
            (void)reply(Value(true));return;
        }
        if(state->entries.size()>=state->maximum_receipts){(void)reply(fail(ErrorCode::would_block,"Transfer receipt capacity reached"));return;}
        auto raw=unhex(*payload,state->maximum_checkpoint+164);if(!raw){(void)reply(fail(ErrorCode::too_large,"Invalid or oversized checkpoint"));return;}
        auto checkpoint=WorkCheckpoint::decode(*raw,state->maximum_checkpoint);
        if(!checkpoint){(void)reply(fail(ErrorCode::malformed,"Invalid work checkpoint"));return;}
        const auto program=std::ranges::find_if(state->programs,[&](const auto& value){return value.kind==checkpoint->kind()&&value.version==checkpoint->version();});
        if(program==state->programs.end()){(void)reply(fail(ErrorCode::unsupported,"Work program is not registered"));return;}
        auto [entry,inserted]=state->entries.emplace(*id,State::Receipt{*payload,{}});(void)inserted;
        bool admitted=false;
        try {
            auto resumed=MigratingWork::resume(*state->runtime,*program,*checkpoint,state->maximum_checkpoint);
            if(resumed){entry->second.work.emplace(std::move(*resumed));admitted=true;}
        } catch(...) {state->entries.erase(entry);(void)reply(fail(ErrorCode::unavailable,"Work admission failed"));return;}
        if(!admitted){state->entries.erase(entry);(void)reply(fail(ErrorCode::would_block,"Target rejected work"));return;}
        (void)reply(Value(true));
    });
    if(!offer)return std::unexpected(offer.error());
    registration.count=1;
    const auto result=peer.expose("work.result",[weak=std::weak_ptr<State>(state)](PeerCall call,PeerReply reply){
        auto state=weak.lock();if(!state){(void)reply(fail(ErrorCode::closed,"Receiver closed"));return;}
        if(!authorized(state->authorize,call)){(void)reply(fail(ErrorCode::permission_denied,"Work query denied"));return;}
        const auto id=field(call.arguments,"id");if(!id||!valid_id(*id)){(void)reply(fail(ErrorCode::invalid_argument,"Invalid transfer id"));return;}
        const auto entry=state->entries.find(*id);if(entry==state->entries.end()||!entry->second.work){(void)reply(fail(ErrorCode::not_found,"Unknown transfer"));return;}
        const auto status=entry->second.work->status();std::string result;
        if(status.state==MigrationState::completed){auto bytes=entry->second.work->result();if(bytes)result=hex_encode(*bytes);}
        (void)reply(Value(Value::Object{{"state",Value(state_name(status.state))},{"result",Value(std::move(result))}}));
    });
    if(!result)return std::unexpected(result.error());
    registration.count=2;
    const auto release=peer.expose("work.release",[weak=std::weak_ptr<State>(state)](PeerCall call,PeerReply reply){
        auto state=weak.lock();if(!state){(void)reply(fail(ErrorCode::closed,"Receiver closed"));return;}
        if(!authorized(state->authorize,call)){(void)reply(fail(ErrorCode::permission_denied,"Work release denied"));return;}
        const auto id=field(call.arguments,"id");if(!id||!valid_id(*id)){(void)reply(fail(ErrorCode::invalid_argument,"Invalid transfer id"));return;}
        auto entry=state->entries.find(*id);if(entry==state->entries.end()||!entry->second.work){(void)reply(fail(ErrorCode::not_found,"Unknown transfer"));return;}
        const auto status=entry->second.work->status().state;
        if(status==MigrationState::queued||status==MigrationState::running){(void)reply(fail(ErrorCode::would_block,"Work is still active"));return;}
        state->entries.erase(entry);(void)reply(Value(true));
    });
    if(!release)return std::unexpected(release.error());
    registration.count=3;receiver->peer_=&peer;registration.count=0;
    return receiver;
}
std::size_t RemoteReceiver::receipts() const{return state_->entries.size();}
std::optional<MigrationStatus> RemoteReceiver::status(std::string_view id) const{
    const auto it=state_->entries.find(id);if(it==state_->entries.end()||!it->second.work)return {};return it->second.work->status();
}
std::expected<std::vector<std::byte>,MigrationError> RemoteReceiver::result(std::string_view id) const{
    const auto it=state_->entries.find(id);if(it==state_->entries.end()||!it->second.work)return std::unexpected(MigrationError::invalid);return it->second.work->result();
}
Result<void> RemoteReceiver::release(std::string_view id){
    const auto it=state_->entries.find(id);if(it==state_->entries.end()||!it->second.work)return fail(ErrorCode::not_found,"Unknown transfer");
    const auto status=it->second.work->status().state;
    if(status==MigrationState::queued||status==MigrationState::running)return fail(ErrorCode::would_block,"Work is still active");
    state_->entries.erase(it);return {};
}
struct RemoteTransfer::State final {
    State(std::string value,WorkCheckpoint ticket):id(std::move(value)),checkpoint(std::move(ticket)){}
    std::string id;WorkCheckpoint checkpoint;bool in_flight=false,was_sent=false,accepted=false,uncertain=false;
};
RemoteTransfer::RemoteTransfer(std::string id,WorkCheckpoint checkpoint):state_(std::make_shared<State>(std::move(id),std::move(checkpoint))){}
Result<void> RemoteTransfer::offer(std::shared_ptr<PeerConnection> link,Completion completion){
    if(!link||!completion||!state_->checkpoint||!valid_id(state_->id))return fail(ErrorCode::invalid_argument,"Invalid transfer offer");
    if(state_->in_flight||state_->accepted)return fail(ErrorCode::invalid_state,"Transfer is already active or accepted");
    if(link->state()!=PeerState::ready)return fail(ErrorCode::invalid_state,"Peer connection is not ready");
    auto payload=state_->checkpoint.encode();if(payload.size()>4u*1024u*1024u+164)return fail(ErrorCode::too_large,"Checkpoint exceeds transfer limit");
    auto arguments=Value(Value::Object{{"id",Value(state_->id)},{"payload",Value(hex_encode(payload))}});
    // A transport can report failure after queueing or writing the frame.
    // Treat every attempted request as ambiguous until an acknowledgement.
    state_->in_flight=true;state_->was_sent=true;state_->uncertain=true;
    try {
        auto request=link->request("work.offer",std::move(arguments),[state=state_,completion=std::move(completion)](Result<Value> response) mutable {
            state->in_flight=false;
            if(!response){state->uncertain=true;completion(std::unexpected(response.error()));return;}
            auto accepted=response->get<bool>();if(!accepted||!accepted->get()){
                state->uncertain=true;completion(fail(ErrorCode::remote_error,"Invalid transfer acknowledgement"));return;
            }
            state->accepted=true;state->uncertain=false;state->checkpoint.reset();completion(true);
        });
        if(!request){state_->in_flight=false;return std::unexpected(request.error());}
        return {};
    }catch(...){
        state_->in_flight=false;state_->uncertain=true;
        try{link->close();}catch(...){}
        return fail(ErrorCode::unavailable,"Work request failed after the transfer attempt");
    }
}
bool RemoteTransfer::accepted() const{return state_->accepted;}
bool RemoteTransfer::uncertain() const{return state_->uncertain;}
bool RemoteTransfer::has_checkpoint() const{return bool(state_->checkpoint);}
Result<WorkCheckpoint> RemoteTransfer::reclaim(){
    if(state_->in_flight||state_->was_sent||state_->uncertain||state_->accepted||!state_->checkpoint)
        return fail(ErrorCode::invalid_state,"Transfer cannot be safely reclaimed");
    return std::move(state_->checkpoint);
}
} // namespace ii::compute_migration
