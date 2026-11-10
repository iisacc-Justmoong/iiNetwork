#include <iiSDKCore/Runtime/ManagedMemory.h>
#include <iiSDKCore/Runtime/MigratingWork.h>
#include <iiGPU/GPU.h>
#include "Kernel.h"
#include <array>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace ii::runtime;
using namespace ii::gpu;
using namespace std::chrono_literals;
namespace {
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
struct Gate final {std::mutex mutex;std::condition_variable cv;bool entered=false,open=false;
    void wait(){std::unique_lock lock(mutex);entered=true;cv.notify_all();if(!cv.wait_for(lock,5s,[&]{return open;}))throw std::runtime_error("CPU step timeout");}
    void started(){std::unique_lock lock(mutex);if(!cv.wait_for(lock,5s,[&]{return entered;}))throw std::runtime_error("CPU step absent");}
    void release(){std::lock_guard lock(mutex);open=true;cv.notify_all();}
};
}
int main(){try{
    auto device=Device::create();if(!device&&(device.error().code==ErrorCode::unsupported||device.error().code==ErrorCode::unavailable))return 77;
    auto gpu=example::take(std::move(device));check(gpu.adapter().hardware,"hardware GPU required");
    Runtime cpu_worker({.workers=1,.capacity=4}),gpu_worker({.workers=1,.capacity=4});
    MemoryPool host(1024);auto block=host.allocate(16).value();const std::array<std::uint32_t,4> input{1,2,3,4};
    std::memcpy(block.bytes().data(),input.data(),block.size());std::vector<std::byte> initial(block.bytes().begin(),block.bytes().end());block.reset();
    Gate gate;std::thread::id cpu_thread,gpu_thread;
    MigrationProgram cpu{"transform",1,[&](std::span<const std::byte> bytes){
        cpu_thread=std::this_thread::get_id();gate.wait();std::array<std::uint32_t,4> values{};std::memcpy(values.data(),bytes.data(),bytes.size());
        for(auto& value:values)++value;auto view=std::as_bytes(std::span(values));return MigrationStep{{view.begin(),view.end()},false};
    }};
    MigrationProgram accelerated{"transform",1,[&](std::span<const std::byte> bytes){
        gpu_thread=std::this_thread::get_id();auto pipeline=example::take(gpu.compute_pipeline(example::transform()));
        auto source=example::take(gpu.buffer({bytes.size()})),destination=example::take(gpu.buffer({bytes.size()}));
        example::take(source.upload(bytes));const std::array<Binding,2> bindings{{{source},{destination}}};
        const std::array<std::uint32_t,3> constants{4,7,13};auto commands=gpu.commands();
        example::take(commands.dispatch(pipeline,bindings,{1,1,1},std::as_bytes(std::span(constants))));example::take(commands.finish());
        example::take(example::take(gpu.submit(std::move(commands))).wait());std::vector<std::byte> output(bytes.size());
        example::take(destination.read(output));return MigrationStep{std::move(output),true};
    }};
    auto work=MigratingWork::start(cpu_worker,std::move(cpu),std::move(initial)).value();gate.started();
    check(bool(work.migrate(gpu_worker,std::move(accelerated))),"request CPU-to-GPU work migration");gate.release();
    auto status=work.wait(10s);check(status&&status->state==MigrationState::completed,"GPU work did not complete");
    auto bytes=work.result().value();std::array<std::uint32_t,4> output{};std::memcpy(output.data(),bytes.data(),bytes.size());
    check(output==std::array<std::uint32_t,4>{27,34,41,48}&&cpu_thread!=gpu_thread,"CPU-to-GPU state or computation mismatch");
    check(host.stats().used==0&&gpu.stats().allocated_bytes==0,"completed work retained native allocations");
    std::cout<<"CPU_GPU_MIGRATION_OK "<<gpu.adapter().name<<'\n';
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
