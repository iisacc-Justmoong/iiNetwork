#include <iiNetwork/Stack.h>
#include <iostream>
#include <stdexcept>

template <class T> T checked(ii::network::Result<T> result)
{
    if (!result) throw std::runtime_error(result.error().message);
    return std::move(*result);
}
void checked(ii::network::Result<void> result)
{
    if (!result) throw std::runtime_error(result.error().message);
}
int main()
{
    using namespace ii::network;
    try
    {
        ii::runtime::EventLoop loop;
        auto [left, right] = MemoryMedium::pair();
        StackEndpoint a{checked(MacAddress::parse("02:00:00:00:00:01")), checked(Ipv4Address::parse("10.0.0.1")), 4001};
        StackEndpoint b{checked(MacAddress::parse("02:00:00:00:00:02")), checked(Ipv4Address::parse("10.0.0.2")), 4002};
        NetworkStack sender(loop, a, left), receiver(loop, b, right);
        StackPeer destination{b.ip, b.port, b.mac}, source{a.ip, a.port, a.mac};
        checked(sender.network.routes.add({checked(Ipv4Address::parse("10.0.0.0")), 24, {}, "memory", 0}));
        auto session = checked(sender.session.open(destination.identity()));
        checked(receiver.session.adopt(session, source.identity()));
        // A product supplies authenticated peer/key establishment.
        Aes256Gcm cipher(checked(Aes256Gcm::generate_key()));
        ii::core::Value message(ii::core::Value::Object{{"message", ii::core::Value("Hello, iiNetwork")}});
        checked(sender.send(session, destination, message, cipher));
        auto result = checked(receiver.receive(cipher));
        if (!result || result->value != message) throw std::runtime_error("Message mismatch");
        std::cout << "iiNetwork: seven layer objects, authenticated message roundtrip\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
