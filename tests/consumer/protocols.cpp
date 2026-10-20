#include <iiNetwork/Server.h>
#include <iiNetwork/Transport.h>
#include <iostream>

int main()
{
    using namespace ii::network;
    ii::runtime::EventLoop loop;
    NativeHttpTransport transport(loop);
    RestClient rest(transport, "https://example.com/api");
    RestRequest request; request.path = "binary"; request.method = "PUT";
    request.body = std::string("a\0b", 3); request.parse_json_response = false;
    auto prepared = rest.prepare(request);
    if (!prepared || prepared->body != *request.body) return 1;
    GraphQLClient graphql(transport, "https://example.com/graphql");
    GraphQLRequest query; query.query = "query Status { status }"; query.operation_name = "Status";
    if (!graphql.prepare(query)) return 2;
    GraphQLService service([](const GraphQLRequest&)
    {
        GraphQLExecutionResult result;
        result.data = ii::core::Value(ii::core::Value::Object{});
        return result;
    });
    ServerRequest incoming; incoming.method = "POST"; incoming.target = "/graphql";
    incoming.headers["Content-Type"] = "application/json"; incoming.body = R"({"query":"{ status }"})";
    if (service(incoming).status != 200) return 3;
    std::cout << "iiNetwork installed REST/GraphQL protocol APIs passed\n";
}
