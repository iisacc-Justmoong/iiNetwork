#include <iiNetwork/Wire.h>
#include <cstdlib>
#include <iostream>

int main() {
    using namespace ii::network::wire;
    const Value input(Object{{"nested", Value(Array{Value("한글"), Value(std::int64_t{-42}), Value(true)})}});
    const auto encoded = json(input);
    const auto decoded = parse_json(encoded);
    if (!decoded || *decoded != input || !json(input, 2).empty() || parse_json(encoded, 2)) {
        std::cerr << "wire JSON must preserve Core values and enforce limits\n";
        return EXIT_FAILURE;
    }
    ii::json::Limits depth_limit;
    depth_limit.depth = 2;
    const auto too_deep = json_codec::stringify(input, depth_limit);
    ii::json::Limits item_limit;
    item_limit.items = 1;
    const auto too_many = json_codec::stringify(input, item_limit);
    const auto binary = json_codec::stringify(Value(ii::core::Bytes{std::byte{1}}));
    if (too_deep || too_deep.error().code != ii::json::ErrorCode::limit_exceeded ||
        too_many || too_many.error().code != ii::json::ErrorCode::limit_exceeded ||
        binary || binary.error().code != ii::json::ErrorCode::unsupported_value) {
        std::cerr << "wire JSON must reject excessive nesting, items and binary values\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
