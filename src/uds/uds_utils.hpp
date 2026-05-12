#pragma once

#include <string>
#include <vector>

namespace uds {

inline std::string bytesToHex(const std::vector<uint8_t>& data) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(data.size() * 3);
    for (auto b : data) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
        out.push_back(' ');
    }
    if (!out.empty()) out.pop_back();
    return out;
}

}  // namespace uds
