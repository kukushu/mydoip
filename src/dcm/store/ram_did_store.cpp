#include "ram_did_store.hpp"

namespace dcm {

std::optional<std::vector<uint8_t>> RamDidStore::read(uint16_t did) const {
    auto it = didStore_.find(did);
    if (it == didStore_.end()) return std::nullopt;
    return it->second;
}

void RamDidStore::write(uint16_t did, const std::vector<uint8_t>& data) { didStore_[did] = data; }

}  // namespace dcm
