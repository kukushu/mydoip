#pragma once

#include "idid_store.hpp"

#include <unordered_map>

namespace dcm {

class RamDidStore : public IDidStore {
public:
    std::optional<std::vector<uint8_t>> read(uint16_t did) const override;
    void write(uint16_t did, const std::vector<uint8_t>& data) override;

private:
    std::unordered_map<uint16_t, std::vector<uint8_t>> didStore_;
};

}  // namespace dcm
