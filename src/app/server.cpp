#include "../dcm/dcm_service.hpp"
#include "../doip/doip_server.hpp"

class UdsServerAdapter : public doip::IUdsServer {
public:
    std::vector<uint8_t> processUdsRequest(uint16_t, uint16_t, const std::vector<uint8_t>& request) override {
        return dcm_.handleRequest(request);
    }
    void tick(uint64_t nowMs) override { dcm_.tick(nowMs); }

private:
    dcm::DcmService dcm_;
};

int main() {
    UdsServerAdapter udsAdapter;
    doip::DoipServer server(udsAdapter);
    return server.run();
}
