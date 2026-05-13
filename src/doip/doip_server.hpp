#pragma once

#include "iuds_server.hpp"

namespace doip {

class DoipServer {
public:
    explicit DoipServer(IUdsServer& udsServer);
    int run();

private:
    IUdsServer& udsServer_;
};

}  // namespace doip
