#include "doip_server.hpp"

#include "../config/demo_config.hpp"
#include "doip_connection.hpp"
#include "../common/log/logger.hpp"

#include <arpa/inet.h>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

namespace doip {

DoipServer::DoipServer(IUdsServer& udsServer) : udsServer_(udsServer) {}

int DoipServer::run() {
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) return 1;

    int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config::kDoipPort);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) return 1;
    if (listen(serverFd, 1) < 0) return 1;

    LOG_INFO("DOIP", "Server listening on 0.0.0.0:" + std::to_string(config::kDoipPort));
    while (true) {
        sockaddr_in clientAddr{};
        socklen_t len = sizeof(clientAddr);
        int clientFd = accept(serverFd, reinterpret_cast<sockaddr*>(&clientAddr), &len);
        if (clientFd < 0) { LOG_WARN("DOIP", "accept failed"); continue; }
        LOG_INFO("DOIP", "Client connected");
        DoipConnection conn(clientFd, udsServer_);
        conn.run();
    }
    close(serverFd);
    return 0;
}

}  // namespace doip
