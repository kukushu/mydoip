#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/socket.h>

namespace doip {

inline bool sendAll(int fd, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        const ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

inline bool recvAll(int fd, uint8_t* data, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        const ssize_t n = recv(fd, data + recvd, len - recvd, 0);
        if (n <= 0) return false;
        recvd += static_cast<size_t>(n);
    }
    return true;
}

}  // namespace doip
