#pragma once

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <unistd.h>
#include <iostream>

class NetlinkTelemetry {
private:
    int nl_sock = -1;
    bool send_mcast_op(enum proc_cn_mcast_op op);

public:
    NetlinkTelemetry() = default;
    ~NetlinkTelemetry();

    bool init();
    bool subscribe();
    bool unsubscribe();
    int get_fd() const { return nl_sock; }
    void process_events(); // Polls the socket and decodes the stream
};
