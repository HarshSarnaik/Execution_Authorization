#include "telemetry/netlink_conn.h"
#include "crypto/evp_verifier.h"
#include "enforcement/state_machine.h"
#include <cstring>
#include <cerrno>

// Global State Machine Instance for integration
StateMachine eal_state_machine;

NetlinkTelemetry::~NetlinkTelemetry() {
    if (nl_sock != -1) {
        unsubscribe();
        close(nl_sock);
    }
}

bool NetlinkTelemetry::init() {
    nl_sock = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
    if (nl_sock == -1) return false;

    struct sockaddr_nl sa_nl;
    memset(&sa_nl, 0, sizeof(sa_nl));
    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();

    if (bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl)) == -1) {
        close(nl_sock);
        return false;
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    setsockopt(nl_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    return true;
}

bool NetlinkTelemetry::send_mcast_op(enum proc_cn_mcast_op op) {
    if (nl_sock == -1) return false;
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct cn_msg *cnm = (struct cn_msg *)NLMSG_DATA(nlh);
    enum proc_cn_mcast_op *mcop = (enum proc_cn_mcast_op *)cnm->data;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_type = NLMSG_DONE;
    cnm->id.idx = CN_IDX_PROC;
    cnm->id.val = CN_VAL_PROC;
    cnm->len = sizeof(enum proc_cn_mcast_op);
    *mcop = op;
    return send(nl_sock, buf, nlh->nlmsg_len, 0) != -1;
}

bool NetlinkTelemetry::subscribe() { return send_mcast_op(PROC_CN_MCAST_LISTEN); }
bool NetlinkTelemetry::unsubscribe() { return send_mcast_op(PROC_CN_MCAST_IGNORE); }

void NetlinkTelemetry::process_events() {
    if (nl_sock == -1) return;
    char buff[1024];
    ssize_t len = recv(nl_sock, buff, sizeof(buff), 0);
    if (len == -1) return;

    struct nlmsghdr *nlh = (struct nlmsghdr *)buff;
    while (NLMSG_OK(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) break;
        if (nlh->nlmsg_type == NLMSG_NOOP) continue;

        struct cn_msg *cnm = (struct cn_msg *)NLMSG_DATA(nlh);
        struct proc_event *ev = (struct proc_event *)cnm->data;

        switch (ev->what) {
            case PROC_EVENT_FORK:
                // Apply a minor trust penalty to the parent for spawning a child
                eal_state_machine.penalize_process(ev->event_data.fork.parent_pid, 200);
                break;
            case PROC_EVENT_EXEC: {
                pid_t exec_pid = ev->event_data.exec.process_pid;
                std::string hash = CryptoVerifier::calculate_sha256(exec_pid);
                std::cout << "[EVENT] EXEC - PID: " << exec_pid << " | SHA-256: " << hash << "\n";
                eal_state_machine.register_process(exec_pid, hash);
                break;
            }
            case PROC_EVENT_EXIT:
                eal_state_machine.remove_process(ev->event_data.exit.process_pid);
                break;
            default: break;
        }
        nlh = NLMSG_NEXT(nlh, len);
    }
}
