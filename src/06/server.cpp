#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <vector>


static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

static void fd_set_nonblocking(int fd) {
    errno = 0;
    int flags = fcntl(fd, F_GETFL, 0);
    if (errno) {
        die("fcntl error");
        return;
    }

    flags = flags | O_NONBLOCK;
    errno = 0;
    (void) fcntl(fd, F_GETFL, flags);
    if (errno) {
        die("fcntl error");
    }
}


const size_t k_max_msg = 4096;

enum {
    STATE_REQ = 0, // reading requests
    STATE_RES = 1, // sending responses
    STATE_END = 2,
};

struct Conn {
    int fd = -1;
    uint32_t state = 0;     // either STATE_REQ or STATE_RES
    // buffer for reading
    size_t read_buf_size = 0;
    uint8_t read_buf[4 + k_max_msg];
    // buffer for writing
    size_t write_buf_size = 0;
    size_t write_buf_sent = 0;
    uint8_t write_buf[4 + k_max_msg];
};


static void connection_put(std::vector<Conn *> &fd2connections, struct Conn *connection) {
    if (fd2connections.size() <= (size_t) connection->fd) {
        fd2connections.resize(connection->fd + 1);
    }
    fd2connections[connection->fd] = connection;
}

static int32_t accept_new_connection(std::vector<Conn *> &fd2connections, int fd) {
    // accept
    struct sockaddr_in client_addr = {};
    socklen_t socklen = sizeof(client_addr);
    int connection_fd = accept(fd, (struct sockaddr *) &client_addr, &socklen);
    if (connection_fd < 0) {
        msg("accept() error");
        return -1; // error
    }

    // set the new connection fd to nonblocking mode
    fd_set_nonblocking(connection_fd);
    // create the struct Conn
    struct Conn *connection = (struct Conn *) malloc(sizeof(struct Conn));
    if (!connection) {
        close(connection_fd);
        return -1;
    }
    connection -> fd = connection_fd;
    connection -> state = STATE_REQ;
    connection -> read_buf_size = 0;
    connection -> write_buf_size = 0;
    connection -> write_buf_sent = 0;
    connection_put(fd2connections, connection);
    return 0 ;
}

static void state_req(Conn *conn);
static void state_res(Conn *conn);

static void connection_io(Conn *connection) {
    if (connection -> state == STATE_REQ) {
        state_req(connection);
    } else if (connection -> state == STATE_RES) {
        state_res(connection);
    } else {
        assert(0); // not expected
    }   
}



static bool try_one_request(Conn *connection) {
    // try to parse a request from the buffer
    if (connection -> read_buf_size < 4) {
        // not enough data in the buffer. will retry in the next iteration
        return false;
    }
    uint32_t len = 0;
    memcpy(&len, &connection->read_buf[0], 4);
    if (len > k_max_msg) {
        msg("too long");
        connection -> state = STATE_END;
        return false;
    }
    if (4 + len > connection -> read_buf_size) {
            // not enough date in the buffer. Will retry in next iteration
            return false;
    }
    // got one request, do something with it
    printf("client says %.*\n", len, &connection -> read_buf[4]);

    // generating echo response
    memcpy(&connection -> write_buf[0], &len, 4);
    memcpy(&connection -> write_buf[4], &connection -> read_buf[4], len);
    connection -> write_buf_size = 4 + len;

    // remove the request from the buffer
    size_t remain = connection -> read_buf_size - 4 - len;
    if (remain) {
        memmove(connection -> read_buf, &connection -> read_buf[4+len], remain);
    }
    connection -> read_buf_size = remain;

    // change state
    connection -> state = STATE_RES;
    state_res(connection);
    // continue the outer loop if the request was fully processed
    return (connection -> state == STATE_REQ);
}
static bool try_fill_buffer(Conn *connection) {
    // try to fill the buffer
    assert(connection -> read_buf_size < sizeof(connection -> read_buf_size));
    ssize_t rv = 0;
    do {
        size_t cap = sizeof(connection -> read_buf) - connection -> read_buf_size;
        rv = read(connection -> fd, &connection -> read_buf[connection -> read_buf_size], cap);
    } while (rv < 0 && errno == EINTR);
    if (rv < 0 && errno == EAGAIN) {
        // got EAGAIN, stop.
        return false;
    }
    if (rv < 0) {
        msg("read() error");
        connection -> state = STATE_END;
        return false;
    }
    if (rv == 0) {
        if (connection -> read_buf_size > 0) {
            msg("unexpected EOF");
        } else {
            msg("EOF");
        }
        connection -> state = STATE_END;
        return false;
    }
    connection -> read_buf_size += (size_t) rv;
    assert(connection -> read_buf_size <= sizeof(connection -> read_buf));

    // try to process requests one by one
    while (try_one_request(connection)){}
    return (connection -> state == STATE_REQ);
}



static void state_req(Conn *connection) {
    while(try_fill_buffer(connection)) {}
}



static bool try_flush_buffer(Conn *connection) {
    ssize_t rv = 0;
    do {
        size_t remain = connection->write_buf_size - connection -> write_buf_sent;
        rv = write(connection -> fd, &connection -> write_buf[connection -> write_buf_sent], remain);
    } while (rv < 0 && errno == EINTR);
    if (rv < 0 && errno == EAGAIN) {
        // got EAGAIN, stop
        return false;
    }
    if (rv < 0) {
        msg("write() error");
        connection -> state = STATE_END;
        return false;
    }
    connection -> write_buf_sent += (size_t) rv;
    assert(connection -> write_buf_sent <= connection -> write_buf_size);
    if (connection -> write_buf_sent == connection -> write_buf_size) {
        // reponse was fully sent, change state back
        connection -> state = STATE_REQ;
        connection -> write_buf_sent = 0;
        connection -> write_buf_size = 0;
        return false;
    }
    // still have some data in write buf, coudl try write again
    return true;
}
static void state_res(Conn *connection) {
    while (try_flush_buffer(connection)) {}
}


int main() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket()");
    }

    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    // bind
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(0);    // wildcard address 0.0.0.0
    int rv = bind(fd, (const sockaddr *)&addr, sizeof(addr));
    if (rv) {
        die("bind()");
    }

    // listen
    rv = listen(fd, SOMAXCONN);
    if (rv) {
        die("listen()");
    }

    // a map of all client connections, keyed by fd
    std::vector<Conn *> fd2conn;

    // set the listen fd to nonblocking mode
    fd_set_nonblocking(fd);

    // the event loop
    std::vector<struct pollfd> poll_args;
    while (true) {
        // prepare the arguments of the poll()
        poll_args.clear();
        // for convenience, the listening fd is put in the first position
        struct pollfd pfd = {fd, POLLIN, 0};
        poll_args.push_back(pfd);
        // connection fds
        for (Conn *conn : fd2conn) {
            if (!conn) {
                continue;
            }
            struct pollfd pfd = {};
            pfd.fd = conn->fd;
            pfd.events = (conn->state == STATE_REQ) ? POLLIN : POLLOUT;
            pfd.events = pfd.events | POLLERR;
            poll_args.push_back(pfd);
        }

        // poll for active fds
        // the timeout argument doesn't matter here
        int rv = poll(poll_args.data(), (nfds_t)poll_args.size(), 1000);
        if (rv < 0) {
            die("poll");
        }

        // process active connections
        for (size_t i = 1; i < poll_args.size(); ++i) {
            if (poll_args[i].revents) {
                Conn *conn = fd2conn[poll_args[i].fd];
                connection_io(conn);
                if (conn->state == STATE_END) {
                    // client closed normally, or something bad happened.
                    // destroy this connection
                    fd2conn[conn->fd] = NULL;
                    (void)close(conn->fd);
                    free(conn);
                }
            }
        }

        // try to accept a new connection if the listening fd is active
        if (poll_args[0].revents) {
            (void)accept_new_connection(fd2conn, fd);
        }
    }

    return 0;
}
























