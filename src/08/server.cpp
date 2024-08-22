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
#include <string>
#include <vector>
// local implementation
#include "hashtable.h"

#define container_of(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type, member) );})


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
    (void)fcntl(fd, F_GETFL, flags);
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
    if (fd2connections.size() <= (size_t)connection->fd) {
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
    connection->fd = connection_fd;
    connection->state = STATE_REQ;
    connection->read_buf_size = 0;
    connection->write_buf_size = 0;
    connection->write_buf_sent = 0;
    connection_put(fd2connections, connection);
    return 0 ;
}

static void state_req(Conn *conn);
static void state_res(Conn *conn);

const size_t k_max_args = 1024;

static void connection_io(Conn *connection) {
    if (connection -> state == STATE_REQ) {
        state_req(connection);
    } else if (connection -> state == STATE_RES) {
        state_res(connection);
    } else {
        assert(0); // not expected
    }   
}

static int32_t parse_request(
    const uint8_t *data, size_t len, std::vector<std::string> &out) 
    {
        if (len < 4) {
            return -1;
        }

        uint32_t n = 0;
        memcpy(&n, &data[0], 4);
        if (n > k_max_args) {
            return -1;
        }
        size_t pos = 4;
        while (n--) {
            if (pos + 4 > len) {
                return -1;
            } 
            uint32_t sz = 0;
            memcpy(&sz, &data[pos], 4);
            if (pos + 4 + sz > len) {
                return -1;
            }
            out.push_back(std::string((char*)&data[pos+4], sz));
            pos += 4 + sz;
        }

        if (pos != len) {
            return -1;   // trailing garbage
        }
        return 0;

 }

 enum {
    RES_OK = 0,
    RES_ERR = 1,
    RES_NX = 2,
 };


// use the hashmap we implemented
static struct {
    HMap db;
} g_data;

// the structure for the key
struct Entry {
    struct HNode node;
    std::string key;
    std::string val;
};

static bool entry_eq(HNode *lhs, HNode *rhs) {
    struct Entry *le = container_of(lhs, struct Entry, node);
    struct Entry *re = container_of(rhs, struct Entry, node);
    return le->key == re->key;
}

static uint64_t str_hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len; i++) {
        h = (h + data[i]) * 0x01000193;
    }
    return h;
}

static uint32_t do_get(
    std::vector<std::string> &cmd, uint8_t *res, uint32_t *reslen)
{
    Entry key; 
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (!node) {
        return RES_NX;
    }

    const std::string &val = container_of(node, Entry, node)->val;
    assert(val.size() <= k_max_msg);
    memcpy(res, val.data(), val.size());
    *reslen = (uint32_t)val.size();
    return RES_OK;
}

static uint32_t do_set(
    std::vector<std::string> &cmd, uint8_t *res, uint32_t *reslen)
{
   (void)res;
   (void)reslen;

    Entry key; 
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (node) {
        container_of(node, Entry, node)->val.swap(cmd[2]);
    } else {
        Entry *ent = new Entry();
        ent->key.swap(key.key);
        ent->node.hcode = key.node.hcode;
        ent->val.swap(cmd[2]);
        hm_insert(&g_data.db, &ent->node);
    }
    return RES_OK;
}

static uint32_t do_del(
    std::vector<std::string> &cmd, uint8_t *res, uint32_t *reslen)
{
    (void)res;
    (void)reslen;
    Entry key; 
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_pop(&g_data.db, &key.node, &entry_eq);
    if (node) {
        delete container_of(node, Entry, node);
    }
    return RES_OK;
}

static bool cmd_is(const std::string &word, const char *cmd) {
    return 0 == strcasecmp(word.c_str(), cmd);
}

static uint32_t do_request(
    const uint8_t *request, uint32_t request_length,
    uint32_t *response_code, uint8_t *response,
    uint32_t *response_length) 
{
    std::vector<std::string> cmd;
    if (0 != parse_request(request, request_length, cmd)) {
        msg("bad request");
        return -1;
    }
    if (cmd.size() == 2 && cmd_is(cmd[0], "get")) {
        *response_code = do_get(cmd, response, response_length);
    } else if (cmd.size() == 3 && cmd_is(cmd[0], "set")) {
        *response_code = do_set(cmd, response, response_length);
    } else if (cmd.size() == 2 && cmd_is(cmd[0], "del")) {
        *response_code = do_del(cmd, response, response_length);
    } else {
        // cmd is not recognized
        *response_code = RES_ERR;
        const char *msg = "Unknown cmd";
        strcpy((char *)response, msg);
        *response_length = strlen(msg);
        return 0;
    }
    return 0;
}

static bool try_one_request(Conn *connection) {
    // try to parse a request from the buffer

    if (connection->read_buf_size < 4) {
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
    if (4 + len > connection->read_buf_size) {
            // not enough date in the buffer. Will retry in next iteration
            return false;
    }
    
    // got one request, generate the response
    uint32_t response_code = 0;
    uint32_t write_length = 0;
    uint32_t err = do_request(
                &connection->read_buf[4], len, &response_code,
                &connection->write_buf[4+4], &write_length);
    if (err) {
            connection->state = STATE_END;
            return false;
    }
    write_length += 4;

    memcpy(&connection->write_buf[0], &len, 4);
    memcpy(&connection->write_buf[4], &response_code, len);
    connection->write_buf_size = 4 + len;

    // remove the request from the buffer
    size_t remain = connection->read_buf_size - 4 - len;
    if (remain) {
        memmove(connection->read_buf, &connection->read_buf[4+len], remain);
    }
    connection -> read_buf_size = remain;

    // change state
    connection->state = STATE_RES;
    state_res(connection);
    // continue the outer loop if the request was fully processed
    return (connection -> state == STATE_REQ);
}

static bool try_fill_buffer(Conn *connection) {
    // try to fill the buffer
    assert(connection->read_buf_size < sizeof(connection->read_buf));
    ssize_t rv = 0;
    do {
        size_t cap = sizeof(connection->read_buf) - connection->read_buf_size;
        rv = read(connection->fd, &connection->read_buf[connection->read_buf_size], cap);
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
        if (connection->read_buf_size > 0) {
            msg("unexpected EOF");
        } else {
            msg("EOF");
        }
        connection->state = STATE_END;
        return false;
    }
    connection->read_buf_size += (size_t) rv;
    assert(connection->read_buf_size <= sizeof(connection->read_buf));

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
        connection->state = STATE_REQ;
        connection->write_buf_sent = 0;
        connection->write_buf_size = 0;
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