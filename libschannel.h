#ifndef ___LIBSCHANNEL_H
#define ___LIBSCHANNEL_H

#include <stdint.h>
#include <stddef.h>

#include <Windows.h>

#define SECURITY_WIN32
#include <security.h>

typedef int(send_recv_func)(char *buffer, int len, void *extra);

struct tls_state {
    // handles
    CredHandle cred_handle;
    CtxtHandle ctx_handle;

    // buffers
    char in_buffer[16384 + 256]; // input buffer (to read from server)
    unsigned long in_buffer_size; // amount of data currently in input buffer

    char *out_buffer; // output buffer (for decrypted data), this is essentially the same as input buffer data is decrypted in place
    unsigned long out_buffer_size; // amount of data currently in output buffer (excluding extra)
    unsigned long out_buffer_used; // amount of extraneous data currently in output buffer

    // functions
    send_recv_func *send;
    send_recv_func *recv;

    // data
    void *extra;
    char *hostname;
    SecPkgContext_StreamSizes stream_sizes;

    int initialized;
};

int tls_connect(struct tls_state *state, char *hostname, send_recv_func send, send_recv_func recv, void *extra);
int tls_write(struct tls_state *state, char *buf, size_t len);
ptrdiff_t tls_read(struct tls_state *state, char *buf, ptrdiff_t len);

#endif