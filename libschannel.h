#ifndef ___LIBSCHANNEL_H
#define ___LIBSCHANNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


#include <Windows.h>

#define SECURITY_WIN32
#include <security.h>

typedef int(send_recv_func)(char *buffer, int len, void *extra);

enum libschannel_connection_state {
	LIBSCHANNEL_OPEN = 0,
	LIBSCHANNEL_CLOSED = 1,
	LIBSCHANNEL_CLOSED_AND_FREED = 2
};

typedef struct tls_state {
	// handles
	CredHandle cred_handle;
	CtxtHandle ctx_handle;

	// buffers
	char in_buffer[16384 + 256]; // input buffer (to read from server)
	unsigned long in_buffer_offset;

	char *out_buffer; // output buffer (to send to server)
	unsigned long out_buffer_length;
	unsigned long out_buffer_extra;

	// functions
	send_recv_func *send;
	send_recv_func *recv;
	void *extra;

	// data
	char *hostname;
	SecPkgContext_StreamSizes stream_sizes;
	bool initialized;
	enum libschannel_connection_state connection_state;
} tls_state_t;

int tls_connect(tls_state_t *state,
                char *hostname,
                send_recv_func *send,
                send_recv_func *recv,
                void *extra);
int tls_write(struct tls_state *state, char *buf, size_t len);
ptrdiff_t tls_read(tls_state_t *state, char *buf, ptrdiff_t len);
void tls_disconnect(tls_state_t *state);

#endif