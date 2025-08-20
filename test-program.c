/*
    Simple TLS-only wget. Minimal URI parsing.
    Usage: wget https://google.com
           wget https://www.google.com > google.html
           wget https://some.download.server/binary-file.bin > binary-file.bin
    
    Compilation: gcc -O3 -flto -s -owget.exe test-program.c libschannel.c -lws2_32 -lsecur32
*/

#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include <winsock2.h>

#include <Windows.h>

#include "libschannel.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

static int send_wrap(char *buffer, int len, void *extra)
{
    int written = 0;
    while (written < len)
    {
        written += send((SOCKET)extra, buffer + written, len - written, 0);
        if (written <= 0)
            break;
    }
    return written == len;
}

static int recv_wrap(char *buffer, int len, void *extra)
{
    int result = recv((SOCKET)extra, buffer, (int)len, 0);
    return result;
}

static char *hresult_to_error_string(HRESULT result) {
	char *output = NULL;

	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
				   | FORMAT_MESSAGE_IGNORE_INSERTS |
				   FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, result,
				   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				   (char *) &output, 0, NULL);
	return output;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    _setmode(_fileno(stdout), _O_BINARY);

    if (argc < 2) {
        eprintf("Usage: wget [url]\n");
        exit(1);
    }

    WSADATA wsaData;
    WSAStartup(WINSOCK_VERSION, &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        eprintf("Error creating socket: %s\n", hresult_to_error_string(GetLastError()));
        exit(1);
    }

    char *url = strdup(argv[1]);
    char *host = strchr(url, ':') + 3;
    char *path = strchr(host, '/');
    if (path != NULL) {
        int sz = (path - host) + 1;
        char *ohost = host;
        host = calloc(sz, 1);
        memcpy(host, ohost, sz - 1);
    }
    path = path ? path : "/";
    
    WINBOOL result = WSAConnectByNameA(sock, host, "https", NULL, NULL, NULL, NULL, NULL, NULL);
    if (result != TRUE) {
        eprintf("Error connecting to remote host %s: %s\n", host, hresult_to_error_string(GetLastError()));
        exit(1);
    }
    int buffer_size = snprintf(NULL, 0, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    buffer_size += 1;
    char *request_buffer = malloc(buffer_size);
    snprintf(request_buffer, buffer_size, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    buffer_size -= 1;

    struct tls_state state;
    result = tls_connect(&state, host, send_wrap, recv_wrap, (void *)sock);
    if (result != 0) {
        eprintf("Error during handshake (%08lx): %s\n", (HRESULT)result, hresult_to_error_string(result));
        exit(1);
    }

    result = tls_write(&state, request_buffer, buffer_size);
    if (result != 0) {
        eprintf("Send failed\n");
        exit(1);
    }

    char outbuf[65536] = {0};

    ptrdiff_t read = tls_read(&state, outbuf, 65536);
    if (read < 0) {
        eprintf("Receive failed\n");
        exit(1);
    }
    
    char *out = strstr(outbuf, "\r\n\r\n") + 4;
    ptrdiff_t data_offset = out - outbuf;
    if ((read - data_offset) > 0) {
        fwrite(outbuf + data_offset, 1, read - data_offset, stdout);
    }
    while (1) {
        read = tls_read(&state, outbuf, 65536);
        if (read < 0) {
            eprintf("Receive failed\n");
            exit(1);
        } else if (read == 0) {
            break;
        }
        fwrite(outbuf, 1, read, stdout);
    }

    return 0;
}