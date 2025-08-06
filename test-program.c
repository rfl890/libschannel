#include <stdio.h>
#include <winsock2.h>
#include "libschannel.h"


int send_wrap(char *buffer, int len, void *extra)
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

int recv_wrap(char *buffer, int len, void *extra)
{
    int result = recv((SOCKET)extra, buffer, (int)len, 0);
    return result;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 9);
    WSADATA wsaData;
    WSAStartup(0x2020, &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    WSAConnectByNameA(sock, "www.google.com", "https", NULL, NULL, NULL, NULL, NULL, NULL);

    struct tls_state state;
    int result = tls_connect(&state, "www.google.com", send_wrap, recv_wrap, (void *)sock);
    if (result != 0) {
        printf("Error during handshake: %08lx\n", (HRESULT)result);
        exit(1);
    }
    printf("Handshake successful!\n");
    
    char req[1024];
    size_t len = sprintf(req, "GET /images/branding/googlelogo/2x/googlelogo_light_color_92x30dp.png HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", "www.google.com");

    result = tls_write(&state, req, len);
    if (result != 0) {
        printf("Send failed\n");
        exit(1);
    }

    char outbuf[65536];

    ptrdiff_t read = tls_read(&state, outbuf, 65536);

    if (read < 0) {
        printf("Receive failed\n");
        exit(1);
    }

    size_t i;

    for (i = 0; i < read - 8; i++) {
        uint64_t buf;
        memcpy(&buf, outbuf + i, 8);
        if (buf == 0x0A1A0A0D474E5089) {
            printf("Found PNG header at offext %08x\n", i);
            break;
        }
    }

    FILE *f = fopen("out.png", "wb");
    fwrite(outbuf + i, 1, read - i, f);
    fclose(f);
}