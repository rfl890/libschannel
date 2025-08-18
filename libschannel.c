#ifdef DEBUG
#include <stdio.h>
#define dprintf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dprintf(...) ((void)0)
#endif

#include <Windows.h>
#include <subauth.h>

#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS
#include <security.h>
#include <schannel.h>

#include "libschannel.h"

#define LIBSCHANNEL_ISC_FLAGS                                                                                             \
    (ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY | ISC_REQ_REPLAY_DETECT |                   \
     ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM | ISC_REQ_USE_SUPPLIED_CREDS)


static void init_sec_buffer(SecBuffer *buffer, void *pvBuffer, unsigned long cbBuffer, unsigned long BufferType) {
    buffer->BufferType = BufferType;
    buffer->cbBuffer = cbBuffer;
    buffer->pvBuffer = pvBuffer;
}

static void init_sec_buffer_empty(SecBuffer *buffer, unsigned long BufferType) {
    buffer->BufferType = BufferType;
    buffer->cbBuffer = 0;
    buffer->pvBuffer = NULL;
}

static void init_sec_buffer_desc(SecBufferDesc *desc, SecBuffer *buffers, unsigned long buffer_count) {
    desc->ulVersion = SECBUFFER_VERSION;
    desc->cBuffers = buffer_count;
    desc->pBuffers = buffers;
}

/*
    Returns: 0 (on success)
            nonzero (on error, cast to an HRESULT)
*/
int tls_connect(struct tls_state *state, char *hostname, send_recv_func send, send_recv_func recv, void *extra) {
    SECURITY_STATUS status;
    SCH_CREDENTIALS credential = {.dwVersion = SCH_CREDENTIALS_VERSION,
                                  .dwCredFormat = 0,
                                  .cCreds = 0,
                                  .paCred = NULL,
                                  .hRootStore = NULL,
                                  .cMappers = 0,
                                  .aphMappers = NULL,
                                  .dwSessionLifespan = 0,
                                  .dwFlags =
                                      SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO,
                                  .cTlsParameters = 0,
                                  .pTlsParameters = NULL};

    if ((status = AcquireCredentialsHandleA(
             NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &credential, NULL, NULL, &state->cred_handle, NULL)) !=
        SEC_E_OK)
    {
        return (int)status;
    }

    state->in_buffer_size = 0;
    state->out_buffer_size = 0;
    state->out_buffer_used = 0;

    state->out_buffer = NULL;

    state->send = send;
    state->recv = recv;

    state->extra = extra;
    state->hostname = strdup(hostname);

    if (state->hostname == NULL) {
        status = E_OUTOFMEMORY;
        goto Error;
    }

    state->initialized = 0;
    state->closed = 0;

    while (1) {
        DWORD flags = LIBSCHANNEL_ISC_FLAGS;

        SecBuffer in_buffers[2];
        SecBuffer out_buffers[2];

        SecBufferDesc in_desc;
        SecBufferDesc out_desc;

        init_sec_buffer(&in_buffers[0], state->in_buffer, state->in_buffer_size, SECBUFFER_TOKEN);
        init_sec_buffer_empty(&in_buffers[1], SECBUFFER_EMPTY);

        init_sec_buffer_empty(&out_buffers[0], SECBUFFER_TOKEN);
        init_sec_buffer_empty(&out_buffers[1], SECBUFFER_ALERT);

        init_sec_buffer_desc(&in_desc, in_buffers, _countof(in_buffers));
        init_sec_buffer_desc(&out_desc, out_buffers, _countof(out_buffers));

        status = InitializeSecurityContext(
            &state->cred_handle,
            state->initialized ? &state->ctx_handle : NULL,
            state->initialized ? NULL : state->hostname,
            flags,
            0,
            0,
            state->initialized ? &in_desc : NULL,
            0,
            state->initialized ? NULL : &state->ctx_handle,
            &out_desc,
            &flags,
            0
        );

        state->initialized = 1;

        if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
            memmove(state->in_buffer, state->in_buffer + (state->in_buffer_size - in_buffers[1].cbBuffer), in_buffers[1].cbBuffer);
            state->in_buffer_size = in_buffers[1].cbBuffer;
        } else if (status != SEC_E_INCOMPLETE_MESSAGE) {
            state->in_buffer_size = 0;
        }

        switch (status) {
            case SEC_E_OK: {
                if (out_buffers[0].cbBuffer > 0) {
                    int succeeded = state->send(out_buffers[0].pvBuffer, out_buffers[0].cbBuffer, state->extra);
                    FreeContextBuffer(out_buffers[0].pvBuffer);
                    if (!succeeded) {
                        status = E_FAIL;
                        goto Error;
                    }
                }
                goto Success;
            }
            case SEC_I_CONTINUE_NEEDED: {
                int succeeded = state->send(out_buffers[0].pvBuffer, out_buffers[0].cbBuffer, state->extra);
                FreeContextBuffer(out_buffers[0].pvBuffer);
                if (!succeeded) {
                    status = E_FAIL;
                    goto Error;
                }
                break;
            }
            case SEC_I_INCOMPLETE_CREDENTIALS: {
                // we don't support this
                status = E_FAIL;
                goto Error;
            }
            case SEC_E_INCOMPLETE_MESSAGE: {
                break;
            }
            default: {
                goto Error;
            }
        }

        int read = state->recv(state->in_buffer + state->in_buffer_size, sizeof(state->in_buffer) - state->in_buffer_size, state->extra);
        if (read <= 0) {
            status = E_FAIL;
            goto Error;
        }

        state->in_buffer_size += read;
    }

Success:
    QueryContextAttributes(&state->ctx_handle, SECPKG_ATTR_STREAM_SIZES, &state->stream_sizes);
    return status;
Error:
    state->closed = 2;
    free(state->hostname);
    DeleteSecurityContext(&state->ctx_handle);
    FreeCredentialsHandle(&state->cred_handle);
    return status;
}


/*
Reads up to len bytes from the TLS socket
Returns: len on success
        < 0 on failure
         
*/

ptrdiff_t tls_read(struct tls_state *state, char *buf, ptrdiff_t len) {
	if (state->closed) {
		return 0;
	}

    ptrdiff_t amount_read = 0;

    while (len > 0) {
        if (state->out_buffer && (state->out_buffer_size > 0)) {
            unsigned long copy_amount = min(len, (ptrdiff_t)state->out_buffer_size);
            memcpy(buf, state->out_buffer, copy_amount);

            amount_read += copy_amount;
            buf += copy_amount;
            len -= copy_amount;

            if (copy_amount == state->out_buffer_size) {
                // We've used all the decrypted data
                // Move extra data to the front
                memmove(state->in_buffer, state->in_buffer + state->out_buffer_used, state->in_buffer_size - state->out_buffer_used);
                state->in_buffer_size -= state->out_buffer_used;
                
                state->out_buffer = NULL;
                state->out_buffer_used = 0;
                state->out_buffer_size = 0;
            } else {
                state->out_buffer_size -= copy_amount; 
                state->out_buffer += copy_amount;
            }
        } else {
            SecBuffer buffers[4];
            SecBufferDesc desc;
            
            init_sec_buffer(&buffers[0], state->in_buffer, state->in_buffer_size, SECBUFFER_DATA);
            init_sec_buffer_empty(&buffers[1], SECBUFFER_EMPTY);
            init_sec_buffer_empty(&buffers[2], SECBUFFER_EMPTY);
            init_sec_buffer_empty(&buffers[3], SECBUFFER_EMPTY);

            init_sec_buffer_desc(&desc, buffers, _countof(buffers));

            SECURITY_STATUS status = DecryptMessage(&state->ctx_handle, &desc, 0, NULL);
            
            switch (status) {
                case SEC_E_OK: {
                    state->out_buffer = buffers[1].pvBuffer;
                    state->out_buffer_size = buffers[1].cbBuffer;

                    state->out_buffer_used = state->in_buffer_size;
                    if (buffers[3].BufferType == SECBUFFER_EXTRA) {
                        state->out_buffer_used -= buffers[3].cbBuffer;
                    }

                    continue;
                }
                case SEC_I_CONTEXT_EXPIRED: {
                    // Shut down the connection
                    state->closed = 1;
                    goto Success;
                }
                case SEC_I_RENEGOTIATE: {
                    // Renegotiate
                    int i;
                    for (i = 0; i < 4; i++) {
                        if (buffers[i].BufferType == SECBUFFER_EXTRA) break;
                    }

                    DWORD flags = LIBSCHANNEL_ISC_FLAGS;

                    SecBuffer in_buffers[2];
                    SecBuffer out_buffers[2];

                    SecBufferDesc in_desc;
                    SecBufferDesc out_desc;

                    init_sec_buffer(&in_buffers[0], buffers[i].pvBuffer, buffers[i].cbBuffer, SECBUFFER_TOKEN);
                    init_sec_buffer_empty(&in_buffers[1], SECBUFFER_EMPTY);

                    init_sec_buffer_empty(&out_buffers[0], SECBUFFER_TOKEN);
                    init_sec_buffer_empty(&out_buffers[1], SECBUFFER_ALERT);

                    init_sec_buffer_desc(&in_desc, in_buffers, _countof(in_buffers));
                    init_sec_buffer_desc(&out_desc, out_buffers, _countof(out_buffers));

                    status = InitializeSecurityContext(
                        &state->cred_handle,
                        state->initialized ? &state->ctx_handle : NULL,
                        state->initialized ? NULL : state->hostname,
                        flags,
                        0,
                        0,
                        state->initialized ? &in_desc : NULL,
                        0,
                        state->initialized ? NULL : &state->ctx_handle,
                        &out_desc,
                        &flags,
                        0
                    );

                    if (status != SEC_E_OK) {
                        if (in_buffers[1].cbBuffer > 0) {
                            FreeContextBuffer(out_buffers[1].pvBuffer);
                        }
                        return status;
                    }

                    if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
                        memmove(state->in_buffer, state->in_buffer + (state->in_buffer_size - in_buffers[1].cbBuffer), in_buffers[1].cbBuffer);
                    }

                    state->out_buffer_used = state->in_buffer_size - in_buffers[1].cbBuffer;
                    state->in_buffer_size = in_buffers[1].cbBuffer;

                    continue;
                }
                case SEC_E_INCOMPLETE_MESSAGE: {
                    break;
                }
                default: {
                    return status;
                }
            }

            int result = state->recv(state->in_buffer + state->in_buffer_size, sizeof(state->in_buffer) - state->in_buffer_size, state->extra);
            if (result == 0) {
                state->closed = 1;
                goto Success;
            } else if (result < 0) {
                return status;
            }

            state->in_buffer_size += result;
        }
    }

Success:
    return amount_read;
}

/*
    Writes len bytes to the TLS socket.
    Return: 0 on success
            nonzero on failure
*/
int tls_write(struct tls_state *state, char *buf, size_t len) {
    if (state->closed) {
        return E_FAIL;
	}
    while (len > 0) {
        unsigned long copy_amount = min(len, (size_t)state->stream_sizes.cbMaximumMessage);
        char *write_buffer = _alloca(sizeof(state->in_buffer));

        SecBuffer buffers[4];
        SecBufferDesc desc;

        init_sec_buffer(&buffers[0], write_buffer, state->stream_sizes.cbHeader, SECBUFFER_STREAM_HEADER);
        init_sec_buffer(&buffers[1], write_buffer + state->stream_sizes.cbHeader, copy_amount, SECBUFFER_DATA);
        init_sec_buffer(&buffers[2], write_buffer + state->stream_sizes.cbHeader + copy_amount, state->stream_sizes.cbTrailer, SECBUFFER_STREAM_TRAILER);
        init_sec_buffer_empty(&buffers[3], SECBUFFER_EMPTY);

        init_sec_buffer_desc(&desc, buffers, _countof(buffers));

        memcpy(buffers[1].pvBuffer,  buf, copy_amount);

        
        desc.ulVersion = SECBUFFER_VERSION;
        desc.pBuffers = buffers;
        desc.cBuffers = _countof(buffers);

        SECURITY_STATUS status = EncryptMessage(&state->ctx_handle, 0, &desc, 0);
        if (status != SEC_E_OK) {
            return status;
        }

        if (!state->send(write_buffer, buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer, state->extra)) {
            return E_FAIL;
        }

        len -= copy_amount;
    }

    return 0;
}

 void tls_disconnect(struct tls_state *state) {
    if (state->closed != 2) {
        state->closed = 2;
        
        SECURITY_STATUS status;
        DWORD token = SCHANNEL_SHUTDOWN;
        DWORD flags = LIBSCHANNEL_ISC_FLAGS;

        SecBuffer buf_token;
        SecBufferDesc buf_token_desc;

        SecBuffer in_buffers[2];
        SecBuffer out_buffers[2];

        SecBufferDesc in_desc;
        SecBufferDesc out_desc;

        init_sec_buffer(&buf_token, &token, sizeof(token), SECBUFFER_TOKEN);
        init_sec_buffer_desc(&buf_token_desc, &buf_token, 1);

        ApplyControlToken(&state->ctx_handle, &buf_token_desc);

        // attempt to send any final data
        init_sec_buffer(&in_buffers[0], state->in_buffer, state->in_buffer_size, SECBUFFER_TOKEN);
        init_sec_buffer_empty(&in_buffers[1], SECBUFFER_EMPTY);

        init_sec_buffer_empty(&out_buffers[0], SECBUFFER_TOKEN);
        init_sec_buffer_empty(&out_buffers[1], SECBUFFER_ALERT);

        init_sec_buffer_desc(&in_desc, in_buffers, _countof(in_buffers));
        init_sec_buffer_desc(&out_desc, out_buffers, _countof(out_buffers));

        status = InitializeSecurityContext(&state->cred_handle,
                                        state->
                                        initialized ? &state->ctx_handle :
                                        NULL,
                                        state->
                                        initialized ? NULL : state->hostname,
                                        flags, 0, 0,
                                        state->initialized ? &in_desc : NULL,
                                        0,
                                        state->
                                        initialized ? NULL :
                                        &state->ctx_handle, &out_desc, &flags,
                                        0);

        if (status == SEC_E_OK) {
            // send the final shutdown message
            state->send(out_buffers[0].pvBuffer, out_buffers[0].cbBuffer, state->extra);
            FreeContextBuffer(out_buffers[0].pvBuffer);
        }

        DeleteSecurityContext(&state->ctx_handle);
        FreeCredentialsHandle(&state->cred_handle);
        free(state->hostname);
    }
}