#ifdef DEBUG
#include <stdio.h>
#define dprintf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dprintf(...) ((void)0)
#endif

#include <stdbool.h>

#include <Windows.h>
#include <subauth.h>

#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>
#include <security.h>

#include "libschannel.h"

#define LIBSCHANNEL_ISC_FLAGS                                                  \
	(ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY |   \
	 ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM |        \
	 ISC_REQ_USE_SUPPLIED_CREDS)

static void init_sec_buffer(SecBuffer *buffer,
                            void *pvBuffer,
                            unsigned long cbBuffer,
                            unsigned long BufferType) {
	buffer->BufferType = BufferType;
	buffer->cbBuffer = cbBuffer;
	buffer->pvBuffer = pvBuffer;
}

static inline void init_sec_buffer_empty(SecBuffer *buffer,
                                         unsigned long BufferType) {
	init_sec_buffer(buffer, NULL, 0, BufferType);
}

static void init_sec_buffer_desc(SecBufferDesc *desc,
                                 SecBuffer *buffers,
                                 unsigned long buffer_count) {
	desc->ulVersion = SECBUFFER_VERSION;
	desc->cBuffers = buffer_count;
	desc->pBuffers = buffers;
}

#define SEC_STATUS_FAIL(status) ((status) != SEC_E_OK)

int tls_connect(tls_state_t *state,
                char *hostname,
                send_recv_func *send,
                send_recv_func *recv,
                void *extra) {
	SECURITY_STATUS status;
	SCH_CREDENTIALS credential = {.dwVersion = SCH_CREDENTIALS_VERSION,
	                              .dwCredFormat = 0,
	                              .cCreds = 0,
	                              .paCred = NULL,
	                              .hRootStore = NULL,
	                              .cMappers = 0,
	                              .aphMappers = NULL,
	                              .dwSessionLifespan = 0,
	                              .dwFlags = SCH_CRED_AUTO_CRED_VALIDATION |
	                                         SCH_CRED_NO_DEFAULT_CREDS |
	                                         SCH_USE_STRONG_CRYPTO,
	                              .cTlsParameters = 0,
	                              .pTlsParameters = NULL};

	if (SEC_STATUS_FAIL(status = AcquireCredentialsHandleA(NULL,
	                                                       UNISP_NAME_A,
	                                                       SECPKG_CRED_OUTBOUND,
	                                                       NULL,
	                                                       &credential,
	                                                       NULL,
	                                                       NULL,
	                                                       &state->cred_handle,
	                                                       NULL))) {
		goto Error;
	}

	state->in_buffer_offset = 0;

	state->out_buffer = NULL;
	state->out_buffer_length = 0;
	state->out_buffer_extra = 0;

	state->send = send;
	state->recv = recv;
	state->extra = extra;

	state->hostname = strdup(hostname);
	if (state->hostname == NULL) {
		status = E_OUTOFMEMORY;
		goto Error;
	}
	state->initialized = false;
	state->connection_state = LIBSCHANNEL_OPEN;

	// InitializeSecurityContext loop
	while (true) {
		DWORD flags = LIBSCHANNEL_ISC_FLAGS;

		SecBuffer in_buffers[2];
		SecBufferDesc in_buffers_desc;

		SecBuffer out_buffers[2];
		SecBufferDesc out_buffers_desc;

		init_sec_buffer(&in_buffers[0],
		                state->in_buffer,
		                state->in_buffer_offset,
		                SECBUFFER_TOKEN);
		init_sec_buffer_empty(&in_buffers[1], SECBUFFER_EMPTY);

		init_sec_buffer_empty(&out_buffers[0], SECBUFFER_TOKEN);
		init_sec_buffer_empty(&out_buffers[1], SECBUFFER_ALERT);

		init_sec_buffer_desc(
		    &in_buffers_desc, in_buffers, _countof(in_buffers));
		init_sec_buffer_desc(
		    &out_buffers_desc, out_buffers, _countof(out_buffers));

		status = InitializeSecurityContextA(
		    &state->cred_handle,
		    state->initialized ? &state->ctx_handle : NULL,
		    state->hostname,
		    flags,
		    0,
		    0,
		    state->initialized ? &in_buffers_desc : NULL,
		    0,
		    &state->ctx_handle,
		    &out_buffers_desc,
		    &flags,
		    0);

		state->initialized = true;

		if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
			memmove(state->in_buffer,
			        state->in_buffer +
			            (state->in_buffer_offset - in_buffers[1].cbBuffer),
			        in_buffers[1].cbBuffer);
			state->in_buffer_offset = in_buffers[1].cbBuffer;
		}

		switch (status) {
		case SEC_E_OK: {
			state->in_buffer_offset =
			    (in_buffers[1].BufferType == SECBUFFER_EXTRA)
			        ? in_buffers[1].cbBuffer
			        : 0;

			if (out_buffers[0].cbBuffer > 0) {
				int succeeded = state->send(out_buffers[0].pvBuffer,
				                            out_buffers[0].cbBuffer,
				                            state->extra);
				FreeContextBuffer(out_buffers[0].pvBuffer);
				if (!succeeded) {
					status = E_FAIL;
					goto Error;
				}
			}

			goto Success;
		}
		case SEC_I_CONTINUE_NEEDED: {
			int succeeded = state->send(
			    out_buffers[0].pvBuffer, out_buffers[0].cbBuffer, state->extra);
			FreeContextBuffer(out_buffers[0].pvBuffer);
			if (!succeeded) {
				status = E_FAIL;
				goto Error;
			}
			if (in_buffers[1].BufferType != SECBUFFER_EXTRA) {
				state->in_buffer_offset = 0;
			}
			break;
		}
		case SEC_E_INCOMPLETE_MESSAGE: {
			int read =
			    state->recv(state->in_buffer + state->in_buffer_offset,
			                sizeof(state->in_buffer) - state->in_buffer_offset,
			                state->extra);
			// simulate random receive sizes for testing
			// int read = state->recv(state->in_buffer +
			// state->in_buffer_offset, (rand() % 100) + 1,
			// state->extra);
			if (read <= 0) {
				status = E_FAIL;
				goto Error;
			}

			state->in_buffer_offset += read;
			continue;
		}
		default: {
			goto Error;
		}
		}
	}

Success:
	QueryContextAttributes(
	    &state->ctx_handle, SECPKG_ATTR_STREAM_SIZES, &state->stream_sizes);
	return status;
Error:
	state->connection_state = LIBSCHANNEL_CLOSED_AND_FREED;
	DeleteSecurityContext(&state->ctx_handle);
	FreeCredentialHandle(&state->cred_handle);
	return status;
}

ptrdiff_t tls_read(tls_state_t *state, char *buf, ptrdiff_t len) {
	ptrdiff_t amount_read = 0;

	if (state->connection_state > LIBSCHANNEL_OPEN) {
		goto Success;
	}

	while (len > 0) {
		if (state->out_buffer) {
			unsigned long copy_amount =
			    min(len, (ptrdiff_t)state->out_buffer_length);
			memcpy(buf, state->out_buffer, copy_amount);

			amount_read += copy_amount;
			buf += copy_amount;
			len -= copy_amount;

			if (copy_amount == state->out_buffer_length) {
				if (state->out_buffer_extra > 0) {
					memmove(
					    state->in_buffer,
					    state->in_buffer +
					        (state->in_buffer_offset - state->out_buffer_extra),
					    state->in_buffer_offset - (state->in_buffer_offset -
					                               state->out_buffer_extra));
					state->in_buffer_offset = state->out_buffer_extra;
				} else {
					state->in_buffer_offset = 0;
				}

				state->out_buffer = NULL;
				state->out_buffer_length = 0;
				state->out_buffer_extra = 0;

			} else {
				state->out_buffer_length -= copy_amount;
				state->out_buffer += copy_amount;
			}
		} else {
			SecBuffer buffers[4];
			SecBufferDesc desc;
			SECURITY_STATUS status;

			init_sec_buffer(&buffers[0],
			                state->in_buffer,
			                state->in_buffer_offset,
			                SECBUFFER_DATA);
			init_sec_buffer_empty(&buffers[1], SECBUFFER_EMPTY);
			init_sec_buffer_empty(&buffers[2], SECBUFFER_EMPTY);
			init_sec_buffer_empty(&buffers[3], SECBUFFER_EMPTY);

			init_sec_buffer_desc(&desc, buffers, _countof(buffers));

			status = DecryptMessage(&state->ctx_handle, &desc, 0, NULL);

			switch (status) {
			case SEC_E_OK: {
				state->out_buffer = buffers[1].pvBuffer;
				state->out_buffer_length = buffers[1].cbBuffer;
				state->out_buffer_extra = state->in_buffer_offset;

				if (buffers[3].BufferType == SECBUFFER_EXTRA) {
					state->out_buffer_extra = buffers[3].cbBuffer;
				} else {
					state->out_buffer_extra = 0;
				}

				continue;
			}
			case SEC_I_CONTEXT_EXPIRED: {
				// Shut down the connection
				state->connection_state = LIBSCHANNEL_CLOSED;
				goto Success;
			}
			case SEC_E_INCOMPLETE_MESSAGE: {
				int result = state->recv(
				    state->in_buffer + state->in_buffer_offset,
				    sizeof(state->in_buffer) - state->in_buffer_offset,
				    state->extra);
				if (result == 0) {
					state->connection_state = LIBSCHANNEL_CLOSED;
					goto Success;
				} else if (result < 0) {
					return status;
				}

				state->in_buffer_offset += result;
				continue;
			}
			case SEC_I_RENEGOTIATE: {
				DWORD flags = LIBSCHANNEL_ISC_FLAGS;

				SecBuffer in_buffers[2];
				SecBufferDesc in_buffers_desc;

				SecBuffer out_buffers[2];
				SecBufferDesc out_buffers_desc;

				init_sec_buffer(&in_buffers[0],
				                buffers[3].pvBuffer,
				                buffers[3].cbBuffer,
				                SECBUFFER_TOKEN);
				init_sec_buffer_empty(&in_buffers[1], SECBUFFER_EMPTY);

				init_sec_buffer_empty(&out_buffers[0], SECBUFFER_TOKEN);
				init_sec_buffer_empty(&out_buffers[1], SECBUFFER_ALERT);

				init_sec_buffer_desc(
				    &in_buffers_desc, in_buffers, _countof(in_buffers));
				init_sec_buffer_desc(
				    &out_buffers_desc, out_buffers, _countof(out_buffers));

				status = InitializeSecurityContextA(&state->cred_handle,
				                                    &state->ctx_handle,
				                                    state->hostname,
				                                    flags,
				                                    0,
				                                    0,
				                                    &in_buffers_desc,
				                                    0,
				                                    &state->ctx_handle,
				                                    &out_buffers_desc,
				                                    &flags,
				                                    0);

				if (SEC_STATUS_FAIL(status)) {
					return status;
				}

				if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
					memmove(state->in_buffer,
					        state->in_buffer + (state->in_buffer_offset -
					                            in_buffers[1].cbBuffer),
					        in_buffers[1].cbBuffer);
					state->in_buffer_offset = in_buffers[1].cbBuffer;
				} else {
					state->in_buffer_offset = 0;
				}

				continue;
			}
			default: {
				return status;
			}
			}
		}
	}

Success:
	return amount_read;
}

int tls_write(tls_state_t *state, char *buf, size_t len) {
	if (state->connection_state > LIBSCHANNEL_OPEN) {
		return E_FAIL;
	}

	while (len > 0) {
		SECURITY_STATUS status;
		unsigned long copy_amount =
		    min(len, (size_t)state->stream_sizes.cbMaximumMessage);
		char *write_buffer = _alloca(sizeof(state->in_buffer));

		SecBuffer buffers[4];
		SecBufferDesc desc;

		init_sec_buffer(&buffers[0],
		                write_buffer,
		                state->stream_sizes.cbHeader,
		                SECBUFFER_STREAM_HEADER);
		init_sec_buffer(&buffers[1],
		                write_buffer + state->stream_sizes.cbHeader,
		                copy_amount,
		                SECBUFFER_DATA);
		init_sec_buffer(&buffers[2],
		                write_buffer + state->stream_sizes.cbHeader +
		                    copy_amount,
		                state->stream_sizes.cbTrailer,
		                SECBUFFER_STREAM_TRAILER);
		init_sec_buffer_empty(&buffers[3], SECBUFFER_EMPTY);

		init_sec_buffer_desc(&desc, buffers, _countof(buffers));

		memcpy(buffers[1].pvBuffer, buf, copy_amount);

		status = EncryptMessage(&state->ctx_handle, 0, &desc, 0);
		if (SEC_STATUS_FAIL(status)) {
			return status;
		}

		if (!state->send(write_buffer,
		                 buffers[0].cbBuffer + buffers[1].cbBuffer +
		                     buffers[2].cbBuffer,
		                 state->extra)) {
			return E_FAIL;
		}

		len -= copy_amount;
	}

	return 0;
}

void tls_disconnect(tls_state_t *state) {
	SECURITY_STATUS status;

	DWORD token = SCHANNEL_SHUTDOWN;
	DWORD flags = LIBSCHANNEL_ISC_FLAGS;

	SecBuffer buf_token;
	SecBufferDesc buf_token_desc;

	SecBuffer out_buffer;
	SecBufferDesc out_buffer_desc;

	if (state->connection_state == LIBSCHANNEL_CLOSED_AND_FREED)
		return;
	state->connection_state = LIBSCHANNEL_CLOSED_AND_FREED;

	init_sec_buffer(&buf_token, &token, sizeof(token), SECBUFFER_TOKEN);
	init_sec_buffer_desc(&buf_token_desc, &buf_token, 1);

	ApplyControlToken(&state->ctx_handle, &buf_token_desc);

	init_sec_buffer_empty(&out_buffer, SECBUFFER_TOKEN);
	init_sec_buffer_desc(&out_buffer_desc, &out_buffer, 1);

	status = InitializeSecurityContextA(&state->cred_handle,
	                                    &state->ctx_handle,
	                                    state->hostname,
	                                    flags,
	                                    0,
	                                    0,
	                                    NULL,
	                                    0,
	                                    &state->ctx_handle,
	                                    &out_buffer_desc,
	                                    &flags,
	                                    0);

	if ((status == SEC_E_OK) || (status == SEC_I_CONTEXT_EXPIRED)) {
		state->send(out_buffer.pvBuffer, out_buffer.cbBuffer, state->extra);
		FreeContextBuffer(out_buffer.pvBuffer);
	}

	DeleteSecurityContext(&state->ctx_handle);
	FreeCredentialsHandle(&state->cred_handle);
	free(state->hostname);
}