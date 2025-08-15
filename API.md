# libschannel API documentation

## `tls_connect`
Performs a TLS handshake with a remote server.
### Parameters
`state`: A pointer to a `struct tls_state` to be initialized.   
`hostname`: The hostname of the remote server. Cannot be `NULL`.   
`send`: A `send` compatible function. See notes.   
`recv`: A `recv` compatible function. See notes.   
`extra`: To be used with `send`/`recv`. See notes.
### Return value
Zero on error, nonzero on failure. In the case of an error, you can cast the return value to an `HRESULT` to retrieve an error message through `FormatMessage`.

## `tls_read`
Reads bytes from a TLS socket.
### Parameters
`state`: The TLS state to operate on.   
`buf`: Input buffer to read into.   
`len`: Length of the input buffer.   
### Return value
Amount read on success, less then zero on error. Zero indicates that the connection was closed by the remote server. In the case of an error, you can cast the return value to an `HRESULT` to retrieve an error message through `FormatMessage`.

## `tls_write`
Writes bytes to a TLS socket.
### Parameters
`state`: The TLS state to operate on.   
`buf`: Output buffer to write.   
`len`: Length of the output buffer.   
### Return value
Zero on success, nonzero on error. In the case of an error, you can cast the return value to an `HRESULT` to retrieve an error message through `FormatMessage`.

## `tls_disconnect`
Disconnects a TLS socket and frees resources.
### Parameters
`state`: The TLS state to operate on.
### Return value
None.
### Notes
It is safe to call this function multiple times.

# Notes
* Always call `tls_disconnect` if an error value is returned from `tls_read`/`tls_write`.
* This library is transport-layer agnostic, so you must pass your own wrappers for `send`/`recv`. 
    * The prototype for a `send/recv` function is `(int)(char *buffer, int len, void *extra)`.
    * The `extra` parameter is passed to these functions to assist with handles and other such needs. It's specified during `tls_connect`. If you don't need it, specify `NULL`.
    * A `send` function must try to send exactly `len` bytes, re-sending as necessary. If `len` bytes were sent, return `1`. Otherwise, return `0`.
    * A `recv` function must try to recieve up to `len` bytes, returning the amount read (`0` if the socket was closed). If there was an error, return a value less than `0`.
    * An example for Winsock wrapper functions can be found in `test-program.c`.