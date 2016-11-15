#
# Copyright 2016 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import socket
import logging
import os
import threading
import time
import base64
from freenas.dispatcher import AsyncResult
from freenas.utils import first_or_default
from freenas.dispatcher.fd import FileDescriptor
from freenas.dispatcher.rpc import SchemaHelper as h, description, accepts, private
from utils import get_freenas_peer_client, call_task_and_check_state
from task import Task, ProgressTask, Provider, TaskException, VerifyException, TaskDescription
from libc.stdlib cimport malloc, free
from posix.unistd cimport read, write
from libc.stdint cimport *
from libc.stdio cimport *
from libc.errno cimport *
from libc.string cimport memcpy


#Encryption imports
cdef extern from "openssl/ossl_typ.h" nogil:
    ctypedef struct EVP_CIPHER_CTX:
        pass

    ctypedef struct EVP_CIPHER:
        pass

    ctypedef struct ENGINE:
        pass


cdef extern from "openssl/conf.h" nogil:
    void OPENSSL_config(const char *config_name)
    void OPENSSL_no_config()


cdef extern from "openssl/evp.h" nogil:
    void OpenSSL_add_all_algorithms()
    void OpenSSL_add_all_ciphers()
    void OpenSSL_add_all_digests()
    void EVP_cleanup()
    EVP_CIPHER_CTX *EVP_CIPHER_CTX_new()
    int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv)
    int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *outb, int *outl, unsigned char *inb, int inl)
    int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
    int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv)
    int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *outb, int *outl, unsigned char *inb, int inl)
    int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl)
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
    const EVP_CIPHER *EVP_aes_128_ofb()
    const EVP_CIPHER *EVP_aes_192_ofb()
    const EVP_CIPHER *EVP_aes_256_ofb()


cdef extern from "openssl/err.h" nogil:
    void ERR_load_crypto_strings()
    void ERR_free_strings()
    void ERR_print_errors_fp(FILE *fp)


#Compression imports
cdef extern from "zlib.h" nogil:
    enum:
        Z_FULL_FLUSH

        Z_OK
        Z_NEED_DICT
        Z_ERRNO
        Z_DATA_ERROR
        Z_MEM_ERROR

        Z_NO_COMPRESSION
        Z_BEST_SPEED
        Z_BEST_COMPRESSION
        Z_DEFAULT_COMPRESSION

        Z_NULL

    ctypedef struct z_stream_s:
        const uint8_t *next_in
        unsigned int avail_in
        unsigned long total_in

        uint8_t *next_out
        unsigned int avail_out
        unsigned long total_out

        uintptr_t zalloc
        uintptr_t zfree
        uintptr_t opaque

        int data_type
        unsigned long adler
        unsigned long reserved
    ctypedef z_stream_s z_stream

    int deflateInit(z_stream *strm, int level)
    int deflate(z_stream *strm, int flush)
    int deflateEnd(z_stream *strm)

    int inflateInit(z_stream *strm)
    int inflate(z_stream *strm, int flush)
    int inflateEnd(z_stream *strm)


#Globals declaration
cdef uint32_t encrypt_transfer_magic = 0xbadbeef0
cdef uint32_t encrypt_rekey_magic = 0xbeefd00d
cdef uint32_t transport_header_magic = 0xdeadbeef


logger = logging.getLogger('ReplicationTransportPlugin')


encryption_data = {}


cipher_types = {
    'AES128': {
        'function': <uintptr_t> &EVP_aes_128_ofb,
        'key_size': 128,
        'iv_size': 128
    },
    'AES192': {
        'function': <uintptr_t> &EVP_aes_192_ofb,
        'key_size': 192,
        'iv_size': 128
    },
    'AES256': {
        'function': <uintptr_t> &EVP_aes_256_ofb,
        'key_size': 256,
        'iv_size': 128
    }
}


cdef uint32_t read_fd(int fd, void *buf, uint32_t nbytes, uint32_t curr_pos) nogil:
    cdef int ret
    cdef uint32_t done = 0

    while True:
        ret = read(fd, <uint8_t *>(buf + curr_pos + done), nbytes - done)
        if ret == -1:
            if errno in (EINTR, EAGAIN):
                continue
            else:
                return ret

        done += ret
        if (done == nbytes) or (ret == 0):
            return done


cdef uint32_t write_fd(int fd, void *buf, uint32_t nbytes) nogil:
    cdef int ret
    cdef uint32_t done = 0

    while True:
        ret = write(fd, <uint8_t *>(buf + done), nbytes - done)
        if ret == -1:
            if errno in (EINTR, EAGAIN):
                continue
            else:
                return ret

        done += ret
        if done == nbytes:
            return done


@description('Provides information about replication transport layer')
class TransportProvider(Provider):
    def __init__(self):
        super(TransportProvider, self).__init__()
        self.cv = threading.Condition()

    @private
    def plugin_types(self):
        return ['compress', 'encrypt', 'throttle']

    @private
    def set_encryption_data(self, key, data):
        with self.cv:
            encryption_data[key] = data
            self.cv.notify_all()

    @private
    def get_encryption_data(self, key):
        with self.cv:
            self.cv.wait_for(lambda: key in encryption_data)
            return encryption_data.pop(key)


@private
@description('Send side of replication transport layer')
@accepts(
    FileDescriptor,
    h.all_of(
        h.ref('replication-transport'),
        h.required('client_address', 'receive_properties')
    )
)
class TransportSendTask(Task):
    def __init__(self, dispatcher, datastore):
        super(TransportSendTask, self).__init__(dispatcher, datastore)
        self.finished = AsyncResult()
        self.addr = None
        self.aborted = False
        self.fds = []
        self.sock = None
        self.conn = None

    @classmethod
    def early_describe(cls):
        return "Sending replication stream"

    def describe(self, fd, transport):
        return TaskDescription("Sending replication stream to {name}", name=transport['client_address'])

    def verify(self, fd, transport):
        client_address = transport.get('client_address')
        if not client_address:
            raise VerifyException(ENOENT, 'Please specify address of a remote')

        if 'server_address' in transport:
            raise VerifyException(EINVAL, 'Server address cannot be specified')

        return []

    def run(self, fd, transport):
        cdef uint8_t *token_buffer = NULL
        cdef int ret
        cdef uint32_t token_size
        cdef uint32_t *buffer = NULL
        cdef int ret_wr
        cdef uint32_t buffer_size
        cdef uint32_t header_size = 2 * sizeof(uint32_t)
        cdef int rd_fd = fd.fd
        cdef int wr_fd
        cdef int header_wr = -1

        conn_fd = None
        try:
            buffer_size = transport.get('buffer_size', 1024*1024)
            client_address = transport.get('client_address')
            remote_client = get_freenas_peer_client(self, client_address)
            server_address = remote_client.local_address[0]
            server_port = transport.get('server_port', 0)

            for conn_option in socket.getaddrinfo(server_address, server_port, socket.AF_UNSPEC, socket.SOCK_STREAM):
                af, sock_type, proto, canonname, addr = conn_option
                try:
                    self.sock = socket.socket(af, sock_type, proto)
                except OSError:
                    self.sock = None
                    continue
                try:
                    self.sock.bind(addr)
                    self.sock.settimeout(30)
                    self.sock.listen(1)
                except socket.timeout:
                    raise TaskException(
                        ETIMEDOUT,
                        'Timeout while waiting for connection from {0}'.format(client_address)
                    )
                except OSError:
                    self.sock.close()
                    self.sock = None
                    continue
                break

            if self.sock is None:
                raise TaskException(EACCES, 'Could not open a socket at address {0}'.format(server_address))

            logger.debug('Created a TCP socket at {0}:{1}'.format(*addr))

            token_size = transport.get('auth_token_size', 1024)
            token = transport.get('auth_token')
            if token:
                actual_size = len(base64.b64decode(token.encode('utf-8')))
                if actual_size != token_size:
                    raise TaskException(
                        EINVAL,
                        'Provided token size {0} does not match token size parameter value {1}'.format(
                            actual_size,
                            token_size
                        )
                    )
            else:
                token = base64.b64encode(os.urandom(token_size)).decode('utf-8')
                transport['auth_token'] = token

            sock_addr = self.sock.getsockname()
            transport['server_address'] = sock_addr[0]
            transport['server_port'] = sock_addr[1]
            transport['buffer_size'] = buffer_size
            transport['auth_token_size'] = token_size

            recv_task_id = remote_client.call_task_async(
                'replication.transport.receive',
                transport,
                callback=self.get_recv_status,
                timeout=604800
            )

            self.conn, addr = self.sock.accept()

            for addr_info in socket.getaddrinfo(client_address, addr[1], socket.AF_UNSPEC, socket.SOCK_STREAM):
                _, _, _, _, desired_address = addr_info

                if addr[0] == desired_address[0]:
                    break

            else:
                raise TaskException(
                    EINVAL,
                    'Connection from an unexpected address {0} - desired {1}'.format(
                        addr[0],
                        client_address
                    )
                )

            logger.debug('New connection from {0}:{1} to {2}:{3}'.format(*(addr + sock_addr)))

            self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size)
            self.conn.settimeout(self.configstore.get('replication.connection.timeout'))

            conn_fd = os.dup(self.conn.fileno())
            self.fds.append(conn_fd)

            token_buffer = <uint8_t *>malloc(token_size * sizeof(uint8_t))
            ret = read_fd(conn_fd, token_buffer, token_size, 0)
            if ret != token_size:
                raise TaskException(
                    ECONNABORTED,
                    'Connection with {0} aborted before authentication'.format(client_address)
                )
            recvd_token = <bytes> token_buffer[:token_size]

            if base64.b64decode(token.encode('utf-8')) != recvd_token:
                raise TaskException(
                    ECONNABORTED,
                    'Transport layer authentication failed. Expected token {0}, was {1}'.format(
                        token,
                        recvd_token.decode('utf-8')
                    )
                )
            logger.debug('{0}:{1} connection authentication finished successfully'.format(*addr))

            plugins = transport.get('transport_plugins', [])
            header_rd, header_wr = os.pipe()
            self.fds.append(header_rd)
            self.fds.append(header_wr)
            last_rd_fd = header_rd
            subtasks = []
            raw_subtasks = []

            for type in ['compress', 'encrypt', 'throttle']:
                plugin = first_or_default(lambda p: p['%type'].startswith(type), plugins)
                if plugin:
                    rd, wr = os.pipe()
                    self.fds.append(rd)
                    self.fds.append(wr)
                    plugin['%type'] = type + '-replication-transport-plugin'
                    plugin['read_fd'] = FileDescriptor(last_rd_fd)
                    plugin['write_fd'] = FileDescriptor(wr)
                    last_rd_fd = rd
                    if type == 'encrypt':
                        plugin['auth_token'] = token
                        plugin['remote'] = client_address
                    raw_subtasks.append(['replication.transport.{0}'.format(type), plugin])
                    logger.debug('Registered {0} transport layer plugin for {1}:{2} connection'.format(type, *addr))

            if len(raw_subtasks):
                logger.debug('Starting plugins for {0}:{1} connection'.format(*addr))
                raw_subtasks[-1][-1]['write_fd'] = FileDescriptor(conn_fd)
                for subtask in raw_subtasks:
                    subtasks.append(self.run_subtask(*subtask))
            else:
                header_wr = conn_fd

            logger.debug(
                'Transport layer plugins registration finished for {0}:{1} connection. Starting transfer.'.format(*addr)
            )
            self.addr = addr

            wr_fd = header_wr
            with nogil:
                buffer = <uint32_t *>malloc((buffer_size + header_size) * sizeof(uint8_t))

                buffer[0] = transport_header_magic
            while True:
                with nogil:
                    ret = read_fd(rd_fd, buffer, buffer_size, header_size)

                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Got {0} bytes of payload ({1}:{2})'.format(ret, *self.addr))

                with nogil:
                    buffer[1] = ret

                    if ret == -1:
                        break
                    if ret == 0:
                        ret_wr = write_fd(wr_fd, buffer, header_size)
                        break
                    else:
                        ret_wr = write_fd(wr_fd, buffer, ret + header_size)

                    if ret_wr == -1:
                        break

                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Written {0} bytes -> TCP socket ({1}:{2})'.format(ret, *self.addr))

        finally:
            if conn_fd and header_wr != conn_fd:
                close_fds(header_wr)

            if not self.aborted and self.conn and addr:
                if ret_wr == -1:
                    raise TaskException(
                        errno,
                        'Header write failed during transmission to {0}:{1}'.format(*addr)
                    )
                if ret == -1:
                    raise TaskException(
                        errno,
                        'Data read failed during transmission to {0}:{1}'.format(*addr)
                    )
                logger.debug('All data fetched for transfer to {0}:{1}. Waiting for plugins to close.'.format(*addr))
                self.join_subtasks(*subtasks)
                if self.conn:
                    self.conn.shutdown(socket.SHUT_RDWR)
                    self.conn.close()
                    self.conn = None

                self.finished.wait()

                logger.debug('Send to {0}:{1} finished. Closing connection'.format(*addr))
                remote_client.disconnect()

            free(buffer)
            free(token_buffer)
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                self.sock = None
            close_fds(self.fds)

    def get_recv_status(self, status):
        if status.get('state') != 'FINISHED':
            error = status.get('error')
            close_fds(self.fds)
            if self.conn:
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
                self.conn = None
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                self.sock = None
            self.finished.set_exception(
                TaskException(
                    error['code'],
                    'Receive task connected to {1}:{2} finished unexpectedly with message: {0}'.format(
                        error['message'],
                        *self.addr
                    )
                )
            )
        else:
            logger.debug('Receive task at {0}:{1} finished'.format(*self.addr))
            self.finished.set(True)

    def abort(self):
        self.aborted = True
        self.finished.set(True)
        close_fds(self.fds)
        if self.conn:
            self.conn.shutdown(socket.SHUT_RDWR)
            self.conn.close()
            self.conn = None
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
            self.sock = None


@private
@description('Receive side of replication transport layer')
@accepts(h.ref('replication-transport'))
class TransportReceiveTask(ProgressTask):
    def __init__(self, dispatcher, datastore):
        super(TransportReceiveTask, self).__init__(dispatcher, datastore)
        self.done = 0
        self.estimated_size = 0
        self.running = True
        self.addr = None
        self.aborted = False
        self.fds = []
        self.sock = None

    @classmethod
    def early_describe(cls):
        return "Receiving replication stream"

    def describe(self, transport):
        return TaskDescription("Receiving replication stream from {name}", name=transport['server_address'])

    def verify(self, transport):
        if 'auth_token' not in transport:
            raise VerifyException(ENOENT, 'Authentication token is not specified')

        if 'server_address' not in transport:
            raise VerifyException(ENOENT, 'Server address is not specified')

        if 'server_port' not in transport:
            raise VerifyException(ENOENT, 'Server port is not specified')

        return []

    def run(self, transport):
        cdef uint8_t *token_buf
        cdef int ret
        cdef uint32_t *buffer = NULL
        cdef uint32_t *header_buffer = NULL
        cdef uint32_t length
        cdef uint32_t buffer_size
        cdef uint32_t header_size = 2 * sizeof(uint32_t)
        cdef int ret_wr
        cdef int header_rd
        cdef int header_wr

        progress_t = None
        addr = None

        server_address = self.environment['SENDER_ADDRESS'].split(',')[0]
        logger.debug('Receive from {0} has started'.format(server_address))
        try:
            buffer_size = transport.get('buffer_size', 1024*1024)

            self.estimated_size = transport.get('estimated_size', 0)
            server_port = transport.get('server_port')
            token = base64.b64decode(transport.get('auth_token').encode('utf-8'))
            token_size = transport.get('auth_token_size')
            token_buf = token

            if len(token) != token_size:
                raise TaskException(
                    EINVAL,
                    'Token size {0} does not match token size field {1}'.format(len(token), token_size)
                )

            for conn_option in socket.getaddrinfo(server_address, server_port, socket.AF_UNSPEC, socket.SOCK_STREAM):
                af, sock_type, proto, canonname, addr = conn_option
                try:
                    self.sock = socket.socket(af, sock_type, proto)
                except OSError:
                    self.sock = None
                    continue
                try:
                    self.sock.connect(addr)
                except OSError:
                    self.sock.close()
                    self.sock = None
                    continue
                break

            if self.sock is None:
                raise TaskException(EACCES, 'Could not connect to a socket at address {0}'.format(server_address))
            self.addr = addr
            logger.debug('Connected to a TCP socket at {0}:{1}'.format(*addr))

            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size)
            self.sock.settimeout(self.configstore.get('replication.connection.timeout'))

            conn_fd = os.dup(self.sock.fileno())
            self.fds.append(conn_fd)

            plugins = transport.get('transport_plugins', [])
            last_rd_fd = conn_fd
            subtasks = []

            for type in ['encrypt', 'compress']:
                plugin = first_or_default(lambda p: p['%type'].startswith(type), plugins)
                if plugin:
                    plugin['%type'] = type + '-replication-transport-plugin'
                    if type == 'encrypt':
                        plugin['auth_token'] = transport.get('auth_token')
                    rd, wr = os.pipe()
                    self.fds.append(rd)
                    self.fds.append(wr)
                    plugin['read_fd'] = FileDescriptor(last_rd_fd)
                    plugin['write_fd'] = FileDescriptor(wr)
                    last_rd_fd = rd
                    subtasks.append(self.run_subtask(
                        'replication.transport.{0}'.format(
                            'decrypt' if plugin['%type'].startswith('encrypt') else 'decompress'
                        ),
                        plugin
                    ))
                    logger.debug(
                        'Registered {0} transport layer plugin for {1}:{2} connection'.format(
                            'decrypt' if plugin['%type'].startswith('encrypt') else 'decompress',
                            *addr
                        )
                    )

            ret = write_fd(self.sock.fileno(), token_buf, token_size)
            if ret == -1:
                raise TaskException(ECONNABORTED, 'Transport connection closed unexpectedly')
            elif ret != token_size:
                raise TaskException(EINVAL, 'Transport failed to write token to socket')
            logger.debug('Authentication token sent to {0}:{1}'.format(*addr))

            zfs_rd, zfs_wr = os.pipe()
            self.fds.append(zfs_wr)
            self.fds.append(zfs_rd)
            recv_props = transport.get('receive_properties')
            subtasks.append(self.run_subtask(
                'zfs.receive',
                recv_props['name'],
                FileDescriptor(zfs_rd),
                recv_props.get('force', False),
                recv_props.get('nomount', False),
                recv_props.get('props', None),
                recv_props.get('limitds', None)
            ))

            progress_t = threading.Thread(target=self.count_progress)
            progress_t.start()
            logger.debug('Started zfs receive task for {0}:{1} connection'.format(*addr))

            header_rd = last_rd_fd
            header_wr = zfs_wr

            with nogil:
                buffer = <uint32_t *>malloc(buffer_size * sizeof(uint8_t))
                header_buffer = <uint32_t *>malloc(header_size * sizeof(uint8_t))
            while True:
                with nogil:
                    ret = read_fd(header_rd, header_buffer, header_size, 0)
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Got {0} bytes of header ({1}:{2})'.format(ret, *self.addr))

                with nogil:
                    if ret != header_size:
                        ret = -1
                        break
                    if header_buffer[0] != transport_header_magic:
                        break
                    length = header_buffer[1]
                    if length == 0:
                        break

                    ret = read_fd(header_rd, buffer, length, 0)
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Got {0} bytes of payload ({1}:{2})'.format(ret, *self.addr))
                with nogil:
                    if ret != length:
                        ret = -1
                        break

                self.done += ret

                with nogil:
                    ret_wr = write_fd(header_wr, buffer, length)
                    if ret_wr == -1:
                        break
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Written {0} bytes of payload -> zfs.receive ({1}:{2})'.format(length, *self.addr))

        finally:
            try:
                if not self.aborted:
                    if header_buffer:
                        if header_buffer[0] != transport_header_magic:
                            raise TaskException(
                                EINVAL,
                                'Bad magic {0} received. Expected {1}'.format(header_buffer[0], transport_header_magic)
                            )
                    if ret == -1:
                        raise TaskException(
                            errno,
                            'Data read failed during transmission from {0}:{1}'.format(*self.addr)
                        )
                    if ret_wr == -1:
                        raise TaskException(
                            errno,
                            'Data write failed during transmission from {0}:{1}'.format(*self.addr)
                        )

                    if addr:
                        logger.debug(
                            'All data fetched for transfer from {0}:{1}. Waiting for plugins to close.'.format(*addr)
                        )
                    self.join_subtasks(*subtasks)
            finally:
                self.running = False
                if progress_t:
                    progress_t.join()
                if addr:
                    logger.debug('Receive from {0}:{1} finished. Closing connection'.format(*addr))
                    if self.sock:
                        self.sock.shutdown(socket.SHUT_RDWR)
                        self.sock.close()
                        self.sock = None
                else:
                    logger.debug('Receive has failed. Closing connection')
                free(buffer)
                free(header_buffer)
                close_fds(self.fds)

    def count_progress(self):
        last_done = 0
        progress = 0
        total_time = 0
        while self.running:
            if self.estimated_size:
                progress = int((float(self.done) / float(self.estimated_size)) * 100)
                if progress > 100:
                    progress = 100
            self.set_progress(progress, 'Transfer speed {0} B/s'.format(self.done - last_done))
            last_done = self.done
            time.sleep(1)
            total_time += 1

        if total_time:
            transfer_speed = int(float(self.done) / float(total_time))
        else:
            transfer_speed = 0
        logger.debug('Overall transfer speed {0} B/s - {1}:{2}'.format(transfer_speed, *self.addr))

    def abort(self):
        self.aborted = True
        close_fds(self.fds)
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
            self.sock = None


@private
@description('Compress the input stream and pass it to the output')
@accepts(h.ref('compress-replication-transport-plugin'))
class TransportCompressTask(Task):
    def __init__(self, dispatcher, datastore):
        super(TransportCompressTask, self).__init__(dispatcher, datastore)
        self.fds = []
        self.aborted = False

    @classmethod
    def early_describe(cls):
        return "Compressing replication stream"

    def describe(self, plugin):
        return TaskDescription(
            "Compressing replication stream using the {method} method",
            method=plugin.get('level', 'DEFAULT')
        )

    def verify(self, plugin):
        if 'read_fd' not in plugin:
            raise VerifyException(ENOENT, 'Read file descriptor is not specified')

        if 'write_fd' not in plugin:
            raise VerifyException(ENOENT, 'Write file descriptor is not specified')

        return []

    def run(self, plugin):
        cdef int ret
        cdef int ret_rd = 0
        cdef int ret_wr = 0
        cdef int level = Z_DEFAULT_COMPRESSION
        cdef int rd_fd = plugin['read_fd'].fd
        cdef int wr_fd = plugin['write_fd'].fd
        cdef uint32_t have
        cdef z_stream strm
        cdef unsigned char *in_buffer = NULL
        cdef unsigned char *out_buffer = NULL
        cdef uint8_t err = 0
        cdef uint32_t buffer_size = plugin.get('buffer_size', 1024*1024)

        self.fds.append(rd_fd)
        self.fds.append(wr_fd)

        comp_level = plugin.get('level', 'DEFAULT')
        if comp_level == 'BEST':
            level = Z_BEST_COMPRESSION
        elif comp_level == 'FAST':
            level = Z_BEST_SPEED

        try:
            with nogil:
                in_buffer = <unsigned char *>malloc(buffer_size * sizeof(uint8_t))
                out_buffer = <unsigned char *>malloc(buffer_size * sizeof(uint8_t))

                strm.zalloc = Z_NULL
                strm.zfree = Z_NULL
                strm.opaque = Z_NULL
                ret = deflateInit(&strm, level)
            if ret != Z_OK:
                return
            IF REPLICATION_TRANSPORT_DEBUG:
                logger.debug('Compression context initialization completed')

            while True:
                with nogil:
                    ret_rd = read_fd(rd_fd, in_buffer, buffer_size, 0)
                    strm.avail_in = ret_rd
                    if ret_rd < 1:
                        break
                    strm.next_in = in_buffer
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Compression: got {0} bytes'.format(ret_rd))

                while True:
                    with nogil:
                        strm.avail_out = buffer_size
                        strm.next_out = out_buffer
                        ret = deflate(&strm, Z_FULL_FLUSH)
                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Compression: buffer deflated')

                    with nogil:
                        have = buffer_size - strm.avail_out
                        ret_wr = write_fd(wr_fd, out_buffer, have)
                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Compression: sent {0} bytes'.format(ret_wr))
                    if ret_wr != have:
                        err = 1
                        break
                    if strm.avail_out != 0:
                        break
                if err == 1:
                    break

            with nogil:
                deflateEnd(&strm)

        finally:
            if not self.aborted:
                if ret == Z_ERRNO:
                    raise TaskException(err, 'Compression initialization failed')

                if ret != Z_OK:
                    raise TaskException(err, 'Compression stream did not complete properly')

                if ret_rd == -1:
                    raise TaskException(err, 'Read from file descriptor failed during compression task')

                if ret_wr == -1:
                    raise TaskException(err, 'Write to file descriptor failed during compression task')

                logger.debug('Compression task finished')
            free(in_buffer)
            free(out_buffer)
            close_fds(self.fds)

    def abort(self):
        self.aborted = True
        close_fds(self.fds)


@private
@description('Decompress the input stream and pass it to the output')
@accepts(h.ref('compress-replication-transport-plugin'))
class TransportDecompressTask(Task):
    def __init__(self, dispatcher, datastore):
        super(TransportDecompressTask, self).__init__(dispatcher, datastore)
        self.fds = []
        self.aborted = False

    @classmethod
    def early_describe(cls):
        return "Decompressing the replication stream"

    def describe(self, plugin):
        return TaskDescription("Decompressing the replication stream")

    def verify(self, plugin):
        if 'read_fd' not in plugin:
            raise VerifyException(ENOENT, 'Read file descriptor is not specified')

        if 'write_fd' not in plugin:
            raise VerifyException(ENOENT, 'Write file descriptor is not specified')

        return []

    def run(self, plugin):
        cdef int ret
        cdef int ret_rd = 0
        cdef int ret_wr = 0
        cdef int rd_fd = plugin['read_fd'].fd
        cdef int wr_fd = plugin['write_fd'].fd
        cdef uint32_t have
        cdef z_stream strm
        cdef unsigned char *in_buffer = NULL
        cdef unsigned char *out_buffer = NULL
        cdef uint32_t buffer_size = plugin.get('buffer_size', 1024*1024)

        self.fds.append(rd_fd)
        self.fds.append(wr_fd)
        try:
            with nogil:
                in_buffer = <unsigned char *>malloc(buffer_size * sizeof(uint8_t))
                out_buffer = <unsigned char *>malloc(buffer_size * sizeof(uint8_t))

                strm.zalloc = Z_NULL
                strm.zfree = Z_NULL
                strm.opaque = Z_NULL
                strm.avail_in = 0
                strm.next_in = NULL
                ret = inflateInit(&strm)
                strm.next_in = in_buffer
            if ret != Z_OK:
                return

            IF REPLICATION_TRANSPORT_DEBUG:
                logger.debug('Decompression context initialization completed')

            while True:
                with nogil:
                    ret_rd = read_fd(rd_fd, in_buffer, buffer_size, 0)
                    strm.avail_in = ret_rd
                    if ret_rd < 1:
                        break
                    strm.next_in = in_buffer
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Decompression: got {0} bytes'.format(ret_rd))

                while True:
                    with nogil:
                        strm.avail_out = buffer_size
                        strm.next_out = out_buffer
                        ret = inflate(&strm, Z_FULL_FLUSH)
                        if (ret == Z_NEED_DICT) or (ret == Z_DATA_ERROR) or (ret == Z_MEM_ERROR):
                            err = 1
                            break
                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Decompression: buffer inflated')

                    with nogil:
                        have = buffer_size - strm.avail_out
                        ret_wr = write_fd(wr_fd, out_buffer, have)
                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Decompression: sent {0} bytes'.format(ret_wr))
                    if ret_wr != have:
                        err = 1
                        break
                    if strm.avail_out != 0:
                        break
                if err == 1:
                    break

            with nogil:
                inflateEnd(&strm)

        finally:
            if not self.aborted:
                if ret == Z_ERRNO:
                    raise TaskException(errno, 'Decompression initialization failed')

                if ret != Z_OK:
                    fault = 'Data error'
                    if ret == Z_MEM_ERROR:
                        fault = 'Not enough memory'
                    raise TaskException(errno, 'Compression stream did not complete properly. {0}'.format(fault))

                if ret_rd == -1:
                    raise TaskException(errno, 'Read from file descriptor failed during decompression task')

                if ret_wr == -1:
                    raise TaskException(errno, 'Write to file descriptor failed during decompression task')
            free(in_buffer)
            free(out_buffer)
            close_fds(self.fds)

    def abort(self):
        self.aborted = True
        close_fds(self.fds)


@private
@description('Encrypt the input stream and pass it to the output')
@accepts(h.ref('encrypt-replication-transport-plugin'))
class TransportEncryptTask(Task):
    def __init__(self, dispatcher, datastore):
        super(TransportEncryptTask, self).__init__(dispatcher, datastore)
        self.fds = []
        self.aborted = False

    @classmethod
    def early_describe(cls):
        return "Encrypting the replication stream"

    def describe(self, plugin):
        return TaskDescription(
            "Encrypting the replication stream using the {algorithm} algorithm",
            algorithm=plugin.get('type', 'AES128')
        )

    def verify(self, plugin):
        if 'auth_token' not in plugin:
            raise VerifyException(ENOENT, 'Authentication token is missing')

        if 'read_fd' not in plugin:
            raise VerifyException(ENOENT, 'Read file descriptor is not specified')

        if 'write_fd' not in plugin:
            raise VerifyException(ENOENT, 'Write file descriptor is not specified')

        return []

    def run(self, plugin):
        cdef uint32_t *plainbuffer = NULL
        cdef unsigned char *cipherbuffer = NULL
        cdef uint8_t *iv
        cdef uint8_t *key
        cdef uint8_t *byte_buffer
        cdef uint32_t key_size
        cdef uint32_t iv_size
        cdef uint32_t buffer_size
        cdef uint32_t header_size = 2 * sizeof(uint32_t)
        cdef uint32_t ret = 1
        cdef int ret_wr = 0
        cdef int plain_ret = 0
        cdef uint32_t renewal_interval
        cdef EVP_CIPHER_CTX *ctx
        cdef const EVP_CIPHER *(*cipher_function) () nogil
        cdef int rd_fd
        cdef int wr_fd
        cdef int cipher_ret
        IF REPLICATION_TRANSPORT_DEBUG:
            cdef uint8_t *log_buffer

        remote = plugin.get('remote')
        encryption_type = plugin.get('type', 'AES128')
        buffer_size = plugin.get('buffer_size', 1024*1024)
        token = plugin.get('auth_token')
        renewal_interval = plugin.get('renewal_interval', 0)
        cipher = cipher_types.get(encryption_type)
        key_size = cipher.get('key_size')
        iv_size = cipher.get('iv_size')

        py_key = os.urandom(key_size)
        py_iv = os.urandom(iv_size)
        key = py_key
        iv = py_iv

        if renewal_interval:
            if (key_size + iv_size) > buffer_size:
                raise TaskException(
                    EINVAL,
                    'Selected buffer size {0} is to small to hold key of size {1} ad iv of size {2}'.format(
                        buffer_size,
                        key_size,
                        iv_size
                    )
                )

        remote_client = get_freenas_peer_client(self, remote)
        remote_client.call_sync(
            'replication.transport.set_encryption_data',
            token,
            {
                'key': base64.b64encode(py_key).decode('utf-8'),
                'iv': base64.b64encode(py_iv).decode('utf-8')
            }
        )
        remote_client.disconnect()

        IF REPLICATION_TRANSPORT_DEBUG:
            logger.debug('Encryption data sent')
            logger.debug('py_key: {0} - py_iv: {1}'.format(
                base64.b64encode(py_key).decode('utf-8'),
                base64.b64encode(py_iv).decode('utf-8'))
            )

            logger.debug('Key: {0}'.format(<bytes> key[:key_size]))
            logger.debug('IV: {0}'.format(<bytes> iv[:iv_size]))

        try:
            rd_fd = plugin.get('read_fd').fd
            self.fds.append(rd_fd)
            wr_fd = plugin.get('write_fd').fd
            self.fds.append(wr_fd)
            cipher_function = <const EVP_CIPHER *(*)() nogil><uintptr_t> cipher['function']

            cipherbuffer = <unsigned char *>malloc((buffer_size + header_size) * sizeof(uint8_t))
            plainbuffer = <uint32_t *>malloc((buffer_size + header_size) * sizeof(uint8_t))
            plainbuffer[0] = encrypt_transfer_magic
            byte_buffer = <uint8_t *> plainbuffer

            with nogil:
                ERR_load_crypto_strings()
                OpenSSL_add_all_algorithms()
                OPENSSL_config(NULL)
                ctx = EVP_CIPHER_CTX_new()
            if ctx == NULL:
                ERR_print_errors_fp(stderr)
                return
            with nogil:
                ret = EVP_EncryptInit_ex(ctx, cipher_function(), NULL, key, iv)
            if ret != 1:
                ERR_print_errors_fp(stderr)
                return
            logger.debug('Encryption context initialization completed')

            while True:
                with nogil:
                    plain_ret = read_fd(rd_fd, plainbuffer, buffer_size, header_size)
                    if plain_ret < 0:
                        break
                    plainbuffer[1] = plain_ret
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Got {0} bytes of plain text'.format(plain_ret))
                    log_buffer = <uint8_t *> plainbuffer
                    logger.debug('Message: {0}'.format(<bytes> log_buffer[:plain_ret]))

                with nogil:
                    ret = EVP_EncryptUpdate(ctx, cipherbuffer, &cipher_ret, <unsigned char *> plainbuffer, plain_ret + header_size)
                    if ret != 1:
                        ERR_print_errors_fp(stderr)
                        break

                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Cipher text size returned {0} bytes'.format(cipher_ret))
                    log_buffer = <uint8_t *> cipherbuffer
                    logger.debug('Message: {0}'.format(<bytes> log_buffer[:cipher_ret]))
                with nogil:
                    ret_wr = write_fd(wr_fd, cipherbuffer, cipher_ret)
                    if ret_wr == -1:
                        break
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Wrote {0} bytes of cipher text'.format(ret_wr))

                if plain_ret == 0:
                    break

                if renewal_interval:
                    renewal_interval -= 1
                    if renewal_interval == 0:
                        renewal_interval = plugin.get('renewal_interval')
                        plainbuffer[0] = encrypt_rekey_magic
                        plainbuffer[1] = key_size + iv_size
                        py_key = os.urandom(key_size)
                        py_iv = os.urandom(iv_size)
                        key = py_key
                        iv = py_iv

                        IF REPLICATION_TRANSPORT_DEBUG:
                            logger.debug('Rekey started')
                            logger.debug('py_key: {0} - py_iv: {1}'.format(
                                py_key,
                                py_iv
                            ))
                            logger.debug('Key: {0}'.format(<bytes> key[:key_size]))
                            logger.debug('IV: {0}'.format(<bytes> iv[:iv_size]))

                        memcpy(&byte_buffer[header_size], key, key_size)
                        memcpy(&byte_buffer[key_size + header_size], iv, iv_size)

                        with nogil:
                            ret = EVP_EncryptUpdate(ctx, cipherbuffer, &cipher_ret, <unsigned char *> plainbuffer, plainbuffer[1] + header_size)
                            if ret != 1:
                                ERR_print_errors_fp(stderr)
                                break

                        IF REPLICATION_TRANSPORT_DEBUG:
                            logger.debug('Cipher text size returned {0} bytes'.format(cipher_ret))
                            log_buffer = <uint8_t *> cipherbuffer
                            logger.debug('Message: {0}'.format(<bytes> log_buffer[:cipher_ret]))

                        plainbuffer[0] = encrypt_transfer_magic

                        with nogil:
                            ret_wr = write_fd(wr_fd, cipherbuffer, cipher_ret)
                            if ret_wr == -1:
                                break

                        IF REPLICATION_TRANSPORT_DEBUG:
                            logger.debug('Wrote {0} bytes of cipher text'.format(ret_wr))

                        with nogil:
                            ret = EVP_EncryptFinal_ex(ctx, cipherbuffer, &cipher_ret)
                            if ret != 1:
                                ERR_print_errors_fp(stderr)
                                break
                            if cipher_ret > 0:
                                ret_wr = write_fd(wr_fd, cipherbuffer, cipher_ret)
                                if ret_wr == -1:
                                    break

                        IF REPLICATION_TRANSPORT_DEBUG:
                            logger.debug('Encryption context finalized. Returned last {0} bytes of cipher text. Starting new context'.format(cipher_ret))

                        with nogil:
                            EVP_CIPHER_CTX_free(ctx)
                            ctx = EVP_CIPHER_CTX_new()
                            if ctx == NULL:
                                ERR_print_errors_fp(stderr)
                                break

                            ret = EVP_EncryptInit_ex(ctx, cipher_function(), NULL, key, iv)
                            if ret != 1:
                                ERR_print_errors_fp(stderr)
                                break

            if plain_ret == 0:
                with nogil:
                    ret = EVP_EncryptFinal_ex(ctx, cipherbuffer, &cipher_ret)
                logger.debug('Encryption context finalized. Returned last {0} bytes of cipher text'.format(cipher_ret))

                if (cipher_ret > 0) and (ret == 1):
                    with nogil:
                        ret_wr = write_fd(wr_fd, cipherbuffer, cipher_ret)
                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Wrote {0} bytes of cipher text'.format(ret_wr))
                        log_buffer = <uint8_t *> cipherbuffer
                        logger.debug('Message: {0}'.format(<bytes> log_buffer[:cipher_ret]))

        finally:
            if not self.aborted:
                if plain_ret == -1:
                    raise TaskException(errno, 'Read from file descriptor failed during encryption task')

                if ret != 1:
                    raise TaskException(errno, 'Cryptographic function failed during encryption task')

                if ret_wr == -1:
                    raise TaskException(errno, 'Write to file descriptor failed during encryption task')

                if not ctx:
                    raise TaskException(errno, 'Cryptographic context creation failed')
            with nogil:
                EVP_CIPHER_CTX_free(ctx)
            free(plainbuffer)
            free(cipherbuffer)
            close_fds(self.fds)

    def abort(self):
        self.aborted = True
        close_fds(self.fds)


@private
@description('Decrypt the input stream and pass it to the output')
@accepts(h.ref('encrypt-replication-transport-plugin'))
class TransportDecryptTask(Task):
    def __init__(self, dispatcher, datastore):
        super(TransportDecryptTask, self).__init__(dispatcher, datastore)
        self.fds = []
        self.aborted = False

    @classmethod
    def early_describe(cls):
        return "Decrypting replication stream"

    def describe(self, plugin):
        return TaskDescription(
            "Decrypting replication stream using the {algorithm} algorithm",
            algorithm=plugin.get('type', 'AES128')
        )

    def verify(self, plugin):
        if 'auth_token' not in plugin:
            raise VerifyException(ENOENT, 'Authentication token is missing')

        if 'read_fd' not in plugin:
            raise VerifyException(ENOENT, 'Read file descriptor is not specified')

        if 'write_fd' not in plugin:
            raise VerifyException(ENOENT, 'Write file descriptor is not specified')

        return []

    def run(self, plugin):
        cdef uint32_t *plainbuffer = NULL
        cdef uint32_t *header_buffer = NULL
        cdef unsigned char *cipherbuffer = NULL
        cdef uint8_t *byte_buffer
        cdef uint8_t *iv = NULL
        cdef uint8_t *key = NULL
        cdef uint8_t *py_iv_t
        cdef uint8_t *py_key_t
        cdef uint32_t key_size
        cdef uint32_t iv_size
        cdef uint32_t buffer_size
        cdef uint32_t header_size = 2 * sizeof(uint32_t)
        cdef uint32_t ret = 1
        cdef uint32_t magic
        cdef int ret_wr = 0
        cdef int cipher_ret = 0
        cdef uint32_t length
        cdef EVP_CIPHER_CTX *ctx
        cdef const EVP_CIPHER *(*cipher_function) () nogil
        cdef int rd_fd
        cdef int wr_fd
        cdef int plain_ret
        IF REPLICATION_TRANSPORT_DEBUG:
            cdef uint8_t *log_buffer

        try:
            encryption_type = plugin.get('type', 'AES128')
            buffer_size = plugin.get('buffer_size', 1024*1024)
            rd_fd = plugin.get('read_fd').fd
            self.fds.append(rd_fd)
            wr_fd = plugin.get('write_fd').fd
            self.fds.append(wr_fd)
            cipher = cipher_types.get(encryption_type)
            cipher_function = <const EVP_CIPHER *(*)() nogil><uintptr_t> cipher['function']
            key_size = cipher['key_size']
            iv_size = cipher['iv_size']
            token = plugin.get('auth_token')

            initial_cipher = self.dispatcher.call_sync('replication.transport.get_encryption_data', token)

            IF REPLICATION_TRANSPORT_DEBUG:
                logger.debug('Decryption data fetched')
                logger.debug('py_key: {0} - py_iv: {1}'.format(initial_cipher['key'], initial_cipher['iv']))

            py_key = base64.b64decode(initial_cipher['key'].encode('utf-8'))
            py_iv = base64.b64decode(initial_cipher['iv'].encode('utf-8'))
            py_key_t = py_key
            py_iv_t = py_iv

            with nogil:
                cipherbuffer = <unsigned char *>malloc(buffer_size * sizeof(uint8_t))
                plainbuffer = <uint32_t *>malloc(buffer_size * sizeof(uint8_t))
                header_buffer = <uint32_t *>malloc(header_size * sizeof(uint8_t))

                byte_buffer = <uint8_t *> plainbuffer

                key = <uint8_t *>malloc(key_size * sizeof(uint8_t))
                iv = <uint8_t *>malloc(iv_size * sizeof(uint8_t))

            memcpy(key, <const void *> py_key_t, key_size)
            memcpy(iv, <const void *> py_iv_t, iv_size)

            IF REPLICATION_TRANSPORT_DEBUG:
                logger.debug('Key: {0}'.format(<bytes> key[:key_size]))
                logger.debug('IV: {0}'.format(<bytes> iv[:iv_size]))

            with nogil:
                ERR_load_crypto_strings()
                OpenSSL_add_all_algorithms()
                OPENSSL_config(NULL)
                ctx = EVP_CIPHER_CTX_new()
            if ctx == NULL:
                ERR_print_errors_fp(stderr)
                return
            with nogil:
                ret = EVP_DecryptInit_ex(ctx, cipher_function(), NULL, key, iv)
            if ret != 1:
                ERR_print_errors_fp(stderr)
                return

            logger.debug('Decryption context initialization completed')

            while True:
                with nogil:
                    cipher_ret = read_fd(rd_fd, cipherbuffer, header_size, 0)
                    if cipher_ret == -1:
                        break
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Got {0} bytes of cipher text'.format(cipher_ret))
                    log_buffer = <uint8_t *> cipherbuffer
                    logger.debug('Message: {0}'.format(<bytes> log_buffer[:cipher_ret]))

                with nogil:
                    ret = EVP_DecryptUpdate(ctx, <unsigned char *> header_buffer, &plain_ret, cipherbuffer, header_size)
                    if ret != 1:
                        ERR_print_errors_fp(stderr)
                        break
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Plain text size returned {0} bytes - header'.format(plain_ret))
                    logger.debug('Message length: {0} bytes'.format(header_buffer[1]))
                    log_buffer = <uint8_t *> header_buffer
                    logger.debug('Message: {0}'.format(<bytes> log_buffer[:plain_ret]))

                with nogil:
                    length = header_buffer[1]
                    if (header_buffer[0] != encrypt_transfer_magic) and (header_buffer[0] != encrypt_rekey_magic):
                        break

                    if length > 0:
                        cipher_ret = read_fd(rd_fd, cipherbuffer, length, 0)
                        if cipher_ret == -1:
                            break

                        ret = EVP_DecryptUpdate(ctx, <unsigned char *> plainbuffer, &plain_ret, cipherbuffer, length)
                    else:
                        ret = EVP_DecryptFinal_ex(ctx, <unsigned char *> plainbuffer, &plain_ret)

                    if ret != 1:
                        ERR_print_errors_fp(stderr)
                        break
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Plain text size returned {0} bytes'.format(plain_ret))
                    log_buffer = <uint8_t *> plainbuffer
                    logger.debug('Message: {0}'.format(<bytes> log_buffer[:plain_ret]))


                if header_buffer[0] == encrypt_rekey_magic:
                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Rekey magic received')
                    with nogil:
                        ret = EVP_DecryptFinal_ex(ctx, <unsigned char *> plainbuffer, &plain_ret)
                        if ret != 1:
                            ERR_print_errors_fp(stderr)
                            break
                        if plain_ret > 0:
                            ret_wr = write_fd(wr_fd, plainbuffer, plain_ret)
                            if ret_wr == -1:
                                break

                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Decryption context finalized. Starting new context')

                    with nogil:
                        EVP_CIPHER_CTX_free(ctx)
                        ctx = EVP_CIPHER_CTX_new()
                        if ctx == NULL:
                            ERR_print_errors_fp(stderr)
                            break

                        memcpy(key, byte_buffer, key_size)
                        memcpy(iv, &byte_buffer[key_size], iv_size)

                        ret = EVP_DecryptInit_ex(ctx, cipher_function(), NULL, key, iv)
                        if ret != 1:
                            ERR_print_errors_fp(stderr)
                            break

                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Initialized new decryption context.')
                        logger.debug('Key: {0}'.format(<bytes> key[:key_size]))
                        logger.debug('IV: {0}'.format(<bytes> iv[:iv_size]))

                else:
                    with nogil:
                        if plain_ret > 0:
                            ret_wr = write_fd(wr_fd, plainbuffer, plain_ret)
                            if ret_wr == -1:
                                break
                    if length == 0:
                        logger.debug('Decryption context finalized')
                        break
                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Wrote {0} bytes of plain text'.format(ret_wr))

        finally:
            if not self.aborted:
                if cipher_ret == -1:
                    raise TaskException(errno, 'Read from file descriptor failed during decryption task')

                if ret != 1:
                    raise TaskException(errno, 'Cryptographic function failed during decryption task')

                if ret_wr == -1:
                    raise TaskException(errno, 'Write to file descriptor failed during decryption task')

                if not ctx:
                    raise TaskException(errno, 'Cryptographic context creation failed')

                if header_buffer:
                    magic = header_buffer[0]
                    if magic:
                        if magic not in (encrypt_rekey_magic, encrypt_transfer_magic):
                            raise TaskException(EINVAL, 'Invalid magic received {0}'.format(magic))

            with nogil:
                EVP_CIPHER_CTX_free(ctx)
            free(plainbuffer)
            free(cipherbuffer)
            free(header_buffer)
            free(iv)
            free(key)
            close_fds(self.fds)

    def abort(self):
        self.aborted = True
        close_fds(self.fds)


@private
@description('Limit throughput to one buffer size per second')
@accepts(h.ref('throttle-replication-transport-plugin'))
class TransportThrottleTask(Task):
    def __init__(self, dispatcher, datastore):
        super(TransportThrottleTask, self).__init__(dispatcher, datastore)
        self.fds = []
        self.aborted = False

    @classmethod
    def early_describe(cls):
        return "Throttling replication stream"

    def describe(self, plugin):
        return TaskDescription(
            "Throttling replication stream to {throttle} iB/s",
            throttle=plugin.get('buffer_size', 50*1024*1024)
        )

    def verify(self, plugin):
        if 'read_fd' not in plugin:
            raise VerifyException(ENOENT, 'Read file descriptor is not specified')

        if 'write_fd' not in plugin:
            raise VerifyException(ENOENT, 'Write file descriptor is not specified')

        return []

    def run(self, plugin):
        cdef uint8_t *buffer = NULL
        cdef uint32_t buffer_size
        cdef int ret
        cdef int ret_wr
        cdef uint32_t done = 0
        cdef uint8_t running = 1
        cdef int rd_fd
        cdef int wr_fd

        timer_ovf = threading.Event()

        def timer():
            IF REPLICATION_TRANSPORT_DEBUG:
                logger.debug('Starting throttle task timer')
            while running:
                time.sleep(1)
                timer_ovf.set()

        try:
            buffer_size = plugin.get('buffer_size', 50*1024*1024)
            buffer = <uint8_t *>malloc(buffer_size * sizeof(uint8_t))
            rd_fd = plugin.get('read_fd').fd
            self.fds.append(rd_fd)
            wr_fd = plugin.get('write_fd').fd
            self.fds.append(wr_fd)
            IF REPLICATION_TRANSPORT_DEBUG:
                logger.debug('Starting throttle task - max transfer speed {0} B/s'.format(buffer_size))

            timer_t = threading.Thread(target=timer)
            timer_t.start()

            while True:
                with nogil:
                    ret = read(rd_fd, buffer + done, buffer_size - done)
                    if ret == -1:
                        if errno in (EINTR, EAGAIN):
                            continue
                        else:
                            break

                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Got {0} bytes from read file descriptor'.format(ret))

                if ret == 0:
                    logger.debug('Null byte received. Ending task.')
                    running = 0
                    break

                with nogil:
                    ret_wr = write_fd(wr_fd, buffer + done, ret)
                    if ret_wr == -1:
                        break
                IF REPLICATION_TRANSPORT_DEBUG:
                    logger.debug('Written {0} bytes to write file descriptor'.format(ret))

                done += ret
                if done == buffer_size:
                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Buffer full. Waiting')
                    timer_ovf.wait()
                    timer_ovf.clear()
                    done = 0
                    IF REPLICATION_TRANSPORT_DEBUG:
                        logger.debug('Throttle task released by timer.')

            if not self.aborted:
                if ret == -1:
                    raise TaskException(errno, 'Throttle task failed on read from file descriptor')

                if ret_wr == -1:
                    raise TaskException(errno, 'Throttle task failed on write to file descriptor')

        finally:
            free(buffer)
            close_fds([wr_fd, rd_fd])

    def abort(self):
        self.aborted = True
        close_fds(self.fds)


def close_fds(fds):
    if isinstance(fds, int):
        fds = [fds]
    try:
        for fd in fds:
            os.close(fd)
    except OSError:
        pass


def _init(dispatcher, plugin):
    # Register schemas
    plugin.register_schema_definition('replication-transport', {
        'type': 'object',
        'properties': {
            'server_address': {'type': 'string'},
            'client_address': {'type': 'string'},
            'server_port': {'type': 'integer'},
            'buffer_size': {'type': 'integer'},
            'auth_token': {'type': 'string'},
            'auth_token_size': {'type': 'integer'},
            'estimated_size': {'type': 'integer'},
            'transport_plugins': {
                'type': ['array', 'null'],
                'items': {'anyOf': [{'$ref': 'replication-transport-plugin'}, {'$ref': 'replication-transport-option'}]}
            },
            'receive_properties':{
                'name': {'type': 'string'},
                'force': {'type': 'boolean'},
                'nomount': {'type': 'boolean'},
                'props': {'type': 'object'},
                'limitds': {'type': 'object'}
            }
        },
        'additionalProperties': False
    })

    plugin.register_schema_definition('compress-replication-transport-plugin', {
        'type': 'object',
        'properties': {
            '%type': {'enum': ['compress-replication-transport-plugin']},
            'read_fd': {'type': 'fd'},
            'write_fd': {'type': 'fd'},
            'level': {'$ref': 'compress-plugin-level'},
            'buffer_size': {'type': 'integer'}
        },
        'additionalProperties': False
    })

    plugin.register_schema_definition('compress-plugin-level', {
        'type': 'string',
        'enum': ['FAST', 'DEFAULT', 'BEST']
    })

    plugin.register_schema_definition('encrypt-replication-transport-plugin', {
        'type': 'object',
        'properties': {
            '%type': {'enum': ['encrypt-replication-transport-plugin']},
            'type': {'$ref': 'encrypt-plugin-type'},
            'read_fd': {'type': 'fd'},
            'write_fd': {'type': 'fd'},
            'auth_token': {'type': 'string'},
            'remote': {'type': 'string'},
            'renewal_interval': {'type': 'integer'},
            'buffer_size': {'type': 'integer'}
        },
        'additionalProperties': False
    })

    plugin.register_schema_definition('encrypt-plugin-type', {
        'type': 'string',
        'enum': ['AES128', 'AES192', 'AES256']
    })

    plugin.register_schema_definition('throttle-replication-transport-plugin', {
        'type': 'object',
        'properties': {
            '%type': {'enum': ['throttle-replication-transport-plugin']},
            'buffer_size': {'type': 'integer'},
            'read_fd': {'type': 'fd'},
            'write_fd': {'type': 'fd'}
        },
        'additionalProperties': False
    })

    # Register providers
    plugin.register_provider('replication.transport', TransportProvider)

    # Register transport plugin schema
    plugin.register_schema_definition('replication-transport-plugin', {
        'discriminator': '%type',
        'oneOf': [
            {'$ref': '{0}-replication-transport-plugin'.format(name)} for name in dispatcher.call_sync(
                'replication.transport.plugin_types'
            )
        ]
    })

    # Register tasks
    plugin.register_task_handler("replication.transport.send", TransportSendTask)
    plugin.register_task_handler("replication.transport.receive", TransportReceiveTask)
    plugin.register_task_handler("replication.transport.compress", TransportCompressTask)
    plugin.register_task_handler("replication.transport.decompress", TransportDecompressTask)
    plugin.register_task_handler("replication.transport.encrypt", TransportEncryptTask)
    plugin.register_task_handler("replication.transport.decrypt", TransportDecryptTask)
    plugin.register_task_handler("replication.transport.throttle", TransportThrottleTask)
