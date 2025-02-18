const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

const Status = enum(usize) {
    Input = 10,
    Success = 20,
    SuccessEndClientCertificateSession = 21,
    RedirectTemporary = 30,
    RedirectPermanent = 31,
    TemporaryFailure = 40,
    ServerUnavailable = 41,
    CGIError = 42,
    ProxyError = 43,
    SlowDown = 44,
    PermanentFailure = 50,
    NotFound = 51,
    Gone = 52,
    ProxyRequestRefused = 53,
    BadRequest = 59,
    ClientCertRequired = 60,
    TransientCertRequest = 61,
    AuthorisedCertRequired = 62,
    CertNotAccepted = 63,
    FutureCertRejected = 64,
    ExpiredCertRejected = 65,
};

const Server = struct {
    const Self = @This();

    // address: []u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator) Server {
        return .{ .allocator = allocator };
    }

    pub fn handleConnection(_: Self, ctx: *c.SSL_CTX, conn: std.net.Stream) !void {
        defer conn.close();

        // Creates a new SSL structure needed to hold the data for a TLS/SSL connection.
        // Reference: https://docs.openssl.org/master/man3/SSL_new/#name
        const ssl = c.SSL_new(ctx) orelse return error.SSLCreateError;
        defer c.SSL_free(ssl);

        // Connect the SSL object with a file descriptor (typically socket descriptor of a network connection).
        // Reference: https://docs.openssl.org/master/man3/SSL_set_fd/
        const fd = conn.handle;
        _ = c.SSL_set_fd(ssl, @intCast(fd));

        // Wait for TLS/SSL client to initiate a TLS/SSL handshake.
        // Reference: https://docs.openssl.org/master/man3/SSL_accept/
        const accept_result = c.SSL_accept(ssl);
        if (accept_result <= 0) {
            const err = c.SSL_get_error(ssl, accept_result);
            std.debug.print("SSL accept error: {}\n", .{err});
            return error.SSLAcceptError;
        }

        // Read bytes from a TLS/SSL connection.
        // Reference: https://docs.openssl.org/master/man3/SSL_read/
        var buf: [1024]u8 = undefined;
        const read_bytes = c.SSL_read(ssl, &buf, buf.len);
        if (read_bytes <= 0) {
            return error.SSLReadError;
        }

        const uri = try std.Uri.parse(&buf);
        std.debug.print("{s}\n", .{uri.scheme});

        // Write bytes to a TLS/SSL connection.
        // Reference: https://docs.openssl.org/master/man3/SSL_write/
        const response = "20 text/gemini; lang=en; charset=utf-8\r\n\r\nHello from geminiz\n";
        const write_bytes = c.SSL_write(ssl, response.ptr, response.len);
        if (write_bytes <= 0) {
            return error.SSLWriteError;
        }

        // Shutdown SSL connection.
        // Reference: https://docs.openssl.org/master/man3/SSL_shutdown/
        _ = c.SSL_shutdown(ssl);
    }

    pub fn listen(self: Self) !void {
        // OpenSSL initialization.
        // Will allocate various resources at startup that must be freed on close down.
        // As of OpenSSL 1.1.0 resources will automatically be allocated and freed so no
        // explicit initialization is required. Though sometimes explicity initialization
        // is desirable. When disired it MUST be called by application code prior to any
        // other OpenSSL function calls.
        // Reference: https://docs.openssl.org/master/man3/OPENSSL_init_ssl/
        _ = c.OPENSSL_init_ssl(0, null);
        _ = c.OPENSSL_init_crypto(0, null);

        // Create SSL context.
        // These are general-purpose version-flexible SSL/TLS methods. The actual protocol
        // version used will be negotiated to the highest version mutually supported by the
        // client and the server.
        // https://docs.openssl.org/master/man3/SSL_CTX_new/#notes
        const method = c.TLS_server_method();
        const ctx = c.SSL_CTX_new(method) orelse {
            return error.SSLContextError;
        };
        defer c.SSL_CTX_free(ctx);

        // Load certificate and private key.
        // Loads the certificate stored in file into ctx.
        // SSL_CTX_use_certificate_chain_file() should be preferred.
        // Reference: https://docs.openssl.org/master/man3/SSL_CTX_use_certificate/#synopsis
        if (c.SSL_CTX_use_certificate_file(ctx, "cert.pem", c.SSL_FILETYPE_PEM) != 1) {
            c.ERR_print_errors_fp(c.stdout);
            return error.CertificateLoadError;
        }
        // Adds private key to ctx, MUST NOT be null.
        if (c.SSL_CTX_use_PrivateKey_file(ctx, "key.pem", c.SSL_FILETYPE_PEM) != 1) {
            c.ERR_print_errors_fp(c.stdout);
            return error.PrivateKeyLoadError;
        }

        // Create TCP server
        const address = try std.net.Address.parseIp("127.0.0.1", 1965);
        var server = try address.listen(.{ .reuse_address = true });
        defer server.deinit();

        std.debug.print("Server listening on {}\n", .{address});

        while (true) {
            const conn = try server.accept();
            try self.handleConnection(ctx, conn.stream);
        }
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const server = Server.init(allocator);
    try server.listen();
}
