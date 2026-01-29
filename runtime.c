#include <JavaScriptCore/JavaScriptCore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>
#include <regex.h>
#include <sys/time.h>
#include <sys/event.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <CommonCrypto/CommonCrypto.h>
#include <sys/sysctl.h>
#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <netdb.h>
#include <zlib.h>

// Module cache
static JSObjectRef module_cache = NULL;
static char current_dir[PATH_MAX];

// Event loop
static JSGlobalContextRef global_ctx = NULL;
static int kq = -1;

// Forward declarations
static char* read_file(const char* path);

// Store argc/argv for process object
static int global_argc = 0;
static char** global_argv = NULL;

// HTTP response data
typedef struct {
    char* data;
    size_t size;
    int status;
} HttpResponse;

// Microtask queue
typedef struct Microtask {
    JSObjectRef callback;
    struct Microtask* next;
} Microtask;

static Microtask* microtask_queue = NULL;
static Microtask* microtask_queue_tail = NULL;

// Timer structure
typedef struct Timer {
    int id;
    uint64_t target_time_ms;
    int interval_ms;
    JSObjectRef callback;
    int is_interval;
    int cancelled;
    struct Timer* next;
} Timer;

static Timer* timer_queue = NULL;
static int next_timer_id = 1;

// HTTP Server structure
typedef struct HttpServer {
    int socket_fd;
    int port;
    JSObjectRef handler;
    struct HttpServer* next;
} HttpServer;

static HttpServer* server_list = NULL;

// Test runner structure
typedef struct Test {
    char* name;
    JSObjectRef callback;
    struct Test* next;
} Test;

static Test* test_list = NULL;
static int test_count = 0;
static int test_passed = 0;
static int test_failed = 0;

// Async operation structure
typedef struct AsyncOp {
    enum { ASYNC_READ_FILE, ASYNC_WRITE_FILE } type;
    char* path;
    char* data;  // For write operations
    JSObjectRef callback;
    struct AsyncOp* next;
} AsyncOp;

static AsyncOp* async_queue = NULL;
static AsyncOp* async_queue_tail = NULL;

// Stream structure
typedef struct Stream {
    FILE* file;
    char* path;
    int is_readable;
    int is_writable;
    JSObjectRef data_callback;
    JSObjectRef end_callback;
    JSObjectRef error_callback;
    int chunk_size;
    int ended;
    struct Stream* next;
} Stream;

static Stream* stream_list = NULL;

// Hash context structure
typedef struct HashContext {
    CC_SHA1_CTX sha1;
    CC_SHA256_CTX sha256;
    CC_SHA512_CTX sha512;
    CC_MD5_CTX md5;
    enum { HASH_SHA1, HASH_SHA256, HASH_SHA512, HASH_MD5 } algorithm;
    int finalized;
} HashContext;

// HMAC context structure
typedef struct HmacContext {
    CCHmacContext hmac_ctx;
    CCHmacAlgorithm algorithm;
    int finalized;
} HmacContext;

// WebSocket connection structure
typedef struct WebSocket {
    int socket_fd;
    int is_client;
    int ready_state;  // 0=CONNECTING, 1=OPEN, 2=CLOSING, 3=CLOSED
    JSObjectRef onopen;
    JSObjectRef onmessage;
    JSObjectRef onerror;
    JSObjectRef onclose;
    char* url;
    char read_buffer[65536];
    size_t read_buffer_len;
    char handshake_buffer[1024];  // Stores client handshake until socket is writable
    size_t handshake_len;
    struct WebSocket* next;
} WebSocket;

static WebSocket* websocket_list = NULL;

// WebSocket opcodes
#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xA

// TCP Socket structure (for net module)
typedef struct TcpSocket {
    int socket_fd;
    int is_server;
    int connecting;
    JSObjectRef on_data;
    JSObjectRef on_end;
    JSObjectRef on_error;
    JSObjectRef on_close;
    JSObjectRef on_connect;
    char read_buffer[65536];
    size_t read_buffer_len;
    struct TcpSocket* next;
} TcpSocket;

static TcpSocket* tcp_socket_list = NULL;

// TCP Server structure (for net.createServer)
typedef struct TcpServer {
    int socket_fd;
    int port;
    JSObjectRef on_connection;
    JSObjectRef on_listening;
    JSObjectRef on_error;
    struct TcpServer* next;
} TcpServer;

static TcpServer* tcp_server_list = NULL;

// TLS/SSL structures
typedef enum {
    TLS_STATE_NONE = 0,
    TLS_STATE_HANDSHAKING,
    TLS_STATE_CONNECTED,
    TLS_STATE_CLOSED
} TlsState;

typedef struct TlsContext {
    SSLContextRef ssl_ctx;
    TlsState state;
    int socket_fd;
    SecIdentityRef identity;
    char* pending_write_data;
    size_t pending_write_len;
    char read_buffer[65536];
    size_t read_buffer_len;
    int is_server;
} TlsContext;

typedef struct HttpsServer {
    int socket_fd;
    int port;
    JSObjectRef handler;
    TlsContext* tls_template;
    struct HttpsServer* next;
} HttpsServer;

typedef struct TlsSocket {
    int socket_fd;
    TlsContext* tls_ctx;
    int is_server;
    int connecting;
    JSObjectRef handler;  // For HTTPS servers - the request handler function
    JSObjectRef on_secure_connect;
    JSObjectRef on_data;
    JSObjectRef on_end;
    JSObjectRef on_error;
    char read_buffer[8192];  // Buffer for reading HTTP request
    size_t read_buffer_len;
    struct TlsSocket* next;
} TlsSocket;

static HttpsServer* https_server_list = NULL;
static TlsSocket* tls_socket_list = NULL;

// Get current time in milliseconds
static uint64_t get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Add timer to queue
static void add_timer(Timer* timer) {
    timer->next = timer_queue;
    timer_queue = timer;
    JSValueProtect(global_ctx, timer->callback);
}

// Remove timer from queue
static void remove_timer(int id) {
    Timer** current = &timer_queue;
    while (*current) {
        if ((*current)->id == id) {
            (*current)->cancelled = 1;
            return;
        }
        current = &(*current)->next;
    }
}

// setTimeout implementation
static JSValueRef js_set_timeout(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount < 2) {
        return JSValueMakeNumber(ctx, 0);
    }

    JSObjectRef callback = JSValueToObject(ctx, arguments[0], NULL);
    int delay = (int)JSValueToNumber(ctx, arguments[1], NULL);

    Timer* timer = malloc(sizeof(Timer));
    timer->id = next_timer_id++;
    timer->target_time_ms = get_time_ms() + delay;
    timer->interval_ms = 0;
    timer->callback = callback;
    timer->is_interval = 0;
    timer->cancelled = 0;

    add_timer(timer);

    return JSValueMakeNumber(ctx, timer->id);
}

// setInterval implementation
static JSValueRef js_set_interval(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                   JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                   const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount < 2) {
        return JSValueMakeNumber(ctx, 0);
    }

    JSObjectRef callback = JSValueToObject(ctx, arguments[0], NULL);
    int interval = (int)JSValueToNumber(ctx, arguments[1], NULL);

    Timer* timer = malloc(sizeof(Timer));
    timer->id = next_timer_id++;
    timer->target_time_ms = get_time_ms() + interval;
    timer->interval_ms = interval;
    timer->callback = callback;
    timer->is_interval = 1;
    timer->cancelled = 0;

    add_timer(timer);

    return JSValueMakeNumber(ctx, timer->id);
}

// clearTimeout/clearInterval implementation
static JSValueRef js_clear_timer(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    int id = (int)JSValueToNumber(ctx, arguments[0], NULL);
    remove_timer(id);

    return JSValueMakeUndefined(ctx);
}

// queueMicrotask implementation
static JSValueRef js_queue_microtask(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                      JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                      const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSObjectRef callback = JSValueToObject(ctx, arguments[0], NULL);

    Microtask* task = malloc(sizeof(Microtask));
    task->callback = callback;
    task->next = NULL;
    JSValueProtect(global_ctx, callback);

    // Add to queue
    if (microtask_queue_tail) {
        microtask_queue_tail->next = task;
        microtask_queue_tail = task;
    } else {
        microtask_queue = task;
        microtask_queue_tail = task;
    }

    return JSValueMakeUndefined(ctx);
}

// Drain microtask queue
static void drain_microtasks() {
    while (microtask_queue) {
        Microtask* task = microtask_queue;
        microtask_queue = task->next;
        if (!microtask_queue) {
            microtask_queue_tail = NULL;
        }

        JSValueRef exception = NULL;
        JSObjectCallAsFunction(global_ctx, task->callback, NULL, 0, NULL, &exception);

        if (exception) {
            JSStringRef js_error = JSValueToStringCopy(global_ctx, exception, NULL);
            size_t max_size = JSStringGetMaximumUTF8CStringSize(js_error);
            char* error_buffer = malloc(max_size);
            JSStringGetUTF8CString(js_error, error_buffer, max_size);
            fprintf(stderr, "Microtask error: %s\n", error_buffer);
            free(error_buffer);
            JSStringRelease(js_error);
        }

        JSValueUnprotect(global_ctx, task->callback);
        free(task);
    }
}

// fs.readFileSync
static JSValueRef js_fs_read_file_sync(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                        JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                        const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    // Check if we should return binary data (Buffer)
    // If no options or options is string, read as text
    // If options is object or null, return Buffer
    int return_buffer = 0;
    if (argumentCount >= 2) {
        // Has options parameter - check if it's null or an object
        if (JSValueIsNull(ctx, arguments[1]) || JSValueIsObject(ctx, arguments[1])) {
            return_buffer = 1;
        }
    } else {
        // No options, but check file extension - .p12, .pfx, .der should be binary
        if (strstr(path, ".p12") || strstr(path, ".pfx") || strstr(path, ".der") ||
            strstr(path, ".bin") || strstr(path, ".key")) {
            return_buffer = 1;
        }
    }

    if (return_buffer) {
        // Read as binary and return Buffer (Uint8Array)
        FILE* file = fopen(path, "rb");
        free(path);

        if (!file) {
            JSStringRef error_str = JSStringCreateWithUTF8CString("File not found");
            *exception = JSValueMakeString(ctx, error_str);
            JSStringRelease(error_str);
            return JSValueMakeUndefined(ctx);
        }

        // Get file size
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        // Read file data
        unsigned char* data = malloc(file_size);
        size_t bytes_read = fread(data, 1, file_size, file);
        fclose(file);

        if (bytes_read != (size_t)file_size) {
            free(data);
            JSStringRef error_str = JSStringCreateWithUTF8CString("Failed to read file");
            *exception = JSValueMakeString(ctx, error_str);
            JSStringRelease(error_str);
            return JSValueMakeUndefined(ctx);
        }

        // Create Uint8Array
        JSObjectRef array = JSObjectMakeTypedArray(ctx, kJSTypedArrayTypeUint8Array, file_size, exception);
        if (*exception) {
            free(data);
            return JSValueMakeUndefined(ctx);
        }

        // Copy data into the array
        JSObjectRef buffer = JSObjectGetTypedArrayBuffer(ctx, array, exception);
        if (*exception) {
            free(data);
            return JSValueMakeUndefined(ctx);
        }

        void* array_data = JSObjectGetTypedArrayBytesPtr(ctx, array, exception);
        if (*exception || !array_data) {
            free(data);
            return JSValueMakeUndefined(ctx);
        }

        memcpy(array_data, data, file_size);
        free(data);

        return array;
    } else {
        // Read as text (original behavior)
        char* content = read_file(path);
        free(path);

        if (!content) {
            JSStringRef error_str = JSStringCreateWithUTF8CString("File not found");
            *exception = JSValueMakeString(ctx, error_str);
            JSStringRelease(error_str);
            return JSValueMakeUndefined(ctx);
        }

        JSStringRef result_str = JSStringCreateWithUTF8CString(content);
        JSValueRef result = JSValueMakeString(ctx, result_str);
        JSStringRelease(result_str);
        free(content);

        return result;
    }
}

// fs.writeFileSync
static JSValueRef js_fs_write_file_sync(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                         JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                         const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t path_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(path_size);
    JSStringGetUTF8CString(path_str, path, path_size);
    JSStringRelease(path_str);

    JSStringRef data_str = JSValueToStringCopy(ctx, arguments[1], exception);
    if (*exception) {
        free(path);
        return JSValueMakeUndefined(ctx);
    }

    size_t data_size = JSStringGetMaximumUTF8CStringSize(data_str);
    char* data = malloc(data_size);
    JSStringGetUTF8CString(data_str, data, data_size);
    JSStringRelease(data_str);

    FILE* file = fopen(path, "w");
    if (!file) {
        free(path);
        free(data);
        JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot write file");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    fputs(data, file);
    fclose(file);
    free(path);
    free(data);

    return JSValueMakeUndefined(ctx);
}

// fs.existsSync
static JSValueRef js_fs_exists_sync(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                     JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                     const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeBoolean(ctx, false);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeBoolean(ctx, false);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    struct stat st;
    int exists = stat(path, &st) == 0;
    free(path);

    return JSValueMakeBoolean(ctx, exists);
}

// fs.readdirSync
static JSValueRef js_fs_readdir_sync(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                      JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                      const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    DIR* dir = opendir(path);
    free(path);

    if (!dir) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot read directory");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    JSValueRef* items = NULL;
    size_t count = 0;
    size_t capacity = 16;
    items = malloc(sizeof(JSValueRef) * capacity);

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (count >= capacity) {
            capacity *= 2;
            items = realloc(items, sizeof(JSValueRef) * capacity);
        }

        JSStringRef name_str = JSStringCreateWithUTF8CString(entry->d_name);
        items[count++] = JSValueMakeString(ctx, name_str);
        JSStringRelease(name_str);
    }

    closedir(dir);

    JSObjectRef array = JSObjectMakeArray(ctx, count, items, exception);
    free(items);

    return array;
}

// fs.mkdirSync
static JSValueRef js_fs_mkdir_sync(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                    JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                    const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    int result = mkdir(path, 0755);
    free(path);

    if (result != 0) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot create directory");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
    }

    return JSValueMakeUndefined(ctx);
}

// fs.rmdirSync
static JSValueRef js_fs_rmdir_sync(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                    JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                    const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    int result = rmdir(path);
    free(path);

    if (result != 0) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot remove directory");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
    }

    return JSValueMakeUndefined(ctx);
}

// fs.unlinkSync
static JSValueRef js_fs_unlink_sync(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                     JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                     const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    int result = unlink(path);
    free(path);

    if (result != 0) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot delete file");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
    }

    return JSValueMakeUndefined(ctx);
}

// Queue async operation
static void queue_async_op(AsyncOp* op) {
    op->next = NULL;
    JSValueProtect(global_ctx, op->callback);

    if (async_queue_tail) {
        async_queue_tail->next = op;
        async_queue_tail = op;
    } else {
        async_queue = op;
        async_queue_tail = op;
    }
}

// Process async operations (called from event loop)
static void process_async_ops() {
    AsyncOp* op = async_queue;
    AsyncOp* prev = NULL;

    while (op) {
        AsyncOp* next = op->next;

        // Execute the operation
        JSValueRef result = NULL;
        JSValueRef error = NULL;

        if (op->type == ASYNC_READ_FILE) {
            char* content = read_file(op->path);
            if (content) {
                JSStringRef content_str = JSStringCreateWithUTF8CString(content);
                result = JSValueMakeString(global_ctx, content_str);
                JSStringRelease(content_str);
                free(content);
            } else {
                JSStringRef error_str = JSStringCreateWithUTF8CString("File not found");
                error = JSValueMakeString(global_ctx, error_str);
                JSStringRelease(error_str);
            }
        } else if (op->type == ASYNC_WRITE_FILE) {
            FILE* file = fopen(op->path, "w");
            if (file) {
                fputs(op->data, file);
                fclose(file);
                result = JSValueMakeUndefined(global_ctx);
            } else {
                JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot write file");
                error = JSValueMakeString(global_ctx, error_str);
                JSStringRelease(error_str);
            }
        }

        // Call callback(error, result)
        JSValueRef args[2] = { error ? error : JSValueMakeNull(global_ctx), result ? result : JSValueMakeUndefined(global_ctx) };
        JSObjectCallAsFunction(global_ctx, op->callback, NULL, 2, args, NULL);

        // Cleanup
        JSValueUnprotect(global_ctx, op->callback);
        free(op->path);
        if (op->data) free(op->data);
        free(op);

        // Remove from queue
        if (prev) {
            prev->next = next;
        } else {
            async_queue = next;
        }
        if (op == async_queue_tail) {
            async_queue_tail = prev;
        }

        op = next;
    }
}

// fs.readFile (async)
static JSValueRef js_fs_read_file(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                   JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                   const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("readFile requires path and callback");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    JSObjectRef callback = JSValueToObject(ctx, arguments[1], NULL);

    AsyncOp* op = malloc(sizeof(AsyncOp));
    op->type = ASYNC_READ_FILE;
    op->path = path;
    op->data = NULL;
    op->callback = callback;

    queue_async_op(op);

    return JSValueMakeUndefined(ctx);
}

// fs.writeFile (async)
static JSValueRef js_fs_write_file(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                    JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                    const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 3) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("writeFile requires path, data, and callback");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t path_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(path_size);
    JSStringGetUTF8CString(path_str, path, path_size);
    JSStringRelease(path_str);

    JSStringRef data_str = JSValueToStringCopy(ctx, arguments[1], exception);
    if (*exception) {
        free(path);
        return JSValueMakeUndefined(ctx);
    }

    size_t data_size = JSStringGetMaximumUTF8CStringSize(data_str);
    char* data = malloc(data_size);
    JSStringGetUTF8CString(data_str, data, data_size);
    JSStringRelease(data_str);

    JSObjectRef callback = JSValueToObject(ctx, arguments[2], NULL);

    AsyncOp* op = malloc(sizeof(AsyncOp));
    op->type = ASYNC_WRITE_FILE;
    op->path = path;
    op->data = data;
    op->callback = callback;

    queue_async_op(op);

    return JSValueMakeUndefined(ctx);
}

// Buffer.from(string/array)
static JSValueRef js_buffer_from(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef code = JSStringCreateWithUTF8CString("new Uint8Array(__temp_buffer_data)");

    // For strings, convert to UTF-8 bytes
    if (JSValueIsString(ctx, arguments[0])) {
        JSStringRef str = JSValueToStringCopy(ctx, arguments[0], exception);
        if (*exception) return JSValueMakeUndefined(ctx);

        size_t max_size = JSStringGetMaximumUTF8CStringSize(str);
        char* buffer = malloc(max_size);
        size_t actual_size = JSStringGetUTF8CString(str, buffer, max_size);
        JSStringRelease(str);

        // Store data temporarily
        JSValueRef* byte_values = malloc(sizeof(JSValueRef) * (actual_size - 1));
        for (size_t i = 0; i < actual_size - 1; i++) {
            byte_values[i] = JSValueMakeNumber(ctx, (unsigned char)buffer[i]);
        }
        JSObjectRef array = JSObjectMakeArray(ctx, actual_size - 1, byte_values, NULL);
        free(byte_values);
        free(buffer);

        JSStringRef temp_name = JSStringCreateWithUTF8CString("__temp_buffer_data");
        JSObjectSetProperty(ctx, global, temp_name, array, kJSPropertyAttributeNone, NULL);
        JSStringRelease(temp_name);

        JSValueRef result = JSEvaluateScript(ctx, code, NULL, NULL, 1, exception);
        JSStringRelease(code);

        return result;
    }

    // For arrays, copy byte values
    JSObjectRef obj = JSValueToObject(ctx, arguments[0], exception);
    if (obj) {
        JSStringRef length_name = JSStringCreateWithUTF8CString("length");
        JSValueRef length_val = JSObjectGetProperty(ctx, obj, length_name, NULL);
        JSStringRelease(length_name);

        if (JSValueIsNumber(ctx, length_val)) {
            size_t length = (size_t)JSValueToNumber(ctx, length_val, NULL);
            JSValueRef* byte_values = malloc(sizeof(JSValueRef) * length);

            for (size_t i = 0; i < length; i++) {
                JSValueRef val = JSObjectGetPropertyAtIndex(ctx, obj, i, NULL);
                byte_values[i] = JSValueMakeNumber(ctx, (unsigned char)JSValueToNumber(ctx, val, NULL));
            }

            JSObjectRef array = JSObjectMakeArray(ctx, length, byte_values, NULL);
            free(byte_values);

            JSStringRef temp_name = JSStringCreateWithUTF8CString("__temp_buffer_data");
            JSObjectSetProperty(ctx, global, temp_name, array, kJSPropertyAttributeNone, NULL);
            JSStringRelease(temp_name);

            JSValueRef result = JSEvaluateScript(ctx, code, NULL, NULL, 1, exception);
            JSStringRelease(code);

            return result;
        }
    }

    JSStringRelease(code);
    return JSValueMakeUndefined(ctx);
}

// Buffer.alloc(size)
static JSValueRef js_buffer_alloc(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                   JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                   const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    int size = (int)JSValueToNumber(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    // Create Uint8Array of specified size
    char code_buf[256];
    snprintf(code_buf, sizeof(code_buf), "new Uint8Array(%d)", size);
    JSStringRef code = JSStringCreateWithUTF8CString(code_buf);
    JSValueRef result = JSEvaluateScript(ctx, code, NULL, NULL, 1, exception);
    JSStringRelease(code);

    return result;
}

// Stream.on(event, callback)
static JSValueRef js_stream_on(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                               JSObjectRef thisObject, size_t argumentCount,
                               const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef event_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(event_str);
    char* event = malloc(max_size);
    JSStringGetUTF8CString(event_str, event, max_size);
    JSStringRelease(event_str);

    JSObjectRef callback = JSValueToObject(ctx, arguments[1], NULL);

    // Get stream pointer from object
    JSStringRef ptr_name = JSStringCreateWithUTF8CString("__stream_ptr");
    JSValueRef ptr_val = JSObjectGetProperty(ctx, thisObject, ptr_name, NULL);
    JSStringRelease(ptr_name);

    if (!JSValueIsNumber(ctx, ptr_val)) {
        free(event);
        return JSValueMakeUndefined(ctx);
    }

    Stream* stream = (Stream*)(uintptr_t)JSValueToNumber(ctx, ptr_val, NULL);

    if (strcmp(event, "data") == 0) {
        stream->data_callback = callback;
        JSValueProtect(global_ctx, callback);
    } else if (strcmp(event, "end") == 0) {
        stream->end_callback = callback;
        JSValueProtect(global_ctx, callback);
    } else if (strcmp(event, "error") == 0) {
        stream->error_callback = callback;
        JSValueProtect(global_ctx, callback);
    }

    free(event);
    return thisObject;
}

// fs.createReadStream(path)
static JSValueRef js_create_read_stream(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                        JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                        const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    FILE* file = fopen(path, "r");
    if (!file) {
        free(path);
        JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot open file for reading");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    Stream* stream = malloc(sizeof(Stream));
    stream->file = file;
    stream->path = path;
    stream->is_readable = 1;
    stream->is_writable = 0;
    stream->data_callback = NULL;
    stream->end_callback = NULL;
    stream->error_callback = NULL;
    stream->chunk_size = 4096;
    stream->ended = 0;
    stream->next = stream_list;
    stream_list = stream;

    // Create stream object
    JSObjectRef stream_obj = JSObjectMake(ctx, NULL, NULL);

    // Store stream pointer
    JSStringRef ptr_name = JSStringCreateWithUTF8CString("__stream_ptr");
    JSObjectSetProperty(ctx, stream_obj, ptr_name, JSValueMakeNumber(ctx, (uintptr_t)stream), kJSPropertyAttributeNone, NULL);
    JSStringRelease(ptr_name);

    // Add on method
    JSStringRef on_name = JSStringCreateWithUTF8CString("on");
    JSObjectRef on_func = JSObjectMakeFunctionWithCallback(ctx, on_name, js_stream_on);
    JSObjectSetProperty(ctx, stream_obj, on_name, on_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(on_name);

    return stream_obj;
}

// fs.createWriteStream(path)
static JSValueRef js_create_write_stream(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                         JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                         const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    FILE* file = fopen(path, "w");
    if (!file) {
        free(path);
        JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot open file for writing");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    Stream* stream = malloc(sizeof(Stream));
    stream->file = file;
    stream->path = path;
    stream->is_readable = 0;
    stream->is_writable = 1;
    stream->data_callback = NULL;
    stream->end_callback = NULL;
    stream->error_callback = NULL;
    stream->chunk_size = 4096;
    stream->ended = 0;
    stream->next = stream_list;
    stream_list = stream;

    // Create stream object with write/end methods
    JSStringRef code = JSStringCreateWithUTF8CString(
        "(function(ptr) {"
        "  return {"
        "    __stream_ptr: ptr,"
        "    write: function(data) { __stream_write(this.__stream_ptr, data); return this; },"
        "    end: function() { __stream_end(this.__stream_ptr); }"
        "  };"
        "})"
    );
    JSValueRef func_val = JSEvaluateScript(ctx, code, NULL, NULL, 1, NULL);
    JSStringRelease(code);

    JSObjectRef func = JSValueToObject(ctx, func_val, NULL);
    JSValueRef args[] = {JSValueMakeNumber(ctx, (uintptr_t)stream)};
    return JSValueToObject(ctx, JSObjectCallAsFunction(ctx, func, NULL, 1, args, NULL), NULL);
}

// __stream_write helper
static JSValueRef js_stream_write(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        return JSValueMakeUndefined(ctx);
    }

    uintptr_t ptr = (uintptr_t)JSValueToNumber(ctx, arguments[0], NULL);
    Stream* stream = (Stream*)ptr;

    JSStringRef data_str = JSValueToStringCopy(ctx, arguments[1], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(data_str);
    char* data = malloc(max_size);
    JSStringGetUTF8CString(data_str, data, max_size);
    JSStringRelease(data_str);

    if (stream->file) {
        fputs(data, stream->file);
        fflush(stream->file);
    }

    free(data);
    return JSValueMakeUndefined(ctx);
}

// __stream_end helper
static JSValueRef js_stream_end(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    uintptr_t ptr = (uintptr_t)JSValueToNumber(ctx, arguments[0], NULL);
    Stream* stream = (Stream*)ptr;

    if (stream->file) {
        fclose(stream->file);
        stream->file = NULL;
    }
    stream->ended = 1;

    return JSValueMakeUndefined(ctx);
}

// Process streams (called from event loop)
static void process_streams() {
    Stream* stream = stream_list;
    while (stream) {
        if (stream->is_readable && !stream->ended && stream->data_callback) {
            char buffer[4096];
            size_t bytes_read = fread(buffer, 1, stream->chunk_size, stream->file);

            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                JSStringRef chunk_str = JSStringCreateWithUTF8CString(buffer);
                JSValueRef args[] = {JSValueMakeString(global_ctx, chunk_str)};
                JSStringRelease(chunk_str);

                JSObjectCallAsFunction(global_ctx, stream->data_callback, NULL, 1, args, NULL);
            }

            if (feof(stream->file) || bytes_read == 0) {
                stream->ended = 1;
                if (stream->end_callback) {
                    JSObjectCallAsFunction(global_ctx, stream->end_callback, NULL, 0, NULL, NULL);
                }
                if (stream->file) {
                    fclose(stream->file);
                    stream->file = NULL;
                }
            }
        }
        stream = stream->next;
    }
}

// child_process.execSync - execute command and return output
static JSValueRef js_exec_sync(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                               JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                               const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef cmd_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(cmd_str);
    char* command = malloc(max_size);
    JSStringGetUTF8CString(cmd_str, command, max_size);
    JSStringRelease(cmd_str);

    // Use popen to capture output
    FILE* pipe = popen(command, "r");
    free(command);

    if (!pipe) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("Failed to execute command");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Read output
    char* output = malloc(8192);
    size_t output_size = 0;
    size_t capacity = 8192;
    char buffer[1024];

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        size_t len = strlen(buffer);
        if (output_size + len >= capacity) {
            capacity *= 2;
            output = realloc(output, capacity);
        }
        memcpy(output + output_size, buffer, len);
        output_size += len;
    }
    output[output_size] = '\0';

    int status = pclose(pipe);

    if (status != 0) {
        free(output);
        JSStringRef error_str = JSStringCreateWithUTF8CString("Command failed");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef result_str = JSStringCreateWithUTF8CString(output);
    JSValueRef result = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    free(output);

    return result;
}

// child_process.spawnSync - spawn command with args
static JSValueRef js_spawn_sync(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef cmd_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t cmd_size = JSStringGetMaximumUTF8CStringSize(cmd_str);
    char* command = malloc(cmd_size);
    JSStringGetUTF8CString(cmd_str, command, cmd_size);
    JSStringRelease(cmd_str);

    // Build full command with args
    char full_cmd[4096];
    snprintf(full_cmd, sizeof(full_cmd), "%s", command);
    free(command);

    // Add arguments if provided
    if (argumentCount > 1 && JSValueIsObject(ctx, arguments[1])) {
        JSObjectRef args_array = JSValueToObject(ctx, arguments[1], NULL);
        JSStringRef length_name = JSStringCreateWithUTF8CString("length");
        JSValueRef length_val = JSObjectGetProperty(ctx, args_array, length_name, NULL);
        JSStringRelease(length_name);

        int argc = (int)JSValueToNumber(ctx, length_val, NULL);
        for (int i = 0; i < argc; i++) {
            JSValueRef arg_val = JSObjectGetPropertyAtIndex(ctx, args_array, i, NULL);
            JSStringRef arg_str = JSValueToStringCopy(ctx, arg_val, NULL);

            size_t arg_size = JSStringGetMaximumUTF8CStringSize(arg_str);
            char* arg = malloc(arg_size);
            JSStringGetUTF8CString(arg_str, arg, arg_size);
            JSStringRelease(arg_str);

            strcat(full_cmd, " ");
            strcat(full_cmd, arg);
            free(arg);
        }
    }

    // Execute command
    FILE* pipe = popen(full_cmd, "r");
    if (!pipe) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("Failed to spawn process");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Read output
    char* output = malloc(8192);
    size_t output_size = 0;
    size_t capacity = 8192;
    char buffer[1024];

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        size_t len = strlen(buffer);
        if (output_size + len >= capacity) {
            capacity *= 2;
            output = realloc(output, capacity);
        }
        memcpy(output + output_size, buffer, len);
        output_size += len;
    }
    output[output_size] = '\0';

    int status = pclose(pipe);

    // Create result object
    JSObjectRef result_obj = JSObjectMake(ctx, NULL, NULL);

    JSStringRef stdout_name = JSStringCreateWithUTF8CString("stdout");
    JSStringRef stdout_str = JSStringCreateWithUTF8CString(output);
    JSObjectSetProperty(ctx, result_obj, stdout_name, JSValueMakeString(ctx, stdout_str), kJSPropertyAttributeNone, NULL);
    JSStringRelease(stdout_name);
    JSStringRelease(stdout_str);

    JSStringRef status_name = JSStringCreateWithUTF8CString("status");
    JSObjectSetProperty(ctx, result_obj, status_name, JSValueMakeNumber(ctx, WEXITSTATUS(status)), kJSPropertyAttributeNone, NULL);
    JSStringRelease(status_name);

    free(output);
    return result_obj;
}

// path.join implementation
static JSValueRef js_path_join(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount == 0) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("."));
    }

    char result[PATH_MAX * 2] = {0};
    char* out = result;

    for (size_t i = 0; i < argumentCount; i++) {
        JSStringRef seg_str = JSValueToStringCopy(ctx, arguments[i], exception);
        if (*exception) return JSValueMakeUndefined(ctx);

        size_t max_size = JSStringGetMaximumUTF8CStringSize(seg_str);
        char* segment = malloc(max_size);
        JSStringGetUTF8CString(seg_str, segment, max_size);
        JSStringRelease(seg_str);

        // Skip empty segments
        if (strlen(segment) == 0) {
            free(segment);
            continue;
        }

        // Handle absolute paths
        if (segment[0] == '/' && out == result) {
            out += sprintf(out, "/");
        } else if (out > result && *(out - 1) != '/') {
            out += sprintf(out, "/");
        }

        // Copy segment, skipping leading slash
        const char* src = (segment[0] == '/') ? segment + 1 : segment;
        while (*src) {
            *out++ = *src++;
        }

        free(segment);
    }
    *out = '\0';

    // Normalize (resolve ..)
    char normalized[PATH_MAX * 2];
    char* segments[256];
    int seg_count = 0;
    int is_absolute = (result[0] == '/');

    char* copy = strdup(result);
    char* token = strtok(copy, "/");
    while (token) {
        if (strcmp(token, "..") == 0) {
            if (seg_count > 0 && strcmp(segments[seg_count - 1], "..") != 0) {
                seg_count--;
            } else if (!is_absolute) {
                segments[seg_count++] = "..";
            }
        } else if (strcmp(token, ".") != 0) {
            segments[seg_count++] = token;
        }
        token = strtok(NULL, "/");
    }

    char* norm = normalized;
    if (is_absolute) *norm++ = '/';
    for (int i = 0; i < seg_count; i++) {
        if (i > 0) *norm++ = '/';
        strcpy(norm, segments[i]);
        norm += strlen(segments[i]);
    }
    *norm = '\0';
    free(copy);

    if (normalized[0] == '\0') {
        strcpy(normalized, ".");
    }

    JSStringRef result_str = JSStringCreateWithUTF8CString(normalized);
    JSValueRef result_val = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);

    return result_val;
}

// path.basename implementation
static JSValueRef js_path_basename(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                    JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                    const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(""));
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    char* base = basename(path);
    char* result = strdup(base);
    free(path);

    // Handle optional extension to strip
    if (argumentCount >= 2) {
        JSStringRef ext_str = JSValueToStringCopy(ctx, arguments[1], exception);
        if (!*exception) {
            size_t ext_size = JSStringGetMaximumUTF8CStringSize(ext_str);
            char* ext = malloc(ext_size);
            JSStringGetUTF8CString(ext_str, ext, ext_size);
            JSStringRelease(ext_str);

            size_t result_len = strlen(result);
            size_t ext_len = strlen(ext);
            if (result_len >= ext_len && strcmp(result + result_len - ext_len, ext) == 0) {
                result[result_len - ext_len] = '\0';
            }
            free(ext);
        }
    }

    JSStringRef result_str = JSStringCreateWithUTF8CString(result);
    JSValueRef result_val = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    free(result);

    return result_val;
}

// path.dirname implementation
static JSValueRef js_path_dirname(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                   JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                   const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("."));
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    char* dir = dirname(path);
    char* result = strdup(dir);
    free(path);

    JSStringRef result_str = JSStringCreateWithUTF8CString(result);
    JSValueRef result_val = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    free(result);

    return result_val;
}

// path.extname implementation
static JSValueRef js_path_extname(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                   JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                   const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(""));
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    char* dot = strrchr(path, '.');
    char* slash = strrchr(path, '/');

    char* result = "";
    if (dot && (!slash || dot > slash)) {
        result = dot;
    }

    JSStringRef result_str = JSStringCreateWithUTF8CString(result);
    JSValueRef result_val = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    free(path);

    return result_val;
}

// path.resolve implementation
static JSValueRef js_path_resolve(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                   JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                   const JSValueRef arguments[], JSValueRef* exception) {
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));

    char result[PATH_MAX * 2];
    strcpy(result, cwd);

    for (size_t i = 0; i < argumentCount; i++) {
        JSStringRef seg_str = JSValueToStringCopy(ctx, arguments[i], exception);
        if (*exception) return JSValueMakeUndefined(ctx);

        size_t max_size = JSStringGetMaximumUTF8CStringSize(seg_str);
        char* segment = malloc(max_size);
        JSStringGetUTF8CString(seg_str, segment, max_size);
        JSStringRelease(seg_str);

        if (segment[0] == '/') {
            strcpy(result, segment);
        } else {
            strcat(result, "/");
            strcat(result, segment);
        }

        free(segment);
    }

    char* real = realpath(result, NULL);
    if (!real) {
        // If realpath fails, normalize manually
        real = strdup(result);
    }

    JSStringRef result_str = JSStringCreateWithUTF8CString(real);
    JSValueRef result_val = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    free(real);

    return result_val;
}

// path.isAbsolute implementation
static JSValueRef js_path_is_absolute(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                       JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                       const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeBoolean(ctx, false);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeBoolean(ctx, false);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    int is_absolute = (path[0] == '/');
    free(path);

    return JSValueMakeBoolean(ctx, is_absolute);
}

// crypto.randomBytes implementation
static JSValueRef js_crypto_random_bytes(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                          JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                          const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        JSStringRef error = JSStringCreateWithUTF8CString("randomBytes requires size argument");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    int size = (int)JSValueToNumber(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    if (size <= 0 || size > 65536) {
        JSStringRef error = JSStringCreateWithUTF8CString("size must be between 1 and 65536");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    unsigned char* buffer = malloc(size);

    // Use /dev/urandom for secure random bytes
    FILE* urandom = fopen("/dev/urandom", "r");
    if (!urandom) {
        free(buffer);
        JSStringRef error = JSStringCreateWithUTF8CString("Failed to open /dev/urandom");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    size_t read_bytes = fread(buffer, 1, size, urandom);
    fclose(urandom);

    if (read_bytes != (size_t)size) {
        free(buffer);
        JSStringRef error = JSStringCreateWithUTF8CString("Failed to generate random bytes");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    JSObjectRef array = JSObjectMakeTypedArray(ctx, kJSTypedArrayTypeUint8Array, size, exception);
    if (*exception) {
        free(buffer);
        return JSValueMakeUndefined(ctx);
    }

    unsigned char* array_buffer = JSObjectGetTypedArrayBytesPtr(ctx, array, exception);
    if (*exception) {
        free(buffer);
        return JSValueMakeUndefined(ctx);
    }

    memcpy(array_buffer, buffer, size);
    free(buffer);

    return array;
}

// Hash finalizer
static void hash_finalizer(JSObjectRef object) {
    HashContext* ctx = JSObjectGetPrivate(object);
    if (ctx) {
        free(ctx);
    }
}

// hash.update implementation
static JSValueRef js_hash_update(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject, size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception) {
    HashContext* hash_ctx = JSObjectGetPrivate(thisObject);
    if (!hash_ctx) {
        JSStringRef error = JSStringCreateWithUTF8CString("Invalid hash object");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    if (hash_ctx->finalized) {
        JSStringRef error = JSStringCreateWithUTF8CString("Cannot update finalized hash");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    if (argumentCount < 1) {
        return thisObject;
    }

    JSStringRef data_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(data_str);
    char* data = malloc(max_size);
    JSStringGetUTF8CString(data_str, data, max_size);
    JSStringRelease(data_str);

    size_t data_len = strlen(data);

    switch (hash_ctx->algorithm) {
        case HASH_MD5:
            CC_MD5_Update(&hash_ctx->md5, data, (CC_LONG)data_len);
            break;
        case HASH_SHA1:
            CC_SHA1_Update(&hash_ctx->sha1, data, data_len);
            break;
        case HASH_SHA256:
            CC_SHA256_Update(&hash_ctx->sha256, data, (CC_LONG)data_len);
            break;
        case HASH_SHA512:
            CC_SHA512_Update(&hash_ctx->sha512, data, data_len);
            break;
    }

    free(data);
    return thisObject;
}

// hash.digest implementation
static JSValueRef js_hash_digest(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject, size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception) {
    HashContext* hash_ctx = JSObjectGetPrivate(thisObject);
    if (!hash_ctx) {
        JSStringRef error = JSStringCreateWithUTF8CString("Invalid hash object");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    if (hash_ctx->finalized) {
        JSStringRef error = JSStringCreateWithUTF8CString("Hash already finalized");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    unsigned char digest[CC_SHA512_DIGEST_LENGTH];
    int digest_len = 0;

    switch (hash_ctx->algorithm) {
        case HASH_MD5:
            CC_MD5_Final(digest, &hash_ctx->md5);
            digest_len = CC_MD5_DIGEST_LENGTH;
            break;
        case HASH_SHA1:
            CC_SHA1_Final(digest, &hash_ctx->sha1);
            digest_len = CC_SHA1_DIGEST_LENGTH;
            break;
        case HASH_SHA256:
            CC_SHA256_Final(digest, &hash_ctx->sha256);
            digest_len = CC_SHA256_DIGEST_LENGTH;
            break;
        case HASH_SHA512:
            CC_SHA512_Final(digest, &hash_ctx->sha512);
            digest_len = CC_SHA512_DIGEST_LENGTH;
            break;
    }

    hash_ctx->finalized = 1;

    // Default to hex encoding
    char* encoding = "hex";
    if (argumentCount > 0) {
        JSStringRef enc_str = JSValueToStringCopy(ctx, arguments[0], NULL);
        size_t max_size = JSStringGetMaximumUTF8CStringSize(enc_str);
        encoding = malloc(max_size);
        JSStringGetUTF8CString(enc_str, encoding, max_size);
        JSStringRelease(enc_str);
    }

    if (strcmp(encoding, "hex") == 0) {
        char* hex = malloc(digest_len * 2 + 1);
        for (int i = 0; i < digest_len; i++) {
            sprintf(hex + i * 2, "%02x", digest[i]);
        }
        hex[digest_len * 2] = '\0';

        JSStringRef result_str = JSStringCreateWithUTF8CString(hex);
        JSValueRef result = JSValueMakeString(ctx, result_str);
        JSStringRelease(result_str);
        free(hex);
        if (argumentCount > 0) free(encoding);
        return result;
    } else {
        // Return Buffer (Uint8Array)
        JSObjectRef array = JSObjectMakeTypedArray(ctx, kJSTypedArrayTypeUint8Array, digest_len, exception);
        if (*exception) {
            if (argumentCount > 0) free(encoding);
            return JSValueMakeUndefined(ctx);
        }

        unsigned char* array_buffer = JSObjectGetTypedArrayBytesPtr(ctx, array, exception);
        if (*exception) {
            if (argumentCount > 0) free(encoding);
            return JSValueMakeUndefined(ctx);
        }

        memcpy(array_buffer, digest, digest_len);
        if (argumentCount > 0) free(encoding);
        return array;
    }
}

// crypto.createHash implementation
static JSValueRef js_crypto_create_hash(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                         JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                         const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        JSStringRef error = JSStringCreateWithUTF8CString("createHash requires algorithm argument");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef algo_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(algo_str);
    char* algorithm = malloc(max_size);
    JSStringGetUTF8CString(algo_str, algorithm, max_size);
    JSStringRelease(algo_str);

    HashContext* hash_ctx = malloc(sizeof(HashContext));
    hash_ctx->finalized = 0;

    if (strcmp(algorithm, "md5") == 0) {
        hash_ctx->algorithm = HASH_MD5;
        CC_MD5_Init(&hash_ctx->md5);
    } else if (strcmp(algorithm, "sha1") == 0) {
        hash_ctx->algorithm = HASH_SHA1;
        CC_SHA1_Init(&hash_ctx->sha1);
    } else if (strcmp(algorithm, "sha256") == 0) {
        hash_ctx->algorithm = HASH_SHA256;
        CC_SHA256_Init(&hash_ctx->sha256);
    } else if (strcmp(algorithm, "sha512") == 0) {
        hash_ctx->algorithm = HASH_SHA512;
        CC_SHA512_Init(&hash_ctx->sha512);
    } else {
        free(hash_ctx);
        free(algorithm);
        JSStringRef error = JSStringCreateWithUTF8CString("Unsupported hash algorithm");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    free(algorithm);

    JSClassDefinition hash_class_def = kJSClassDefinitionEmpty;
    hash_class_def.finalize = hash_finalizer;
    JSClassRef hash_class = JSClassCreate(&hash_class_def);
    JSObjectRef hash_obj = JSObjectMake(ctx, hash_class, hash_ctx);
    JSClassRelease(hash_class);

    JSStringRef update_name = JSStringCreateWithUTF8CString("update");
    JSObjectRef update_func = JSObjectMakeFunctionWithCallback(ctx, update_name, js_hash_update);
    JSObjectSetProperty(ctx, hash_obj, update_name, update_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(update_name);

    JSStringRef digest_name = JSStringCreateWithUTF8CString("digest");
    JSObjectRef digest_func = JSObjectMakeFunctionWithCallback(ctx, digest_name, js_hash_digest);
    JSObjectSetProperty(ctx, hash_obj, digest_name, digest_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(digest_name);

    return hash_obj;
}

// HMAC finalizer
static void hmac_finalizer(JSObjectRef object) {
    HmacContext* ctx = JSObjectGetPrivate(object);
    if (ctx) {
        free(ctx);
    }
}

// hmac.update implementation
static JSValueRef js_hmac_update(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject, size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception) {
    HmacContext* hmac_ctx = JSObjectGetPrivate(thisObject);
    if (!hmac_ctx) {
        JSStringRef error = JSStringCreateWithUTF8CString("Invalid hmac object");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    if (hmac_ctx->finalized) {
        JSStringRef error = JSStringCreateWithUTF8CString("Cannot update finalized hmac");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    if (argumentCount < 1) {
        return thisObject;
    }

    JSStringRef data_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(data_str);
    char* data = malloc(max_size);
    JSStringGetUTF8CString(data_str, data, max_size);
    JSStringRelease(data_str);

    size_t data_len = strlen(data);
    CCHmacUpdate(&hmac_ctx->hmac_ctx, data, data_len);
    free(data);

    return thisObject;
}

// hmac.digest implementation
static JSValueRef js_hmac_digest(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject, size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception) {
    HmacContext* hmac_ctx = JSObjectGetPrivate(thisObject);
    if (!hmac_ctx) {
        JSStringRef error = JSStringCreateWithUTF8CString("Invalid hmac object");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    if (hmac_ctx->finalized) {
        JSStringRef error = JSStringCreateWithUTF8CString("HMAC already finalized");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    unsigned char digest[CC_SHA512_DIGEST_LENGTH];
    int digest_len;

    switch (hmac_ctx->algorithm) {
        case kCCHmacAlgMD5:
            digest_len = CC_MD5_DIGEST_LENGTH;
            break;
        case kCCHmacAlgSHA1:
            digest_len = CC_SHA1_DIGEST_LENGTH;
            break;
        case kCCHmacAlgSHA256:
            digest_len = CC_SHA256_DIGEST_LENGTH;
            break;
        case kCCHmacAlgSHA512:
            digest_len = CC_SHA512_DIGEST_LENGTH;
            break;
        default:
            digest_len = CC_SHA256_DIGEST_LENGTH;
    }

    CCHmacFinal(&hmac_ctx->hmac_ctx, digest);
    hmac_ctx->finalized = 1;

    // Default to hex encoding
    char* encoding = "hex";
    if (argumentCount > 0) {
        JSStringRef enc_str = JSValueToStringCopy(ctx, arguments[0], NULL);
        size_t max_size = JSStringGetMaximumUTF8CStringSize(enc_str);
        encoding = malloc(max_size);
        JSStringGetUTF8CString(enc_str, encoding, max_size);
        JSStringRelease(enc_str);
    }

    if (strcmp(encoding, "hex") == 0) {
        char* hex = malloc(digest_len * 2 + 1);
        for (int i = 0; i < digest_len; i++) {
            sprintf(hex + i * 2, "%02x", digest[i]);
        }
        hex[digest_len * 2] = '\0';

        JSStringRef result_str = JSStringCreateWithUTF8CString(hex);
        JSValueRef result = JSValueMakeString(ctx, result_str);
        JSStringRelease(result_str);
        free(hex);
        if (argumentCount > 0) free(encoding);
        return result;
    } else {
        // Return Buffer (Uint8Array)
        JSObjectRef array = JSObjectMakeTypedArray(ctx, kJSTypedArrayTypeUint8Array, digest_len, exception);
        if (*exception) {
            if (argumentCount > 0) free(encoding);
            return JSValueMakeUndefined(ctx);
        }

        unsigned char* array_buffer = JSObjectGetTypedArrayBytesPtr(ctx, array, exception);
        if (*exception) {
            if (argumentCount > 0) free(encoding);
            return JSValueMakeUndefined(ctx);
        }

        memcpy(array_buffer, digest, digest_len);
        if (argumentCount > 0) free(encoding);
        return array;
    }
}

// crypto.createHmac implementation
static JSValueRef js_crypto_create_hmac(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                         JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                         const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        JSStringRef error = JSStringCreateWithUTF8CString("createHmac requires algorithm and key arguments");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef algo_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(algo_str);
    char* algorithm = malloc(max_size);
    JSStringGetUTF8CString(algo_str, algorithm, max_size);
    JSStringRelease(algo_str);

    JSStringRef key_str = JSValueToStringCopy(ctx, arguments[1], exception);
    if (*exception) {
        free(algorithm);
        return JSValueMakeUndefined(ctx);
    }

    size_t key_max_size = JSStringGetMaximumUTF8CStringSize(key_str);
    char* key = malloc(key_max_size);
    JSStringGetUTF8CString(key_str, key, key_max_size);
    JSStringRelease(key_str);
    size_t key_len = strlen(key);

    HmacContext* hmac_ctx = malloc(sizeof(HmacContext));
    hmac_ctx->finalized = 0;

    if (strcmp(algorithm, "md5") == 0) {
        hmac_ctx->algorithm = kCCHmacAlgMD5;
    } else if (strcmp(algorithm, "sha1") == 0) {
        hmac_ctx->algorithm = kCCHmacAlgSHA1;
    } else if (strcmp(algorithm, "sha256") == 0) {
        hmac_ctx->algorithm = kCCHmacAlgSHA256;
    } else if (strcmp(algorithm, "sha512") == 0) {
        hmac_ctx->algorithm = kCCHmacAlgSHA512;
    } else {
        free(hmac_ctx);
        free(algorithm);
        free(key);
        JSStringRef error = JSStringCreateWithUTF8CString("Unsupported hmac algorithm");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    CCHmacInit(&hmac_ctx->hmac_ctx, hmac_ctx->algorithm, key, key_len);
    free(algorithm);
    free(key);

    JSClassDefinition hmac_class_def = kJSClassDefinitionEmpty;
    hmac_class_def.finalize = hmac_finalizer;
    JSClassRef hmac_class = JSClassCreate(&hmac_class_def);
    JSObjectRef hmac_obj = JSObjectMake(ctx, hmac_class, hmac_ctx);
    JSClassRelease(hmac_class);

    JSStringRef update_name = JSStringCreateWithUTF8CString("update");
    JSObjectRef update_func = JSObjectMakeFunctionWithCallback(ctx, update_name, js_hmac_update);
    JSObjectSetProperty(ctx, hmac_obj, update_name, update_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(update_name);

    JSStringRef digest_name = JSStringCreateWithUTF8CString("digest");
    JSObjectRef digest_func = JSObjectMakeFunctionWithCallback(ctx, digest_name, js_hmac_digest);
    JSObjectSetProperty(ctx, hmac_obj, digest_name, digest_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(digest_name);

    return hmac_obj;
}

// TCP Socket finalizer
static void tcp_socket_finalizer(JSObjectRef object) {
    TcpSocket* sock = JSObjectGetPrivate(object);
    if (sock) {
        if (sock->socket_fd >= 0) {
            close(sock->socket_fd);
        }
        if (sock->on_data) JSValueUnprotect(global_ctx, sock->on_data);
        if (sock->on_end) JSValueUnprotect(global_ctx, sock->on_end);
        if (sock->on_error) JSValueUnprotect(global_ctx, sock->on_error);
        if (sock->on_close) JSValueUnprotect(global_ctx, sock->on_close);
        if (sock->on_connect) JSValueUnprotect(global_ctx, sock->on_connect);

        // Remove from list
        TcpSocket** current = &tcp_socket_list;
        while (*current) {
            if (*current == sock) {
                *current = sock->next;
                break;
            }
            current = &(*current)->next;
        }

        free(sock);
    }
}

// TCP Socket property setter
static bool tcp_socket_set_property(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName,
                                     JSValueRef value, JSValueRef* exception __attribute__((unused))) {
    TcpSocket* sock = JSObjectGetPrivate(object);
    if (!sock) return false;

    char prop_name[32];
    JSStringGetUTF8CString(propertyName, prop_name, sizeof(prop_name));

    if (strcmp(prop_name, "ondata") == 0 && JSValueIsObject(ctx, value)) {
        if (sock->on_data) JSValueUnprotect(ctx, sock->on_data);
        sock->on_data = JSValueToObject(ctx, value, NULL);
        JSValueProtect(ctx, sock->on_data);
        return true;
    } else if (strcmp(prop_name, "onend") == 0 && JSValueIsObject(ctx, value)) {
        if (sock->on_end) JSValueUnprotect(ctx, sock->on_end);
        sock->on_end = JSValueToObject(ctx, value, NULL);
        JSValueProtect(ctx, sock->on_end);
        return true;
    } else if (strcmp(prop_name, "onerror") == 0 && JSValueIsObject(ctx, value)) {
        if (sock->on_error) JSValueUnprotect(ctx, sock->on_error);
        sock->on_error = JSValueToObject(ctx, value, NULL);
        JSValueProtect(ctx, sock->on_error);
        return true;
    } else if (strcmp(prop_name, "onclose") == 0 && JSValueIsObject(ctx, value)) {
        if (sock->on_close) JSValueUnprotect(ctx, sock->on_close);
        sock->on_close = JSValueToObject(ctx, value, NULL);
        JSValueProtect(ctx, sock->on_close);
        return true;
    } else if (strcmp(prop_name, "onconnect") == 0 && JSValueIsObject(ctx, value)) {
        if (sock->on_connect) JSValueUnprotect(ctx, sock->on_connect);
        sock->on_connect = JSValueToObject(ctx, value, NULL);
        JSValueProtect(ctx, sock->on_connect);
        return true;
    }

    return false;
}

// socket.write() implementation
static JSValueRef js_tcp_socket_write(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                       JSObjectRef thisObject, size_t argumentCount,
                                       const JSValueRef arguments[], JSValueRef* exception) {
    TcpSocket* sock = JSObjectGetPrivate(thisObject);
    if (!sock || sock->socket_fd < 0) {
        JSStringRef error = JSStringCreateWithUTF8CString("Socket is not connected");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    if (argumentCount < 1) return JSValueMakeUndefined(ctx);

    JSStringRef data_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(data_str);
    char* data = malloc(max_size);
    JSStringGetUTF8CString(data_str, data, max_size);
    JSStringRelease(data_str);

    ssize_t sent = send(sock->socket_fd, data, strlen(data), 0);
    free(data);

    if (sent < 0) {
        JSStringRef error = JSStringCreateWithUTF8CString("Failed to send data");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    return JSValueMakeUndefined(ctx);
}

// socket.end() implementation
static JSValueRef js_tcp_socket_end(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                     JSObjectRef thisObject, size_t argumentCount,
                                     const JSValueRef arguments[], JSValueRef* exception) {
    TcpSocket* sock = JSObjectGetPrivate(thisObject);
    if (!sock || sock->socket_fd < 0) return JSValueMakeUndefined(ctx);

    // Optionally send final data
    if (argumentCount > 0) {
        js_tcp_socket_write(ctx, function, thisObject, argumentCount, arguments, exception);
    }

    shutdown(sock->socket_fd, SHUT_WR);
    return JSValueMakeUndefined(ctx);
}

// socket.destroy() implementation
static JSValueRef js_tcp_socket_destroy(JSContextRef ctx __attribute__((unused)),
                                         JSObjectRef function __attribute__((unused)),
                                         JSObjectRef thisObject, size_t argumentCount __attribute__((unused)),
                                         const JSValueRef arguments[] __attribute__((unused)),
                                         JSValueRef* exception __attribute__((unused))) {
    TcpSocket* sock = JSObjectGetPrivate(thisObject);
    if (!sock) return JSValueMakeUndefined(ctx);

    if (sock->socket_fd >= 0) {
        close(sock->socket_fd);
        sock->socket_fd = -1;
    }

    return JSValueMakeUndefined(ctx);
}

// Helper to create socket object
static JSObjectRef create_tcp_socket_object(JSContextRef ctx, TcpSocket* sock) {
    JSClassDefinition sock_class_def = kJSClassDefinitionEmpty;
    sock_class_def.finalize = tcp_socket_finalizer;
    sock_class_def.setProperty = tcp_socket_set_property;
    JSClassRef sock_class = JSClassCreate(&sock_class_def);
    JSObjectRef sock_obj = JSObjectMake(ctx, sock_class, sock);
    JSClassRelease(sock_class);

    // Add methods
    JSStringRef write_name = JSStringCreateWithUTF8CString("write");
    JSObjectRef write_func = JSObjectMakeFunctionWithCallback(ctx, write_name, js_tcp_socket_write);
    JSObjectSetProperty(ctx, sock_obj, write_name, write_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(write_name);

    JSStringRef end_name = JSStringCreateWithUTF8CString("end");
    JSObjectRef end_func = JSObjectMakeFunctionWithCallback(ctx, end_name, js_tcp_socket_end);
    JSObjectSetProperty(ctx, sock_obj, end_name, end_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(end_name);

    JSStringRef destroy_name = JSStringCreateWithUTF8CString("destroy");
    JSObjectRef destroy_func = JSObjectMakeFunctionWithCallback(ctx, destroy_name, js_tcp_socket_destroy);
    JSObjectSetProperty(ctx, sock_obj, destroy_name, destroy_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(destroy_name);

    return sock_obj;
}

// net.createConnection() implementation
static JSValueRef js_net_create_connection(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                            JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                            const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        JSStringRef error = JSStringCreateWithUTF8CString("createConnection requires port or options");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    int port = 0;
    char host[256] = "127.0.0.1";

    // Parse arguments (port or {port, host})
    if (JSValueIsObject(ctx, arguments[0])) {
        JSObjectRef options = JSValueToObject(ctx, arguments[0], NULL);

        JSStringRef port_name = JSStringCreateWithUTF8CString("port");
        JSValueRef port_val = JSObjectGetProperty(ctx, options, port_name, NULL);
        JSStringRelease(port_name);
        if (!JSValueIsUndefined(ctx, port_val)) {
            port = (int)JSValueToNumber(ctx, port_val, NULL);
        }

        JSStringRef host_name = JSStringCreateWithUTF8CString("host");
        JSValueRef host_val = JSObjectGetProperty(ctx, options, host_name, NULL);
        JSStringRelease(host_name);
        if (!JSValueIsUndefined(ctx, host_val)) {
            JSStringRef host_str = JSValueToStringCopy(ctx, host_val, NULL);
            JSStringGetUTF8CString(host_str, host, sizeof(host));
            JSStringRelease(host_str);
        }
    } else {
        port = (int)JSValueToNumber(ctx, arguments[0], NULL);
        if (argumentCount > 1) {
            JSStringRef host_str = JSValueToStringCopy(ctx, arguments[1], NULL);
            JSStringGetUTF8CString(host_str, host, sizeof(host));
            JSStringRelease(host_str);
        }
    }

    // Create socket
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        JSStringRef error = JSStringCreateWithUTF8CString("Failed to create socket");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Set non-blocking
    fcntl(sock_fd, F_SETFL, O_NONBLOCK);

    // Connect
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &server_addr.sin_addr);

    // Handle localhost
    if (server_addr.sin_addr.s_addr == 0 && strcmp(host, "localhost") == 0) {
        inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    }

    int result = connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Create TcpSocket object
    TcpSocket* sock = malloc(sizeof(TcpSocket));
    sock->socket_fd = sock_fd;
    sock->is_server = 0;
    sock->connecting = (result == -1 && errno == EINPROGRESS);
    sock->on_data = NULL;
    sock->on_end = NULL;
    sock->on_error = NULL;
    sock->on_close = NULL;
    sock->on_connect = NULL;
    sock->read_buffer_len = 0;
    sock->next = tcp_socket_list;
    tcp_socket_list = sock;

    JSObjectRef sock_obj = create_tcp_socket_object(ctx, sock);

    // Initialize kqueue if not already done
    if (kq == -1) {
        kq = kqueue();
    }

    // Add to kqueue
    struct kevent ev;
    EV_SET(&ev, sock_fd, EVFILT_READ, EV_ADD, 0, 0, sock_obj);
    kevent(kq, &ev, 1, NULL, 0, NULL);
    JSValueProtect(global_ctx, sock_obj);

    // Always watch for write to detect connection (works for both async and immediate)
    // Mark as connecting so we trigger onconnect when writable
    sock->connecting = 1;
    struct kevent wev;
    EV_SET(&wev, sock_fd, EVFILT_WRITE, EV_ADD, 0, 0, sock_obj);
    kevent(kq, &wev, 1, NULL, 0, NULL);

    return sock_obj;
}

// net.createServer() implementation
static JSValueRef js_net_create_server(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                        JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                        const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    // Create server object
    JSObjectRef server_obj = JSObjectMake(ctx, NULL, NULL);

    // Store connection handler if provided
    if (argumentCount > 0 && JSValueIsObject(ctx, arguments[0])) {
        JSStringRef on_conn = JSStringCreateWithUTF8CString("_onconnection");
        JSObjectSetProperty(ctx, server_obj, on_conn, arguments[0], kJSPropertyAttributeNone, NULL);
        JSStringRelease(on_conn);
    }

    return server_obj;
}

// server.listen() implementation
static JSValueRef js_tcp_server_listen(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                        JSObjectRef thisObject, size_t argumentCount,
                                        const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        JSStringRef error = JSStringCreateWithUTF8CString("listen requires port");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    int port = (int)JSValueToNumber(ctx, arguments[0], NULL);

    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        JSStringRef error = JSStringCreateWithUTF8CString("Failed to create socket");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Set socket options
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(server_fd);
        char error_msg[128];
        snprintf(error_msg, sizeof(error_msg), "Failed to bind to port %d", port);
        JSStringRef error = JSStringCreateWithUTF8CString(error_msg);
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Listen
    if (listen(server_fd, 128) < 0) {
        close(server_fd);
        JSStringRef error = JSStringCreateWithUTF8CString("Failed to listen");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Create TcpServer structure
    TcpServer* server = malloc(sizeof(TcpServer));
    server->socket_fd = server_fd;
    server->port = port;

    // Get connection handler
    JSStringRef on_conn_name = JSStringCreateWithUTF8CString("_onconnection");
    JSValueRef on_conn = JSObjectGetProperty(ctx, thisObject, on_conn_name, NULL);
    JSStringRelease(on_conn_name);
    server->on_connection = JSValueIsObject(ctx, on_conn) ? JSValueToObject(ctx, on_conn, NULL) : NULL;
    if (server->on_connection) JSValueProtect(global_ctx, server->on_connection);

    server->on_listening = NULL;
    server->on_error = NULL;
    server->next = tcp_server_list;
    tcp_server_list = server;

    // Store server pointer in JS object
    JSStringRef server_ptr_name = JSStringCreateWithUTF8CString("_serverptr");
    JSObjectSetProperty(ctx, thisObject, server_ptr_name, JSValueMakeNumber(ctx, (double)(uintptr_t)server),
                        kJSPropertyAttributeNone, NULL);
    JSStringRelease(server_ptr_name);

    // Initialize kqueue if not already done
    if (kq == -1) {
        kq = kqueue();
    }

    // Add to kqueue
    struct kevent ev;
    EV_SET(&ev, server_fd, EVFILT_READ, EV_ADD, 0, 0, thisObject);
    kevent(kq, &ev, 1, NULL, 0, NULL);
    JSValueProtect(global_ctx, thisObject);

    // Call listening callback if provided
    if (argumentCount > 1 && JSValueIsObject(ctx, arguments[1])) {
        JSObjectRef callback = JSValueToObject(ctx, arguments[1], NULL);
        JSObjectCallAsFunction(ctx, callback, NULL, 0, NULL, NULL);
    }

    return JSValueMakeUndefined(ctx);
}

// Create net module object

// Modify createServer to add listen method to returned object
static JSValueRef js_net_create_server_with_listen(JSContextRef ctx, JSObjectRef function,
                                                     JSObjectRef thisObject, size_t argumentCount,
                                                     const JSValueRef arguments[], JSValueRef* exception) {
    JSValueRef server_obj = js_net_create_server(ctx, function, thisObject, argumentCount, arguments, exception);

    if (JSValueIsObject(ctx, server_obj)) {
        JSObjectRef server = JSValueToObject(ctx, server_obj, NULL);

        // Add listen method
        JSStringRef listen_name = JSStringCreateWithUTF8CString("listen");
        JSObjectRef listen_func = JSObjectMakeFunctionWithCallback(ctx, listen_name, js_tcp_server_listen);
        JSObjectSetProperty(ctx, server, listen_name, listen_func, kJSPropertyAttributeNone, NULL);
        JSStringRelease(listen_name);
    }

    return server_obj;
}

// Update create_net_module to use the new version
static JSObjectRef create_net_module_final(JSContextRef ctx) {
    JSObjectRef net = JSObjectMake(ctx, NULL, NULL);

    JSStringRef createConnection_name = JSStringCreateWithUTF8CString("createConnection");
    JSObjectRef createConnection_func = JSObjectMakeFunctionWithCallback(ctx, createConnection_name, js_net_create_connection);
    JSObjectSetProperty(ctx, net, createConnection_name, createConnection_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(createConnection_name);

    JSStringRef connect_name = JSStringCreateWithUTF8CString("connect");
    JSObjectSetProperty(ctx, net, connect_name, createConnection_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(connect_name);

    JSStringRef createServer_name = JSStringCreateWithUTF8CString("createServer");
    JSObjectRef createServer_func = JSObjectMakeFunctionWithCallback(ctx, createServer_name, js_net_create_server_with_listen);
    JSObjectSetProperty(ctx, net, createServer_name, createServer_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(createServer_name);

    return net;
}

// url.parse() implementation
static JSValueRef js_url_parse(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeNull(ctx);
    }

    JSStringRef url_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeNull(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(url_str);
    char* url = malloc(max_size);
    JSStringGetUTF8CString(url_str, url, max_size);
    JSStringRelease(url_str);

    // Parse URL components
    JSObjectRef parsed = JSObjectMake(ctx, NULL, NULL);

    char* current = url;
    char protocol[64] = {0};
    char host[256] = {0};
    char hostname[256] = {0};
    char port[16] = {0};
    char pathname[1024] = "/";
    char search[1024] = {0};
    char hash[256] = {0};

    // Parse protocol
    char* protocol_end = strstr(current, "://");
    if (protocol_end) {
        size_t protocol_len = protocol_end - current;
        strncpy(protocol, current, protocol_len);
        protocol[protocol_len] = '\0';
        strcat(protocol, ":");
        current = protocol_end + 3;
    }

    // Parse host (hostname + port)
    char* path_start = strchr(current, '/');
    char* query_start = strchr(current, '?');
    char* hash_start = strchr(current, '#');

    char* host_end = path_start;
    if (!host_end || (query_start && query_start < host_end)) host_end = query_start;
    if (!host_end || (hash_start && hash_start < host_end)) host_end = hash_start;
    if (!host_end) host_end = current + strlen(current);

    size_t host_len = host_end - current;
    strncpy(host, current, host_len);
    host[host_len] = '\0';

    // Parse hostname and port from host
    char* port_sep = strchr(host, ':');
    if (port_sep) {
        size_t hostname_len = port_sep - host;
        strncpy(hostname, host, hostname_len);
        hostname[hostname_len] = '\0';
        strcpy(port, port_sep + 1);
    } else {
        strcpy(hostname, host);
    }

    current = host_end;

    // Parse pathname
    if (*current == '/') {
        char* query_or_hash = strchr(current, '?');
        if (!query_or_hash) query_or_hash = strchr(current, '#');
        if (query_or_hash) {
            size_t path_len = query_or_hash - current;
            strncpy(pathname, current, path_len);
            pathname[path_len] = '\0';
            current = query_or_hash;
        } else {
            strcpy(pathname, current);
            current += strlen(current);
        }
    }

    // Parse search (query)
    if (*current == '?') {
        char* hash_pos = strchr(current, '#');
        if (hash_pos) {
            size_t search_len = hash_pos - current;
            strncpy(search, current, search_len);
            search[search_len] = '\0';
            current = hash_pos;
        } else {
            strcpy(search, current);
            current += strlen(current);
        }
    }

    // Parse hash
    if (*current == '#') {
        strcpy(hash, current);
    }

    // Set properties
    if (protocol[0]) {
        JSStringRef protocol_name = JSStringCreateWithUTF8CString("protocol");
        JSStringRef protocol_val = JSStringCreateWithUTF8CString(protocol);
        JSObjectSetProperty(ctx, parsed, protocol_name, JSValueMakeString(ctx, protocol_val), kJSPropertyAttributeNone, NULL);
        JSStringRelease(protocol_name);
        JSStringRelease(protocol_val);
    }

    if (host[0]) {
        JSStringRef host_name = JSStringCreateWithUTF8CString("host");
        JSStringRef host_val = JSStringCreateWithUTF8CString(host);
        JSObjectSetProperty(ctx, parsed, host_name, JSValueMakeString(ctx, host_val), kJSPropertyAttributeNone, NULL);
        JSStringRelease(host_name);
        JSStringRelease(host_val);
    }

    if (hostname[0]) {
        JSStringRef hostname_name = JSStringCreateWithUTF8CString("hostname");
        JSStringRef hostname_val = JSStringCreateWithUTF8CString(hostname);
        JSObjectSetProperty(ctx, parsed, hostname_name, JSValueMakeString(ctx, hostname_val), kJSPropertyAttributeNone, NULL);
        JSStringRelease(hostname_name);
        JSStringRelease(hostname_val);
    }

    if (port[0]) {
        JSStringRef port_name = JSStringCreateWithUTF8CString("port");
        JSStringRef port_val = JSStringCreateWithUTF8CString(port);
        JSObjectSetProperty(ctx, parsed, port_name, JSValueMakeString(ctx, port_val), kJSPropertyAttributeNone, NULL);
        JSStringRelease(port_name);
        JSStringRelease(port_val);
    }

    JSStringRef pathname_name = JSStringCreateWithUTF8CString("pathname");
    JSStringRef pathname_val = JSStringCreateWithUTF8CString(pathname);
    JSObjectSetProperty(ctx, parsed, pathname_name, JSValueMakeString(ctx, pathname_val), kJSPropertyAttributeNone, NULL);
    JSStringRelease(pathname_name);
    JSStringRelease(pathname_val);

    if (search[0]) {
        JSStringRef search_name = JSStringCreateWithUTF8CString("search");
        JSStringRef search_val = JSStringCreateWithUTF8CString(search);
        JSObjectSetProperty(ctx, parsed, search_name, JSValueMakeString(ctx, search_val), kJSPropertyAttributeNone, NULL);
        JSStringRelease(search_name);
        JSStringRelease(search_val);

        // Also add query (without '?')
        if (search[0] == '?') {
            JSStringRef query_name = JSStringCreateWithUTF8CString("query");
            JSStringRef query_val = JSStringCreateWithUTF8CString(search + 1);
            JSObjectSetProperty(ctx, parsed, query_name, JSValueMakeString(ctx, query_val), kJSPropertyAttributeNone, NULL);
            JSStringRelease(query_name);
            JSStringRelease(query_val);
        }
    }

    if (hash[0]) {
        JSStringRef hash_name = JSStringCreateWithUTF8CString("hash");
        JSStringRef hash_val = JSStringCreateWithUTF8CString(hash);
        JSObjectSetProperty(ctx, parsed, hash_name, JSValueMakeString(ctx, hash_val), kJSPropertyAttributeNone, NULL);
        JSStringRelease(hash_name);
        JSStringRelease(hash_val);
    }

    free(url);
    return parsed;
}

// url.format() implementation
static JSValueRef js_url_format(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                 JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                 const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount < 1 || !JSValueIsObject(ctx, arguments[0])) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(""));
    }

    JSObjectRef urlObj = JSValueToObject(ctx, arguments[0], NULL);
    char result[2048] = {0};
    char temp[512];

    // Protocol
    JSStringRef protocol_name = JSStringCreateWithUTF8CString("protocol");
    JSValueRef protocol_val = JSObjectGetProperty(ctx, urlObj, protocol_name, NULL);
    JSStringRelease(protocol_name);
    if (!JSValueIsUndefined(ctx, protocol_val)) {
        JSStringRef protocol_str = JSValueToStringCopy(ctx, protocol_val, NULL);
        JSStringGetUTF8CString(protocol_str, temp, sizeof(temp));
        JSStringRelease(protocol_str);
        strcat(result, temp);
        if (!strstr(temp, "://")) strcat(result, "//");
    }

    // Host (or hostname + port)
    JSStringRef host_name = JSStringCreateWithUTF8CString("host");
    JSValueRef host_val = JSObjectGetProperty(ctx, urlObj, host_name, NULL);
    JSStringRelease(host_name);
    if (!JSValueIsUndefined(ctx, host_val)) {
        JSStringRef host_str = JSValueToStringCopy(ctx, host_val, NULL);
        JSStringGetUTF8CString(host_str, temp, sizeof(temp));
        JSStringRelease(host_str);
        strcat(result, temp);
    } else {
        // Try hostname + port
        JSStringRef hostname_name = JSStringCreateWithUTF8CString("hostname");
        JSValueRef hostname_val = JSObjectGetProperty(ctx, urlObj, hostname_name, NULL);
        JSStringRelease(hostname_name);
        if (!JSValueIsUndefined(ctx, hostname_val)) {
            JSStringRef hostname_str = JSValueToStringCopy(ctx, hostname_val, NULL);
            JSStringGetUTF8CString(hostname_str, temp, sizeof(temp));
            JSStringRelease(hostname_str);
            strcat(result, temp);

            JSStringRef port_name = JSStringCreateWithUTF8CString("port");
            JSValueRef port_val = JSObjectGetProperty(ctx, urlObj, port_name, NULL);
            JSStringRelease(port_name);
            if (!JSValueIsUndefined(ctx, port_val)) {
                JSStringRef port_str = JSValueToStringCopy(ctx, port_val, NULL);
                JSStringGetUTF8CString(port_str, temp, sizeof(temp));
                JSStringRelease(port_str);
                strcat(result, ":");
                strcat(result, temp);
            }
        }
    }

    // Pathname
    JSStringRef pathname_name = JSStringCreateWithUTF8CString("pathname");
    JSValueRef pathname_val = JSObjectGetProperty(ctx, urlObj, pathname_name, NULL);
    JSStringRelease(pathname_name);
    if (!JSValueIsUndefined(ctx, pathname_val)) {
        JSStringRef pathname_str = JSValueToStringCopy(ctx, pathname_val, NULL);
        JSStringGetUTF8CString(pathname_str, temp, sizeof(temp));
        JSStringRelease(pathname_str);
        strcat(result, temp);
    }

    // Search
    JSStringRef search_name = JSStringCreateWithUTF8CString("search");
    JSValueRef search_val = JSObjectGetProperty(ctx, urlObj, search_name, NULL);
    JSStringRelease(search_name);
    if (!JSValueIsUndefined(ctx, search_val)) {
        JSStringRef search_str = JSValueToStringCopy(ctx, search_val, NULL);
        JSStringGetUTF8CString(search_str, temp, sizeof(temp));
        JSStringRelease(search_str);
        strcat(result, temp);
    }

    // Hash
    JSStringRef hash_name = JSStringCreateWithUTF8CString("hash");
    JSValueRef hash_val = JSObjectGetProperty(ctx, urlObj, hash_name, NULL);
    JSStringRelease(hash_name);
    if (!JSValueIsUndefined(ctx, hash_val)) {
        JSStringRef hash_str = JSValueToStringCopy(ctx, hash_val, NULL);
        JSStringGetUTF8CString(hash_str, temp, sizeof(temp));
        JSStringRelease(hash_str);
        strcat(result, temp);
    }

    JSStringRef result_str = JSStringCreateWithUTF8CString(result);
    JSValueRef result_val = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    return result_val;
}

// Create url module object
static JSObjectRef create_url_module(JSContextRef ctx) {
    JSObjectRef url = JSObjectMake(ctx, NULL, NULL);

    JSStringRef parse_name = JSStringCreateWithUTF8CString("parse");
    JSObjectRef parse_func = JSObjectMakeFunctionWithCallback(ctx, parse_name, js_url_parse);
    JSObjectSetProperty(ctx, url, parse_name, parse_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(parse_name);

    JSStringRef format_name = JSStringCreateWithUTF8CString("format");
    JSObjectRef format_func = JSObjectMakeFunctionWithCallback(ctx, format_name, js_url_format);
    JSObjectSetProperty(ctx, url, format_name, format_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(format_name);

    return url;
}

// util.format() implementation - simple printf-like formatting
static JSValueRef js_util_format(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount == 0) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(""));
    }

    char result[4096] = {0};

    // Get format string
    JSStringRef format_str = JSValueToStringCopy(ctx, arguments[0], NULL);
    char format[2048];
    JSStringGetUTF8CString(format_str, format, sizeof(format));
    JSStringRelease(format_str);

    // Simple %s, %d, %j replacement
    char* out = result;
    char* fmt = format;
    size_t arg_index = 1;

    while (*fmt && out < result + sizeof(result) - 100) {
        if (*fmt == '%' && *(fmt + 1)) {
            char spec = *(fmt + 1);
            if (spec == 's' || spec == 'd' || spec == 'j') {
                if (arg_index < argumentCount) {
                    if (spec == 's' || spec == 'j') {
                        JSStringRef arg_str = JSValueToStringCopy(ctx, arguments[arg_index], NULL);
                        char temp[512];
                        JSStringGetUTF8CString(arg_str, temp, sizeof(temp));
                        JSStringRelease(arg_str);
                        out += sprintf(out, "%s", temp);
                    } else if (spec == 'd') {
                        double num = JSValueToNumber(ctx, arguments[arg_index], NULL);
                        out += sprintf(out, "%.0f", num);
                    }
                    arg_index++;
                } else {
                    *out++ = '%';
                    *out++ = spec;
                }
                fmt += 2;
                continue;
            }
        }
        *out++ = *fmt++;
    }
    *out = '\0';

    // Append remaining arguments
    while (arg_index < argumentCount) {
        if (out < result + sizeof(result) - 100) {
            *out++ = ' ';
            JSStringRef arg_str = JSValueToStringCopy(ctx, arguments[arg_index], NULL);
            char temp[512];
            JSStringGetUTF8CString(arg_str, temp, sizeof(temp));
            JSStringRelease(arg_str);
            out += sprintf(out, "%s", temp);
        }
        arg_index++;
    }

    JSStringRef result_str = JSStringCreateWithUTF8CString(result);
    JSValueRef result_val = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    return result_val;
}

// util.inspect() implementation - basic object inspection
static JSValueRef js_util_inspect(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                   JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                   const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount == 0) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("undefined"));
    }

    // Use JSC's built-in string conversion
    JSStringRef str = JSValueToStringCopy(ctx, arguments[0], NULL);
    JSValueRef result = JSValueMakeString(ctx, str);
    JSStringRelease(str);
    return result;
}

// Create util module object
static JSObjectRef create_util_module(JSContextRef ctx) {
    JSObjectRef util = JSObjectMake(ctx, NULL, NULL);

    JSStringRef format_name = JSStringCreateWithUTF8CString("format");
    JSObjectRef format_func = JSObjectMakeFunctionWithCallback(ctx, format_name, js_util_format);
    JSObjectSetProperty(ctx, util, format_name, format_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(format_name);

    JSStringRef inspect_name = JSStringCreateWithUTF8CString("inspect");
    JSObjectRef inspect_func = JSObjectMakeFunctionWithCallback(ctx, inspect_name, js_util_inspect);
    JSObjectSetProperty(ctx, util, inspect_name, inspect_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(inspect_name);

    return util;
}

// os.platform() implementation
static JSValueRef js_os_platform(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount __attribute__((unused)),
                                  const JSValueRef arguments[] __attribute__((unused)),
                                  JSValueRef* exception __attribute__((unused))) {
    #ifdef __APPLE__
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("darwin"));
    #elif __linux__
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("linux"));
    #elif _WIN32
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("win32"));
    #else
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("unknown"));
    #endif
}

// os.arch() implementation
static JSValueRef js_os_arch(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                              JSObjectRef thisObject __attribute__((unused)), size_t argumentCount __attribute__((unused)),
                              const JSValueRef arguments[] __attribute__((unused)),
                              JSValueRef* exception __attribute__((unused))) {
    #if defined(__x86_64__) || defined(_M_X64)
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("x64"));
    #elif defined(__aarch64__) || defined(_M_ARM64)
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("arm64"));
    #elif defined(__i386__) || defined(_M_IX86)
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("ia32"));
    #elif defined(__arm__) || defined(_M_ARM)
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("arm"));
    #else
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("unknown"));
    #endif
}

// os.homedir() implementation
static JSValueRef js_os_homedir(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                 JSObjectRef thisObject __attribute__((unused)), size_t argumentCount __attribute__((unused)),
                                 const JSValueRef arguments[] __attribute__((unused)),
                                 JSValueRef* exception __attribute__((unused))) {
    const char* home = getenv("HOME");
    if (!home) home = "/";
    return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(home));
}

// os.tmpdir() implementation
static JSValueRef js_os_tmpdir(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                JSObjectRef thisObject __attribute__((unused)), size_t argumentCount __attribute__((unused)),
                                const JSValueRef arguments[] __attribute__((unused)),
                                JSValueRef* exception __attribute__((unused))) {
    const char* tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = getenv("TMP");
    if (!tmpdir) tmpdir = getenv("TEMP");
    if (!tmpdir) tmpdir = "/tmp";
    return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(tmpdir));
}

// os.hostname() implementation
static JSValueRef js_os_hostname(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount __attribute__((unused)),
                                  const JSValueRef arguments[] __attribute__((unused)),
                                  JSValueRef* exception __attribute__((unused))) {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(hostname));
    }
    return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("localhost"));
}

// os.type() implementation
static JSValueRef js_os_type(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                              JSObjectRef thisObject __attribute__((unused)), size_t argumentCount __attribute__((unused)),
                              const JSValueRef arguments[] __attribute__((unused)),
                              JSValueRef* exception __attribute__((unused))) {
    #ifdef __APPLE__
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("Darwin"));
    #elif __linux__
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("Linux"));
    #elif _WIN32
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("Windows_NT"));
    #else
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString("Unknown"));
    #endif
}

// os.cpus() implementation - returns array of CPU info
static JSValueRef js_os_cpus(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                              JSObjectRef thisObject __attribute__((unused)), size_t argumentCount __attribute__((unused)),
                              const JSValueRef arguments[] __attribute__((unused)),
                              JSValueRef* exception __attribute__((unused))) {
    // Simple implementation - return array with basic info
    int ncpu = 1;
    #ifdef __APPLE__
        size_t len = sizeof(ncpu);
        sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0);
    #endif

    JSValueRef* cpus = malloc(sizeof(JSValueRef) * ncpu);
    for (int i = 0; i < ncpu; i++) {
        JSObjectRef cpu = JSObjectMake(ctx, NULL, NULL);

        JSStringRef model_name = JSStringCreateWithUTF8CString("model");
        JSStringRef model_val = JSStringCreateWithUTF8CString("CPU");
        JSObjectSetProperty(ctx, cpu, model_name, JSValueMakeString(ctx, model_val), kJSPropertyAttributeNone, NULL);
        JSStringRelease(model_name);
        JSStringRelease(model_val);

        JSStringRef speed_name = JSStringCreateWithUTF8CString("speed");
        JSObjectSetProperty(ctx, cpu, speed_name, JSValueMakeNumber(ctx, 0), kJSPropertyAttributeNone, NULL);
        JSStringRelease(speed_name);

        cpus[i] = cpu;
    }

    JSObjectRef array = JSObjectMakeArray(ctx, ncpu, cpus, NULL);
    free(cpus);
    return array;
}

// Create os module object
static JSObjectRef create_os_module(JSContextRef ctx) {
    JSObjectRef os = JSObjectMake(ctx, NULL, NULL);

    JSStringRef platform_name = JSStringCreateWithUTF8CString("platform");
    JSObjectRef platform_func = JSObjectMakeFunctionWithCallback(ctx, platform_name, js_os_platform);
    JSObjectSetProperty(ctx, os, platform_name, platform_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(platform_name);

    JSStringRef arch_name = JSStringCreateWithUTF8CString("arch");
    JSObjectRef arch_func = JSObjectMakeFunctionWithCallback(ctx, arch_name, js_os_arch);
    JSObjectSetProperty(ctx, os, arch_name, arch_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(arch_name);

    JSStringRef homedir_name = JSStringCreateWithUTF8CString("homedir");
    JSObjectRef homedir_func = JSObjectMakeFunctionWithCallback(ctx, homedir_name, js_os_homedir);
    JSObjectSetProperty(ctx, os, homedir_name, homedir_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(homedir_name);

    JSStringRef tmpdir_name = JSStringCreateWithUTF8CString("tmpdir");
    JSObjectRef tmpdir_func = JSObjectMakeFunctionWithCallback(ctx, tmpdir_name, js_os_tmpdir);
    JSObjectSetProperty(ctx, os, tmpdir_name, tmpdir_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(tmpdir_name);

    JSStringRef hostname_name = JSStringCreateWithUTF8CString("hostname");
    JSObjectRef hostname_func = JSObjectMakeFunctionWithCallback(ctx, hostname_name, js_os_hostname);
    JSObjectSetProperty(ctx, os, hostname_name, hostname_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(hostname_name);

    JSStringRef type_name = JSStringCreateWithUTF8CString("type");
    JSObjectRef type_func = JSObjectMakeFunctionWithCallback(ctx, type_name, js_os_type);
    JSObjectSetProperty(ctx, os, type_name, type_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(type_name);

    JSStringRef cpus_name = JSStringCreateWithUTF8CString("cpus");
    JSObjectRef cpus_func = JSObjectMakeFunctionWithCallback(ctx, cpus_name, js_os_cpus);
    JSObjectSetProperty(ctx, os, cpus_name, cpus_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(cpus_name);

    // Add EOL constant
    JSStringRef eol_name = JSStringCreateWithUTF8CString("EOL");
    #ifdef _WIN32
        JSStringRef eol_val = JSStringCreateWithUTF8CString("\r\n");
    #else
        JSStringRef eol_val = JSStringCreateWithUTF8CString("\n");
    #endif
    JSObjectSetProperty(ctx, os, eol_name, JSValueMakeString(ctx, eol_val), kJSPropertyAttributeNone, NULL);
    JSStringRelease(eol_name);
    JSStringRelease(eol_val);

    return os;
}

//

// Create crypto module object
static JSObjectRef create_crypto_module(JSContextRef ctx) {
    JSObjectRef crypto = JSObjectMake(ctx, NULL, NULL);

    JSStringRef randomBytes_name = JSStringCreateWithUTF8CString("randomBytes");
    JSObjectRef randomBytes_func = JSObjectMakeFunctionWithCallback(ctx, randomBytes_name, js_crypto_random_bytes);
    JSObjectSetProperty(ctx, crypto, randomBytes_name, randomBytes_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(randomBytes_name);

    JSStringRef createHash_name = JSStringCreateWithUTF8CString("createHash");
    JSObjectRef createHash_func = JSObjectMakeFunctionWithCallback(ctx, createHash_name, js_crypto_create_hash);
    JSObjectSetProperty(ctx, crypto, createHash_name, createHash_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(createHash_name);

    JSStringRef createHmac_name = JSStringCreateWithUTF8CString("createHmac");
    JSObjectRef createHmac_func = JSObjectMakeFunctionWithCallback(ctx, createHmac_name, js_crypto_create_hmac);
    JSObjectSetProperty(ctx, crypto, createHmac_name, createHmac_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(createHmac_name);

    return crypto;
}

// EventEmitter implementation in JavaScript
static const char* eventemitter_source =
"class EventEmitter {\n"
"  constructor() {\n"
"    this._events = {};\n"
"  }\n"
"\n"
"  on(event, listener) {\n"
"    if (!this._events[event]) {\n"
"      this._events[event] = [];\n"
"    }\n"
"    this._events[event].push(listener);\n"
"    return this;\n"
"  }\n"
"\n"
"  once(event, listener) {\n"
"    const wrapper = (...args) => {\n"
"      this.removeListener(event, wrapper);\n"
"      listener.apply(this, args);\n"
"    };\n"
"    wrapper.listener = listener;\n"
"    return this.on(event, wrapper);\n"
"  }\n"
"\n"
"  emit(event, ...args) {\n"
"    const listeners = this._events[event];\n"
"    if (!listeners || listeners.length === 0) {\n"
"      return this;\n"
"    }\n"
"    for (const listener of listeners.slice()) {\n"
"      listener.apply(this, args);\n"
"    }\n"
"    return this;\n"
"  }\n"
"\n"
"  removeListener(event, listener) {\n"
"    const listeners = this._events[event];\n"
"    if (!listeners) return this;\n"
"    const index = listeners.findIndex(\n"
"      l => l === listener || l.listener === listener\n"
"    );\n"
"    if (index !== -1) {\n"
"      listeners.splice(index, 1);\n"
"    }\n"
"    if (listeners.length === 0) {\n"
"      delete this._events[event];\n"
"    }\n"
"    return this;\n"
"  }\n"
"\n"
"  off(event, listener) {\n"
"    return this.removeListener(event, listener);\n"
"  }\n"
"\n"
"  removeAllListeners(event) {\n"
"    if (event) {\n"
"      delete this._events[event];\n"
"    } else {\n"
"      this._events = {};\n"
"    }\n"
"    return this;\n"
"  }\n"
"\n"
"  listeners(event) {\n"
"    return this._events[event] ? this._events[event].slice() : [];\n"
"  }\n"
"\n"
"  listenerCount(event) {\n"
"    return this._events[event] ? this._events[event].length : 0;\n"
"  }\n"
"\n"
"  eventNames() {\n"
"    return Object.keys(this._events);\n"
"  }\n"
"}\n"
"\n"
"EventEmitter;\n";

// Create events module object (EventEmitter)
static JSObjectRef create_events_module(JSContextRef ctx) {
    // Evaluate EventEmitter class
    JSStringRef source = JSStringCreateWithUTF8CString(eventemitter_source);
    JSValueRef exception = NULL;
    JSValueRef result = JSEvaluateScript(ctx, source, NULL, NULL, 0, &exception);
    JSStringRelease(source);

    if (exception) {
        return JSObjectMake(ctx, NULL, NULL);
    }

    // Create module object with EventEmitter as default export
    JSObjectRef events = JSObjectMake(ctx, NULL, NULL);
    JSStringRef ee_name = JSStringCreateWithUTF8CString("EventEmitter");
    JSObjectSetProperty(ctx, events, ee_name, result, kJSPropertyAttributeNone, NULL);
    JSStringRelease(ee_name);

    return events;
}

// Create http module object
static JSObjectRef create_http_module(JSContextRef ctx) {
    JSObjectRef http = JSObjectMake(ctx, NULL, NULL);

    // http.createServer() - wraps serve()
    const char* createServer_code =
        "(function() {"
        "  return function(handler) {"
        "    return {"
        "      listen: function(port, callback) {"
        "        serve(port, handler);"
        "        if (callback) callback();"
        "      }"
        "    };"
        "  };"
        "})()";

    JSStringRef code_str = JSStringCreateWithUTF8CString(createServer_code);
    JSValueRef createServer_func = JSEvaluateScript(ctx, code_str, NULL, NULL, 1, NULL);
    JSStringRelease(code_str);

    JSStringRef createServer_name = JSStringCreateWithUTF8CString("createServer");
    JSObjectSetProperty(ctx, http, createServer_name, createServer_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(createServer_name);

    return http;
}

// Create https module object
static JSObjectRef create_https_module(JSContextRef ctx) {
    JSObjectRef https = JSObjectMake(ctx, NULL, NULL);

    // https.get() - wraps fetch()
    const char* get_code =
        "(function() {"
        "  return function(url, callback) {"
        "    fetch(url).then(res => {"
        "      res.on = function(event, cb) {"
        "        if (event === 'data') res.text().then(cb);"
        "      };"
        "      if (callback) callback(res);"
        "    });"
        "  };"
        "})()";

    JSStringRef code_str = JSStringCreateWithUTF8CString(get_code);
    JSValueRef get_func = JSEvaluateScript(ctx, code_str, NULL, NULL, 1, NULL);
    JSStringRelease(code_str);

    JSStringRef get_name = JSStringCreateWithUTF8CString("get");
    JSObjectSetProperty(ctx, https, get_name, get_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(get_name);

    // https.request() - similar to get()
    JSStringRef request_name = JSStringCreateWithUTF8CString("request");
    JSObjectSetProperty(ctx, https, request_name, get_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(request_name);

    // https.createServer() - wraps serve_https()
    const char* createServer_code =
        "(function() {"
        "  return function(options, handler) {"
        "    return {"
        "      listen: function(port, callback) {"
        "        serve_https(port, options, handler);"
        "        if (callback) callback();"
        "      }"
        "    };"
        "  };"
        "})()";

    JSStringRef createServer_str = JSStringCreateWithUTF8CString(createServer_code);
    JSValueRef createServer_func = JSEvaluateScript(ctx, createServer_str, NULL, NULL, 1, NULL);
    JSStringRelease(createServer_str);

    JSStringRef createServer_name = JSStringCreateWithUTF8CString("createServer");
    JSObjectSetProperty(ctx, https, createServer_name, createServer_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(createServer_name);

    return https;
}

// dns.lookup() implementation
static JSValueRef js_dns_lookup(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        JSStringRef error = JSStringCreateWithUTF8CString("lookup requires hostname and callback");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Get hostname
    JSStringRef hostname_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(hostname_str);
    char* hostname = malloc(max_size);
    JSStringGetUTF8CString(hostname_str, hostname, max_size);
    JSStringRelease(hostname_str);

    // Get callback
    JSObjectRef callback = JSValueToObject(ctx, arguments[1], exception);
    if (*exception) {
        free(hostname);
        return JSValueMakeUndefined(ctx);
    }

    // Resolve hostname
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;  // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = NULL;
    int status = getaddrinfo(hostname, NULL, &hints, &result);

    if (status != 0) {
        // Call callback with error
        JSStringRef error_msg = JSStringCreateWithUTF8CString(gai_strerror(status));
        JSValueRef error_val = JSValueMakeString(ctx, error_msg);
        JSStringRelease(error_msg);

        JSValueRef args[] = {error_val, JSValueMakeNull(ctx)};
        JSObjectCallAsFunction(ctx, callback, NULL, 2, args, NULL);

        free(hostname);
        return JSValueMakeUndefined(ctx);
    }

    // Get first IP address
    char ip_str[INET6_ADDRSTRLEN];
    void* addr_ptr = NULL;

    if (result->ai_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)result->ai_addr;
        addr_ptr = &(ipv4->sin_addr);
    } else {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)result->ai_addr;
        addr_ptr = &(ipv6->sin6_addr);
    }

    inet_ntop(result->ai_family, addr_ptr, ip_str, sizeof(ip_str));
    int family = result->ai_family == AF_INET ? 4 : 6;

    freeaddrinfo(result);
    free(hostname);

    // Call callback(null, address, family)
    JSStringRef ip_js = JSStringCreateWithUTF8CString(ip_str);
    JSValueRef ip_val = JSValueMakeString(ctx, ip_js);
    JSStringRelease(ip_js);

    JSValueRef args[] = {JSValueMakeNull(ctx), ip_val, JSValueMakeNumber(ctx, family)};
    JSObjectCallAsFunction(ctx, callback, NULL, 3, args, NULL);

    return JSValueMakeUndefined(ctx);
}

// Create dns module object
static JSObjectRef create_dns_module(JSContextRef ctx) {
    JSObjectRef dns = JSObjectMake(ctx, NULL, NULL);

    // dns.lookup()
    JSStringRef lookup_name = JSStringCreateWithUTF8CString("lookup");
    JSObjectRef lookup_func = JSObjectMakeFunctionWithCallback(ctx, lookup_name, js_dns_lookup);
    JSObjectSetProperty(ctx, dns, lookup_name, lookup_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(lookup_name);

    return dns;
}

// UDP Socket structure
typedef struct UdpSocket {
    int socket_fd;
    JSObjectRef on_message;
    JSObjectRef on_error;
    struct UdpSocket* next;
} UdpSocket;

static UdpSocket* udp_socket_list = NULL;

// dgram.createSocket() implementation
static JSValueRef js_dgram_create_socket(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                         JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                         const JSValueRef arguments[], JSValueRef* exception) {
    // Get socket type (udp4 or udp6)
    int family = AF_INET;  // Default to IPv4
    if (argumentCount > 0) {
        JSStringRef type_str = JSValueToStringCopy(ctx, arguments[0], exception);
        if (*exception) return JSValueMakeUndefined(ctx);

        char type[16];
        JSStringGetUTF8CString(type_str, type, sizeof(type));
        JSStringRelease(type_str);

        if (strcmp(type, "udp6") == 0) {
            family = AF_INET6;
        }
    }

    // Create UDP socket
    int sock_fd = socket(family, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        JSStringRef error = JSStringCreateWithUTF8CString("Failed to create UDP socket");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Set non-blocking
    fcntl(sock_fd, F_SETFL, O_NONBLOCK);

    // Create UdpSocket structure
    UdpSocket* udp_sock = malloc(sizeof(UdpSocket));
    udp_sock->socket_fd = sock_fd;
    udp_sock->on_message = NULL;
    udp_sock->on_error = NULL;
    udp_sock->next = udp_socket_list;
    udp_socket_list = udp_sock;

    // Create socket object
    const char* socket_code =
        "(function(fd) {"
        "  return {"
        "    __udp_fd: fd,"
        "    bind: function(port, address, callback) {"
        "      __udp_bind(this.__udp_fd, port, address || '0.0.0.0');"
        "      if (callback) callback();"
        "    },"
        "    send: function(msg, port, address, callback) {"
        "      __udp_send(this.__udp_fd, msg, port, address);"
        "      if (callback) callback();"
        "    },"
        "    on: function(event, handler) {"
        "      if (event === 'message') __udp_on_message(this.__udp_fd, handler);"
        "      if (event === 'error') __udp_on_error(this.__udp_fd, handler);"
        "    },"
        "    close: function() { __udp_close(this.__udp_fd); }"
        "  };"
        "})";

    JSStringRef code_str = JSStringCreateWithUTF8CString(socket_code);
    JSValueRef func_val = JSEvaluateScript(ctx, code_str, NULL, NULL, 1, NULL);
    JSStringRelease(code_str);

    JSObjectRef func = JSValueToObject(ctx, func_val, NULL);
    JSValueRef args[] = {JSValueMakeNumber(ctx, (double)sock_fd)};
    return JSObjectCallAsFunction(ctx, func, NULL, 1, args, NULL);
}

// __udp_bind helper
static JSValueRef js_udp_bind(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                              JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                              const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 3) return JSValueMakeUndefined(ctx);

    int sock_fd = (int)JSValueToNumber(ctx, arguments[0], NULL);
    int port = (int)JSValueToNumber(ctx, arguments[1], NULL);

    JSStringRef addr_str = JSValueToStringCopy(ctx, arguments[2], exception);
    char address[256];
    JSStringGetUTF8CString(addr_str, address, sizeof(address));
    JSStringRelease(addr_str);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, address, &addr.sin_addr);

    if (bind(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        JSStringRef error = JSStringCreateWithUTF8CString("Failed to bind UDP socket");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
    }

    // Initialize kqueue if needed and register socket
    if (kq == -1) {
        kq = kqueue();
    }

    struct kevent ev;
    EV_SET(&ev, sock_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(kq, &ev, 1, NULL, 0, NULL);

    return JSValueMakeUndefined(ctx);
}

// __udp_send helper
static JSValueRef js_udp_send(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                              JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                              const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 4) return JSValueMakeUndefined(ctx);

    int sock_fd = (int)JSValueToNumber(ctx, arguments[0], NULL);

    // Handle Buffer (Uint8Array) input
    unsigned char* message = NULL;
    size_t message_len = 0;

    JSObjectRef msg_obj = JSValueToObject(ctx, arguments[1], exception);
    if (msg_obj) {
        JSStringRef length_name = JSStringCreateWithUTF8CString("length");
        JSValueRef length_val = JSObjectGetProperty(ctx, msg_obj, length_name, NULL);
        JSStringRelease(length_name);

        if (JSValueIsNumber(ctx, length_val)) {
            message_len = (size_t)JSValueToNumber(ctx, length_val, NULL);
            message = malloc(message_len);

            for (size_t i = 0; i < message_len; i++) {
                JSValueRef byte_val = JSObjectGetPropertyAtIndex(ctx, msg_obj, i, NULL);
                message[i] = (unsigned char)JSValueToNumber(ctx, byte_val, NULL);
            }
        }
    }

    if (!message) {
        return JSValueMakeUndefined(ctx);
    }

    int port = (int)JSValueToNumber(ctx, arguments[2], NULL);

    JSStringRef addr_str = JSValueToStringCopy(ctx, arguments[3], exception);
    char address[256];
    JSStringGetUTF8CString(addr_str, address, sizeof(address));
    JSStringRelease(addr_str);

    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, address, &dest_addr.sin_addr);

    sendto(sock_fd, message, message_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    free(message);

    return JSValueMakeUndefined(ctx);
}

// __udp_on_message helper
static JSValueRef js_udp_on_message(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                    JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                    const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount < 2) return JSValueMakeUndefined(ctx);

    int sock_fd = (int)JSValueToNumber(ctx, arguments[0], NULL);
    JSObjectRef handler = JSValueToObject(ctx, arguments[1], NULL);

    // Find UDP socket and store handler
    for (UdpSocket* sock = udp_socket_list; sock; sock = sock->next) {
        if (sock->socket_fd == sock_fd) {
            if (sock->on_message) JSValueUnprotect(global_ctx, sock->on_message);
            sock->on_message = handler;
            JSValueProtect(global_ctx, handler);
            break;
        }
    }

    return JSValueMakeUndefined(ctx);
}

// __udp_on_error helper
static JSValueRef js_udp_on_error(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount < 2) return JSValueMakeUndefined(ctx);

    int sock_fd = (int)JSValueToNumber(ctx, arguments[0], NULL);
    JSObjectRef handler = JSValueToObject(ctx, arguments[1], NULL);

    for (UdpSocket* sock = udp_socket_list; sock; sock = sock->next) {
        if (sock->socket_fd == sock_fd) {
            if (sock->on_error) JSValueUnprotect(global_ctx, sock->on_error);
            sock->on_error = handler;
            JSValueProtect(global_ctx, handler);
            break;
        }
    }

    return JSValueMakeUndefined(ctx);
}

// __udp_close helper
static JSValueRef js_udp_close(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                               JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                               const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    if (argumentCount < 1) return JSValueMakeUndefined(ctx);

    int sock_fd = (int)JSValueToNumber(ctx, arguments[0], NULL);

    // Remove from kqueue
    struct kevent ev;
    EV_SET(&ev, sock_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    kevent(kq, &ev, 1, NULL, 0, NULL);

    close(sock_fd);

    // Remove from list
    UdpSocket** current = &udp_socket_list;
    while (*current) {
        if ((*current)->socket_fd == sock_fd) {
            UdpSocket* to_free = *current;
            *current = (*current)->next;
            if (to_free->on_message) JSValueUnprotect(global_ctx, to_free->on_message);
            if (to_free->on_error) JSValueUnprotect(global_ctx, to_free->on_error);
            free(to_free);
            break;
        }
        current = &(*current)->next;
    }

    return JSValueMakeUndefined(ctx);
}

// Create dgram module object
static JSObjectRef create_dgram_module(JSContextRef ctx) {
    JSObjectRef dgram = JSObjectMake(ctx, NULL, NULL);

    // dgram.createSocket()
    JSStringRef createSocket_name = JSStringCreateWithUTF8CString("createSocket");
    JSObjectRef createSocket_func = JSObjectMakeFunctionWithCallback(ctx, createSocket_name, js_dgram_create_socket);
    JSObjectSetProperty(ctx, dgram, createSocket_name, createSocket_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(createSocket_name);

    return dgram;
}

// zlib.gzip() implementation
static JSValueRef js_zlib_gzip(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                               JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                               const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        JSStringRef error = JSStringCreateWithUTF8CString("gzip requires data and callback");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Get input data from Buffer (Uint8Array)
    JSObjectRef data_obj = JSValueToObject(ctx, arguments[0], exception);
    if (!data_obj) return JSValueMakeUndefined(ctx);

    JSStringRef length_name = JSStringCreateWithUTF8CString("length");
    JSValueRef length_val = JSObjectGetProperty(ctx, data_obj, length_name, NULL);
    JSStringRelease(length_name);

    if (!JSValueIsNumber(ctx, length_val)) return JSValueMakeUndefined(ctx);

    size_t data_len = (size_t)JSValueToNumber(ctx, length_val, NULL);
    unsigned char* data = malloc(data_len);

    for (size_t i = 0; i < data_len; i++) {
        JSValueRef byte_val = JSObjectGetPropertyAtIndex(ctx, data_obj, i, NULL);
        data[i] = (unsigned char)JSValueToNumber(ctx, byte_val, NULL);
    }

    // Get callback
    JSObjectRef callback = JSValueToObject(ctx, arguments[1], exception);
    if (*exception) {
        free(data);
        return JSValueMakeUndefined(ctx);
    }

    // Compress data
    uLongf compressed_size = compressBound(data_len);
    unsigned char* compressed = malloc(compressed_size);

    int result = compress2(compressed, &compressed_size, data, data_len, Z_DEFAULT_COMPRESSION);
    free(data);

    if (result != Z_OK) {
        free(compressed);
        JSStringRef error = JSStringCreateWithUTF8CString("Compression failed");
        JSValueRef error_val = JSValueMakeString(ctx, error);
        JSStringRelease(error);

        JSValueRef args[] = {error_val, JSValueMakeNull(ctx)};
        JSObjectCallAsFunction(ctx, callback, NULL, 2, args, NULL);
        return JSValueMakeUndefined(ctx);
    }

    // Create Buffer from compressed data
    JSValueRef* byte_values = malloc(sizeof(JSValueRef) * compressed_size);
    for (size_t i = 0; i < compressed_size; i++) {
        byte_values[i] = JSValueMakeNumber(ctx, compressed[i]);
    }
    JSObjectRef byte_array = JSObjectMakeArray(ctx, compressed_size, byte_values, NULL);
    free(byte_values);
    free(compressed);

    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef temp_name = JSStringCreateWithUTF8CString("__temp_zlib_data");
    JSObjectSetProperty(ctx, global, temp_name, byte_array, kJSPropertyAttributeNone, NULL);
    JSStringRelease(temp_name);

    JSStringRef code = JSStringCreateWithUTF8CString("Buffer.from(__temp_zlib_data)");
    JSValueRef compressed_val = JSEvaluateScript(ctx, code, NULL, NULL, 1, NULL);
    JSStringRelease(code);

    // Call callback(null, compressed)
    JSValueRef args[] = {JSValueMakeNull(ctx), compressed_val};
    JSObjectCallAsFunction(ctx, callback, NULL, 2, args, NULL);

    return JSValueMakeUndefined(ctx);
}

// zlib.gunzip() implementation
static JSValueRef js_zlib_gunzip(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                 JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                 const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        JSStringRef error = JSStringCreateWithUTF8CString("gunzip requires data and callback");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Get input data from Buffer (Uint8Array)
    JSObjectRef data_obj = JSValueToObject(ctx, arguments[0], exception);
    if (!data_obj) return JSValueMakeUndefined(ctx);

    JSStringRef length_name = JSStringCreateWithUTF8CString("length");
    JSValueRef length_val = JSObjectGetProperty(ctx, data_obj, length_name, NULL);
    JSStringRelease(length_name);

    if (!JSValueIsNumber(ctx, length_val)) return JSValueMakeUndefined(ctx);

    size_t data_len = (size_t)JSValueToNumber(ctx, length_val, NULL);
    unsigned char* data = malloc(data_len);

    for (size_t i = 0; i < data_len; i++) {
        JSValueRef byte_val = JSObjectGetPropertyAtIndex(ctx, data_obj, i, NULL);
        data[i] = (unsigned char)JSValueToNumber(ctx, byte_val, NULL);
    }

    // Get callback
    JSObjectRef callback = JSValueToObject(ctx, arguments[1], exception);
    if (*exception) {
        free(data);
        return JSValueMakeUndefined(ctx);
    }

    // Decompress data (assume 10x expansion)
    uLongf decompressed_size = data_len * 10;
    unsigned char* decompressed = malloc(decompressed_size);

    int result = uncompress(decompressed, &decompressed_size, data, data_len);
    free(data);

    if (result != Z_OK) {
        free(decompressed);
        JSStringRef error = JSStringCreateWithUTF8CString("Decompression failed");
        JSValueRef error_val = JSValueMakeString(ctx, error);
        JSStringRelease(error);

        JSValueRef args[] = {error_val, JSValueMakeNull(ctx)};
        JSObjectCallAsFunction(ctx, callback, NULL, 2, args, NULL);
        return JSValueMakeUndefined(ctx);
    }

    // Create Buffer from decompressed data
    JSValueRef* byte_values = malloc(sizeof(JSValueRef) * decompressed_size);
    for (size_t i = 0; i < decompressed_size; i++) {
        byte_values[i] = JSValueMakeNumber(ctx, decompressed[i]);
    }
    JSObjectRef byte_array = JSObjectMakeArray(ctx, decompressed_size, byte_values, NULL);
    free(byte_values);
    free(decompressed);

    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef temp_name = JSStringCreateWithUTF8CString("__temp_zlib_data");
    JSObjectSetProperty(ctx, global, temp_name, byte_array, kJSPropertyAttributeNone, NULL);
    JSStringRelease(temp_name);

    JSStringRef code = JSStringCreateWithUTF8CString("Buffer.from(__temp_zlib_data)");
    JSValueRef decompressed_val = JSEvaluateScript(ctx, code, NULL, NULL, 1, NULL);
    JSStringRelease(code);

    // Call callback(null, decompressed)
    JSValueRef args[] = {JSValueMakeNull(ctx), decompressed_val};
    JSObjectCallAsFunction(ctx, callback, NULL, 2, args, NULL);

    return JSValueMakeUndefined(ctx);
}

// Create zlib module object
static JSObjectRef create_zlib_module(JSContextRef ctx) {
    JSObjectRef zlib = JSObjectMake(ctx, NULL, NULL);

    // zlib.gzip()
    JSStringRef gzip_name = JSStringCreateWithUTF8CString("gzip");
    JSObjectRef gzip_func = JSObjectMakeFunctionWithCallback(ctx, gzip_name, js_zlib_gzip);
    JSObjectSetProperty(ctx, zlib, gzip_name, gzip_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(gzip_name);

    // zlib.gunzip()
    JSStringRef gunzip_name = JSStringCreateWithUTF8CString("gunzip");
    JSObjectRef gunzip_func = JSObjectMakeFunctionWithCallback(ctx, gunzip_name, js_zlib_gunzip);
    JSObjectSetProperty(ctx, zlib, gunzip_name, gunzip_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(gunzip_name);

    return zlib;
}

// Generate WebSocket accept key from Sec-WebSocket-Key
static void ws_generate_accept_key(const char* client_key, char* accept_key) {
    char combined[256];
    snprintf(combined, sizeof(combined), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);

    unsigned char hash[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(combined, (CC_LONG)strlen(combined), hash);

    // Base64 encode
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, j = 0;
    for (i = 0; i < CC_SHA1_DIGEST_LENGTH; i += 3) {
        unsigned int n = ((unsigned int)hash[i] << 16) |
                         ((i + 1 < CC_SHA1_DIGEST_LENGTH) ? ((unsigned int)hash[i + 1] << 8) : 0) |
                         ((i + 2 < CC_SHA1_DIGEST_LENGTH) ? hash[i + 2] : 0);

        accept_key[j++] = base64_chars[(n >> 18) & 63];
        accept_key[j++] = base64_chars[(n >> 12) & 63];
        accept_key[j++] = (i + 1 < CC_SHA1_DIGEST_LENGTH) ? base64_chars[(n >> 6) & 63] : '=';
        accept_key[j++] = (i + 2 < CC_SHA1_DIGEST_LENGTH) ? base64_chars[n & 63] : '=';
    }
    accept_key[j] = '\0';
}

// Encode WebSocket frame
static size_t ws_encode_frame(unsigned char* out, const unsigned char* payload, size_t payload_len,
                               int opcode, int is_client) {
    size_t pos = 0;

    // FIN bit set, opcode
    out[pos++] = 0x80 | (opcode & 0x0F);

    // Mask bit and payload length
    unsigned char mask_bit = is_client ? 0x80 : 0x00;

    if (payload_len < 126) {
        out[pos++] = mask_bit | payload_len;
    } else if (payload_len < 65536) {
        out[pos++] = mask_bit | 126;
        out[pos++] = (payload_len >> 8) & 0xFF;
        out[pos++] = payload_len & 0xFF;
    } else {
        out[pos++] = mask_bit | 127;
        for (int i = 7; i >= 0; i--) {
            out[pos++] = (payload_len >> (i * 8)) & 0xFF;
        }
    }

    // Masking key (if client)
    unsigned char mask[4] = {0};
    if (is_client) {
        FILE* urandom = fopen("/dev/urandom", "r");
        if (urandom) {
            fread(mask, 1, 4, urandom);
            fclose(urandom);
        }
        memcpy(out + pos, mask, 4);
        pos += 4;
    }

    // Payload (masked if client)
    for (size_t i = 0; i < payload_len; i++) {
        out[pos++] = is_client ? (payload[i] ^ mask[i % 4]) : payload[i];
    }

    return pos;
}

// Parse WebSocket frame
static int ws_parse_frame(const unsigned char* data, size_t data_len,
                          int* opcode, unsigned char** payload, size_t* payload_len,
                          size_t* frame_len) {
    if (data_len < 2) return -1;  // Need at least 2 bytes

    int fin = (data[0] & 0x80) != 0;
    *opcode = data[0] & 0x0F;
    int masked = (data[1] & 0x80) != 0;
    uint64_t len = data[1] & 0x7F;

    size_t pos = 2;

    // Extended payload length
    if (len == 126) {
        if (data_len < 4) return -1;
        len = (data[2] << 8) | data[3];
        pos = 4;
    } else if (len == 127) {
        if (data_len < 10) return -1;
        len = 0;
        for (int i = 0; i < 8; i++) {
            len = (len << 8) | data[2 + i];
        }
        pos = 10;
    }

    // Masking key
    unsigned char mask[4] = {0};
    if (masked) {
        if (data_len < pos + 4) return -1;
        memcpy(mask, data + pos, 4);
        pos += 4;
    }

    // Check if we have full frame
    if (data_len < pos + len) return -1;

    // Unmask payload
    *payload = malloc(len + 1);
    for (size_t i = 0; i < len; i++) {
        (*payload)[i] = masked ? (data[pos + i] ^ mask[i % 4]) : data[pos + i];
    }
    (*payload)[len] = '\0';  // Null terminate for text frames
    *payload_len = len;
    *frame_len = pos + len;

    return fin ? 1 : 0;  // Return 1 if final frame
}

// WebSocket finalizer
static void websocket_finalizer(JSObjectRef object) {
    WebSocket* ws = JSObjectGetPrivate(object);
    if (ws) {
        if (ws->socket_fd >= 0) {
            close(ws->socket_fd);
        }
        if (ws->url) free(ws->url);
        if (ws->onopen) JSValueUnprotect(global_ctx, ws->onopen);
        if (ws->onmessage) JSValueUnprotect(global_ctx, ws->onmessage);
        if (ws->onerror) JSValueUnprotect(global_ctx, ws->onerror);
        if (ws->onclose) JSValueUnprotect(global_ctx, ws->onclose);

        // Remove from list
        WebSocket** current = &websocket_list;
        while (*current) {
            if (*current == ws) {
                *current = ws->next;
                break;
            }
            current = &(*current)->next;
        }

        free(ws);
    }
}

// WebSocket property setter
static bool websocket_set_property(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName,
                                    JSValueRef value, JSValueRef* exception __attribute__((unused))) {
    WebSocket* ws = JSObjectGetPrivate(object);
    if (!ws) return false;

    char prop_name[32];
    JSStringGetUTF8CString(propertyName, prop_name, sizeof(prop_name));

    if (strcmp(prop_name, "onopen") == 0 && JSValueIsObject(ctx, value)) {
        if (ws->onopen) JSValueUnprotect(ctx, ws->onopen);
        ws->onopen = JSValueToObject(ctx, value, NULL);
        JSValueProtect(ctx, ws->onopen);
        return true;
    } else if (strcmp(prop_name, "onmessage") == 0 && JSValueIsObject(ctx, value)) {
        if (ws->onmessage) JSValueUnprotect(ctx, ws->onmessage);
        ws->onmessage = JSValueToObject(ctx, value, NULL);
        JSValueProtect(ctx, ws->onmessage);
        return true;
    } else if (strcmp(prop_name, "onerror") == 0 && JSValueIsObject(ctx, value)) {
        if (ws->onerror) JSValueUnprotect(ctx, ws->onerror);
        ws->onerror = JSValueToObject(ctx, value, NULL);
        JSValueProtect(ctx, ws->onerror);
        return true;
    } else if (strcmp(prop_name, "onclose") == 0 && JSValueIsObject(ctx, value)) {
        if (ws->onclose) JSValueUnprotect(ctx, ws->onclose);
        ws->onclose = JSValueToObject(ctx, value, NULL);
        JSValueProtect(ctx, ws->onclose);
        return true;
    }

    return false;
}

// ws.send() implementation
static JSValueRef js_websocket_send(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                     JSObjectRef thisObject, size_t argumentCount,
                                     const JSValueRef arguments[], JSValueRef* exception) {
    WebSocket* ws = JSObjectGetPrivate(thisObject);
    if (!ws || ws->ready_state != 1) {
        JSStringRef error = JSStringCreateWithUTF8CString("WebSocket is not open");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    if (argumentCount < 1) return JSValueMakeUndefined(ctx);

    JSStringRef data_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(data_str);
    char* data = malloc(max_size);
    JSStringGetUTF8CString(data_str, data, max_size);
    JSStringRelease(data_str);

    size_t data_len = strlen(data);
    unsigned char frame[65536];
    size_t frame_len = ws_encode_frame(frame, (unsigned char*)data, data_len, WS_OPCODE_TEXT, ws->is_client);

    send(ws->socket_fd, frame, frame_len, 0);
    free(data);

    return JSValueMakeUndefined(ctx);
}

// ws.close() implementation
static JSValueRef js_websocket_close(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                      JSObjectRef thisObject, size_t argumentCount __attribute__((unused)),
                                      const JSValueRef arguments[] __attribute__((unused)),
                                      JSValueRef* exception __attribute__((unused))) {
    WebSocket* ws = JSObjectGetPrivate(thisObject);
    if (!ws || ws->ready_state == 3) return JSValueMakeUndefined(ctx);

    ws->ready_state = 2;  // CLOSING

    unsigned char close_frame[2] = {0};
    unsigned char frame[256];
    size_t frame_len = ws_encode_frame(frame, close_frame, 0, WS_OPCODE_CLOSE, ws->is_client);
    send(ws->socket_fd, frame, frame_len, 0);

    ws->ready_state = 3;  // CLOSED
    close(ws->socket_fd);
    ws->socket_fd = -1;

    return JSValueMakeUndefined(ctx);
}

// WebSocket constructor
static JSObjectRef js_websocket_constructor(JSContextRef ctx, JSObjectRef constructor __attribute__((unused)),
                                             size_t argumentCount,
                                             const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        JSStringRef error = JSStringCreateWithUTF8CString("WebSocket requires url argument");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return NULL;
    }

    JSStringRef url_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return NULL;

    size_t max_size = JSStringGetMaximumUTF8CStringSize(url_str);
    char* url = malloc(max_size);
    JSStringGetUTF8CString(url_str, url, max_size);
    JSStringRelease(url_str);

    // Parse URL (ws://host:port/path)
    char host[256] = {0};
    char path[512] = "/";
    int port = 80;

    if (strncmp(url, "ws://", 5) == 0) {
        const char* url_part = url + 5;
        const char* slash = strchr(url_part, '/');
        const char* colon = strchr(url_part, ':');

        if (colon && (!slash || colon < slash)) {
            size_t host_len = colon - url_part;
            strncpy(host, url_part, host_len);
            host[host_len] = '\0';
            port = atoi(colon + 1);
            if (slash) strncpy(path, slash, sizeof(path) - 1);
        } else if (slash) {
            size_t host_len = slash - url_part;
            strncpy(host, url_part, host_len);
            host[host_len] = '\0';
            strncpy(path, slash, sizeof(path) - 1);
        } else {
            strncpy(host, url_part, sizeof(host) - 1);
        }
    } else {
        free(url);
        JSStringRef error = JSStringCreateWithUTF8CString("Only ws:// protocol supported");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return NULL;
    }

    // Create socket
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        free(url);
        JSStringRef error = JSStringCreateWithUTF8CString("Failed to create socket");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return NULL;
    }

    // Set non-blocking
    fcntl(sock_fd, F_SETFL, O_NONBLOCK);

    // Connect
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &server_addr.sin_addr);

    // Try to resolve hostname if not IP
    if (server_addr.sin_addr.s_addr == 0) {
        // Simple fallback - try localhost
        if (strcmp(host, "localhost") == 0) {
            inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
        }
    }

    connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Create WebSocket object
    WebSocket* ws = malloc(sizeof(WebSocket));
    ws->socket_fd = sock_fd;
    ws->is_client = 1;
    ws->ready_state = 0;  // CONNECTING
    ws->onopen = NULL;
    ws->onmessage = NULL;
    ws->onerror = NULL;
    ws->onclose = NULL;
    ws->url = url;
    ws->read_buffer_len = 0;
    ws->handshake_len = 0;
    ws->next = websocket_list;
    websocket_list = ws;

    // Create JS object
    JSClassDefinition ws_class_def = kJSClassDefinitionEmpty;
    ws_class_def.finalize = websocket_finalizer;
    ws_class_def.setProperty = websocket_set_property;
    JSClassRef ws_class = JSClassCreate(&ws_class_def);
    JSObjectRef ws_obj = JSObjectMake(ctx, ws_class, ws);
    JSClassRelease(ws_class);

    // Add methods
    JSStringRef send_name = JSStringCreateWithUTF8CString("send");
    JSObjectRef send_func = JSObjectMakeFunctionWithCallback(ctx, send_name, js_websocket_send);
    JSObjectSetProperty(ctx, ws_obj, send_name, send_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(send_name);

    JSStringRef close_name = JSStringCreateWithUTF8CString("close");
    JSObjectRef close_func = JSObjectMakeFunctionWithCallback(ctx, close_name, js_websocket_close);
    JSObjectSetProperty(ctx, ws_obj, close_name, close_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(close_name);

    // Add readyState property
    JSStringRef readyState_name = JSStringCreateWithUTF8CString("readyState");
    JSObjectSetProperty(ctx, ws_obj, readyState_name, JSValueMakeNumber(ctx, ws->ready_state),
                        kJSPropertyAttributeNone, NULL);
    JSStringRelease(readyState_name);

    // Prepare HTTP upgrade request (will be sent when socket is writable)
    ws->handshake_len = snprintf(ws->handshake_buffer, sizeof(ws->handshake_buffer),
             "GET %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n",
             path, host, port);

    // Add to kqueue with WRITE filter to detect when socket is connected and writable
    struct kevent ev;
    EV_SET(&ev, sock_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, ws_obj);
    kevent(kq, &ev, 1, NULL, 0, NULL);
    JSValueProtect(global_ctx, ws_obj);

    return ws_obj;
}

// Create path module object
static JSObjectRef create_path_module(JSContextRef ctx) {
    JSObjectRef path = JSObjectMake(ctx, NULL, NULL);

    JSStringRef join_name = JSStringCreateWithUTF8CString("join");
    JSObjectRef join_func = JSObjectMakeFunctionWithCallback(ctx, join_name, js_path_join);
    JSObjectSetProperty(ctx, path, join_name, join_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(join_name);

    JSStringRef basename_name = JSStringCreateWithUTF8CString("basename");
    JSObjectRef basename_func = JSObjectMakeFunctionWithCallback(ctx, basename_name, js_path_basename);
    JSObjectSetProperty(ctx, path, basename_name, basename_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(basename_name);

    JSStringRef dirname_name = JSStringCreateWithUTF8CString("dirname");
    JSObjectRef dirname_func = JSObjectMakeFunctionWithCallback(ctx, dirname_name, js_path_dirname);
    JSObjectSetProperty(ctx, path, dirname_name, dirname_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(dirname_name);

    JSStringRef extname_name = JSStringCreateWithUTF8CString("extname");
    JSObjectRef extname_func = JSObjectMakeFunctionWithCallback(ctx, extname_name, js_path_extname);
    JSObjectSetProperty(ctx, path, extname_name, extname_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(extname_name);

    JSStringRef resolve_name = JSStringCreateWithUTF8CString("resolve");
    JSObjectRef resolve_func = JSObjectMakeFunctionWithCallback(ctx, resolve_name, js_path_resolve);
    JSObjectSetProperty(ctx, path, resolve_name, resolve_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(resolve_name);

    JSStringRef isAbsolute_name = JSStringCreateWithUTF8CString("isAbsolute");
    JSObjectRef isAbsolute_func = JSObjectMakeFunctionWithCallback(ctx, isAbsolute_name, js_path_is_absolute);
    JSObjectSetProperty(ctx, path, isAbsolute_name, isAbsolute_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(isAbsolute_name);

    // path.sep
    JSStringRef sep_name = JSStringCreateWithUTF8CString("sep");
    JSStringRef sep_value = JSStringCreateWithUTF8CString("/");
    JSObjectSetProperty(ctx, path, sep_name, JSValueMakeString(ctx, sep_value), kJSPropertyAttributeNone, NULL);
    JSStringRelease(sep_name);
    JSStringRelease(sep_value);

    // path.delimiter
    JSStringRef delimiter_name = JSStringCreateWithUTF8CString("delimiter");
    JSStringRef delimiter_value = JSStringCreateWithUTF8CString(":");
    JSObjectSetProperty(ctx, path, delimiter_name, JSValueMakeString(ctx, delimiter_value), kJSPropertyAttributeNone, NULL);
    JSStringRelease(delimiter_name);
    JSStringRelease(delimiter_value);

    return path;
}

// Create child_process module object
static JSObjectRef create_child_process_module(JSContextRef ctx) {
    JSObjectRef cp = JSObjectMake(ctx, NULL, NULL);

    JSStringRef execSync_name = JSStringCreateWithUTF8CString("execSync");
    JSObjectRef execSync_func = JSObjectMakeFunctionWithCallback(ctx, execSync_name, js_exec_sync);
    JSObjectSetProperty(ctx, cp, execSync_name, execSync_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(execSync_name);

    JSStringRef spawnSync_name = JSStringCreateWithUTF8CString("spawnSync");
    JSObjectRef spawnSync_func = JSObjectMakeFunctionWithCallback(ctx, spawnSync_name, js_spawn_sync);
    JSObjectSetProperty(ctx, cp, spawnSync_name, spawnSync_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(spawnSync_name);

    return cp;
}

// Create fs module object
static JSObjectRef create_fs_module(JSContextRef ctx) {
    JSObjectRef fs = JSObjectMake(ctx, NULL, NULL);

    JSStringRef readFileSync_name = JSStringCreateWithUTF8CString("readFileSync");
    JSObjectRef readFileSync_func = JSObjectMakeFunctionWithCallback(ctx, readFileSync_name, js_fs_read_file_sync);
    JSObjectSetProperty(ctx, fs, readFileSync_name, readFileSync_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(readFileSync_name);

    JSStringRef writeFileSync_name = JSStringCreateWithUTF8CString("writeFileSync");
    JSObjectRef writeFileSync_func = JSObjectMakeFunctionWithCallback(ctx, writeFileSync_name, js_fs_write_file_sync);
    JSObjectSetProperty(ctx, fs, writeFileSync_name, writeFileSync_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(writeFileSync_name);

    JSStringRef existsSync_name = JSStringCreateWithUTF8CString("existsSync");
    JSObjectRef existsSync_func = JSObjectMakeFunctionWithCallback(ctx, existsSync_name, js_fs_exists_sync);
    JSObjectSetProperty(ctx, fs, existsSync_name, existsSync_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(existsSync_name);

    JSStringRef readdirSync_name = JSStringCreateWithUTF8CString("readdirSync");
    JSObjectRef readdirSync_func = JSObjectMakeFunctionWithCallback(ctx, readdirSync_name, js_fs_readdir_sync);
    JSObjectSetProperty(ctx, fs, readdirSync_name, readdirSync_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(readdirSync_name);

    JSStringRef mkdirSync_name = JSStringCreateWithUTF8CString("mkdirSync");
    JSObjectRef mkdirSync_func = JSObjectMakeFunctionWithCallback(ctx, mkdirSync_name, js_fs_mkdir_sync);
    JSObjectSetProperty(ctx, fs, mkdirSync_name, mkdirSync_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(mkdirSync_name);

    JSStringRef rmdirSync_name = JSStringCreateWithUTF8CString("rmdirSync");
    JSObjectRef rmdirSync_func = JSObjectMakeFunctionWithCallback(ctx, rmdirSync_name, js_fs_rmdir_sync);
    JSObjectSetProperty(ctx, fs, rmdirSync_name, rmdirSync_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(rmdirSync_name);

    JSStringRef unlinkSync_name = JSStringCreateWithUTF8CString("unlinkSync");
    JSObjectRef unlinkSync_func = JSObjectMakeFunctionWithCallback(ctx, unlinkSync_name, js_fs_unlink_sync);
    JSObjectSetProperty(ctx, fs, unlinkSync_name, unlinkSync_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(unlinkSync_name);

    // Async functions
    JSStringRef readFile_name = JSStringCreateWithUTF8CString("readFile");
    JSObjectRef readFile_func = JSObjectMakeFunctionWithCallback(ctx, readFile_name, js_fs_read_file);
    JSObjectSetProperty(ctx, fs, readFile_name, readFile_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(readFile_name);

    JSStringRef writeFile_name = JSStringCreateWithUTF8CString("writeFile");
    JSObjectRef writeFile_func = JSObjectMakeFunctionWithCallback(ctx, writeFile_name, js_fs_write_file);
    JSObjectSetProperty(ctx, fs, writeFile_name, writeFile_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(writeFile_name);

    // Streams
    JSStringRef createReadStream_name = JSStringCreateWithUTF8CString("createReadStream");
    JSObjectRef createReadStream_func = JSObjectMakeFunctionWithCallback(ctx, createReadStream_name, js_create_read_stream);
    JSObjectSetProperty(ctx, fs, createReadStream_name, createReadStream_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(createReadStream_name);

    JSStringRef createWriteStream_name = JSStringCreateWithUTF8CString("createWriteStream");
    JSObjectRef createWriteStream_func = JSObjectMakeFunctionWithCallback(ctx, createWriteStream_name, js_create_write_stream);
    JSObjectSetProperty(ctx, fs, createWriteStream_name, createWriteStream_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(createWriteStream_name);

    return fs;
}

// ============================================================================
// Web APIs: TextEncoder, TextDecoder, URL, URLSearchParams, AbortController
// ============================================================================

// TextEncoder data structure
typedef struct {
    char encoding[16];  // Always "utf-8" for now
} TextEncoderData;

// TextEncoder finalizer
static void text_encoder_finalize(JSObjectRef object) {
    TextEncoderData* data = JSObjectGetPrivate(object);
    if (data) {
        free(data);
    }
}

// TextEncoder.encode() method
static JSValueRef js_text_encoder_encode(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                          JSObjectRef thisObject, size_t argumentCount,
                                          const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1 || !JSValueIsString(ctx, arguments[0])) {
        return JSValueMakeUndefined(ctx);
    }

    // Convert string to UTF-8 bytes
    JSStringRef str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(str);
    char* buffer = malloc(max_size);
    size_t actual_size = JSStringGetUTF8CString(str, buffer, max_size);
    JSStringRelease(str);

    // Create Uint8Array with the bytes (actual_size - 1 excludes null terminator)
    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSValueRef* byte_values = malloc(sizeof(JSValueRef) * (actual_size - 1));
    for (size_t i = 0; i < actual_size - 1; i++) {
        byte_values[i] = JSValueMakeNumber(ctx, (unsigned char)buffer[i]);
    }
    JSObjectRef array = JSObjectMakeArray(ctx, actual_size - 1, byte_values, NULL);
    free(byte_values);
    free(buffer);

    // Create Uint8Array from array
    JSStringRef temp_name = JSStringCreateWithUTF8CString("__temp_encoder_data");
    JSObjectSetProperty(ctx, global, temp_name, array, kJSPropertyAttributeNone, NULL);
    JSStringRelease(temp_name);

    JSStringRef code = JSStringCreateWithUTF8CString("new Uint8Array(__temp_encoder_data)");
    JSValueRef result = JSEvaluateScript(ctx, code, NULL, NULL, 1, exception);
    JSStringRelease(code);

    return result;
}

// TextEncoder constructor
static JSObjectRef js_text_encoder_constructor(JSContextRef ctx, JSObjectRef constructor __attribute__((unused)),
                                                size_t argumentCount __attribute__((unused)),
                                                const JSValueRef arguments[] __attribute__((unused)),
                                                JSValueRef* exception __attribute__((unused))) {
    // Create private data
    TextEncoderData* data = malloc(sizeof(TextEncoderData));
    strcpy(data->encoding, "utf-8");

    // Create class with finalizer
    JSClassDefinition class_def = kJSClassDefinitionEmpty;
    class_def.finalize = text_encoder_finalize;
    JSClassRef class = JSClassCreate(&class_def);
    JSObjectRef instance = JSObjectMake(ctx, class, data);
    JSClassRelease(class);

    // Add encode method
    JSStringRef encode_name = JSStringCreateWithUTF8CString("encode");
    JSObjectRef encode_func = JSObjectMakeFunctionWithCallback(ctx, encode_name, js_text_encoder_encode);
    JSObjectSetProperty(ctx, instance, encode_name, encode_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(encode_name);

    // Add encoding property (read-only)
    JSStringRef encoding_name = JSStringCreateWithUTF8CString("encoding");
    JSStringRef encoding_val = JSStringCreateWithUTF8CString("utf-8");
    JSObjectSetProperty(ctx, instance, encoding_name, JSValueMakeString(ctx, encoding_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(encoding_name);
    JSStringRelease(encoding_val);

    return instance;
}

// TextDecoder data structure
typedef struct {
    char encoding[16];
} TextDecoderData;

// TextDecoder finalizer
static void text_decoder_finalize(JSObjectRef object) {
    TextDecoderData* data = JSObjectGetPrivate(object);
    if (data) {
        free(data);
    }
}

// TextDecoder.decode() method
static JSValueRef js_text_decoder_decode(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                          JSObjectRef thisObject, size_t argumentCount,
                                          const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(""));
    }

    JSObjectRef obj = JSValueToObject(ctx, arguments[0], exception);
    if (*exception || !obj) return JSValueMakeUndefined(ctx);

    // Get length property
    JSStringRef length_name = JSStringCreateWithUTF8CString("length");
    JSValueRef length_val = JSObjectGetProperty(ctx, obj, length_name, NULL);
    JSStringRelease(length_name);

    if (!JSValueIsNumber(ctx, length_val)) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(""));
    }

    size_t length = (size_t)JSValueToNumber(ctx, length_val, NULL);
    if (length == 0) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(""));
    }

    // Extract bytes from array/buffer
    char* buffer = malloc(length + 1);
    for (size_t i = 0; i < length; i++) {
        JSValueRef val = JSObjectGetPropertyAtIndex(ctx, obj, i, NULL);
        buffer[i] = (char)JSValueToNumber(ctx, val, NULL);
    }
    buffer[length] = '\0';

    // Create JavaScript string from UTF-8 bytes
    JSStringRef result_str = JSStringCreateWithUTF8CString(buffer);
    JSValueRef result = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    free(buffer);

    return result;
}

// TextDecoder constructor
static JSObjectRef js_text_decoder_constructor(JSContextRef ctx, JSObjectRef constructor __attribute__((unused)),
                                                size_t argumentCount,
                                                const JSValueRef arguments[], JSValueRef* exception) {
    // Get encoding (default to utf-8)
    char encoding[16] = "utf-8";
    if (argumentCount > 0 && JSValueIsString(ctx, arguments[0])) {
        JSStringRef enc_str = JSValueToStringCopy(ctx, arguments[0], exception);
        if (*exception) return NULL;
        JSStringGetUTF8CString(enc_str, encoding, sizeof(encoding));
        JSStringRelease(enc_str);
    }

    // Create private data
    TextDecoderData* data = malloc(sizeof(TextDecoderData));
    strncpy(data->encoding, encoding, sizeof(data->encoding) - 1);
    data->encoding[sizeof(data->encoding) - 1] = '\0';

    // Create class with finalizer
    JSClassDefinition class_def = kJSClassDefinitionEmpty;
    class_def.finalize = text_decoder_finalize;
    JSClassRef class = JSClassCreate(&class_def);
    JSObjectRef instance = JSObjectMake(ctx, class, data);
    JSClassRelease(class);

    // Add decode method
    JSStringRef decode_name = JSStringCreateWithUTF8CString("decode");
    JSObjectRef decode_func = JSObjectMakeFunctionWithCallback(ctx, decode_name, js_text_decoder_decode);
    JSObjectSetProperty(ctx, instance, decode_name, decode_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(decode_name);

    // Add encoding property (read-only)
    JSStringRef encoding_name = JSStringCreateWithUTF8CString("encoding");
    JSStringRef encoding_val = JSStringCreateWithUTF8CString(data->encoding);
    JSObjectSetProperty(ctx, instance, encoding_name, JSValueMakeString(ctx, encoding_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(encoding_name);
    JSStringRelease(encoding_val);

    return instance;
}

// Base64 character table (reused from WebSocket accept key generation)
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 decode lookup helper
static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -1;  // Padding
    return -2;  // Invalid
}

// btoa() - encode string to base64
static JSValueRef js_btoa(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                          JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                          const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1 || !JSValueIsString(ctx, arguments[0])) {
        JSStringRef error = JSStringCreateWithUTF8CString("btoa requires a string argument");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Get input string
    JSStringRef input_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(input_str);
    char* input = malloc(max_size);
    size_t input_len = JSStringGetUTF8CString(input_str, input, max_size);
    JSStringRelease(input_str);
    input_len--;  // Remove null terminator

    // Calculate output size (4 chars for every 3 bytes, plus padding)
    size_t output_len = ((input_len + 2) / 3) * 4;
    char* output = malloc(output_len + 1);

    size_t i = 0, j = 0;
    while (i < input_len) {
        unsigned int n = ((unsigned int)(unsigned char)input[i] << 16) |
                         ((i + 1 < input_len) ? ((unsigned int)(unsigned char)input[i + 1] << 8) : 0) |
                         ((i + 2 < input_len) ? (unsigned char)input[i + 2] : 0);

        output[j++] = base64_chars[(n >> 18) & 63];
        output[j++] = base64_chars[(n >> 12) & 63];
        output[j++] = (i + 1 < input_len) ? base64_chars[(n >> 6) & 63] : '=';
        output[j++] = (i + 2 < input_len) ? base64_chars[n & 63] : '=';

        i += 3;
    }
    output[j] = '\0';

    JSStringRef result_str = JSStringCreateWithUTF8CString(output);
    JSValueRef result = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    free(input);
    free(output);

    return result;
}

// atob() - decode base64 to string
static JSValueRef js_atob(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                          JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                          const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1 || !JSValueIsString(ctx, arguments[0])) {
        JSStringRef error = JSStringCreateWithUTF8CString("atob requires a string argument");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Get input string
    JSStringRef input_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(input_str);
    char* input = malloc(max_size);
    size_t input_len = JSStringGetUTF8CString(input_str, input, max_size);
    JSStringRelease(input_str);
    input_len--;  // Remove null terminator

    // Remove whitespace
    char* clean_input = malloc(input_len + 1);
    size_t clean_len = 0;
    for (size_t i = 0; i < input_len; i++) {
        if (input[i] != ' ' && input[i] != '\t' && input[i] != '\n' && input[i] != '\r') {
            clean_input[clean_len++] = input[i];
        }
    }
    clean_input[clean_len] = '\0';
    free(input);

    // Validate length (must be multiple of 4)
    if (clean_len % 4 != 0) {
        free(clean_input);
        JSStringRef error = JSStringCreateWithUTF8CString("Invalid base64 string");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return JSValueMakeUndefined(ctx);
    }

    // Calculate output size
    size_t output_len = (clean_len / 4) * 3;
    if (clean_len > 0 && clean_input[clean_len - 1] == '=') output_len--;
    if (clean_len > 1 && clean_input[clean_len - 2] == '=') output_len--;

    char* output = malloc(output_len + 1);
    size_t i = 0, j = 0;

    while (i < clean_len) {
        int a = base64_decode_char(clean_input[i]);
        int b = base64_decode_char(clean_input[i + 1]);
        int c = base64_decode_char(clean_input[i + 2]);
        int d = base64_decode_char(clean_input[i + 3]);

        if (a < 0 || b < 0 || (c < -1) || (d < -1)) {
            free(clean_input);
            free(output);
            JSStringRef error = JSStringCreateWithUTF8CString("Invalid base64 string");
            *exception = JSValueMakeString(ctx, error);
            JSStringRelease(error);
            return JSValueMakeUndefined(ctx);
        }

        unsigned int n = (a << 18) | (b << 12) | ((c >= 0 ? c : 0) << 6) | (d >= 0 ? d : 0);

        if (j < output_len) output[j++] = (n >> 16) & 0xFF;
        if (j < output_len) output[j++] = (n >> 8) & 0xFF;
        if (j < output_len) output[j++] = n & 0xFF;

        i += 4;
    }
    output[j] = '\0';

    JSStringRef result_str = JSStringCreateWithUTF8CString(output);
    JSValueRef result = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    free(clean_input);
    free(output);

    return result;
}

// URL data structure
typedef struct {
    char protocol[64];
    char hostname[256];
    char port[16];
    char pathname[1024];
    char search[1024];
    char hash[256];
    char host[272];  // hostname + : + port
    char href[2048];
    char origin[320];  // protocol + // + host
} URLData;

// URL finalizer
static void url_finalize(JSObjectRef object) {
    URLData* data = JSObjectGetPrivate(object);
    if (data) {
        free(data);
    }
}

// URL.toString() method
static JSValueRef js_url_tostring(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                   JSObjectRef thisObject, size_t argumentCount __attribute__((unused)),
                                   const JSValueRef arguments[] __attribute__((unused)),
                                   JSValueRef* exception __attribute__((unused))) {
    URLData* data = JSObjectGetPrivate(thisObject);
    if (!data) return JSValueMakeUndefined(ctx);

    JSStringRef result_str = JSStringCreateWithUTF8CString(data->href);
    JSValueRef result = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    return result;
}

// URL.toJSON() method
static JSValueRef js_url_tojson(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                 JSObjectRef thisObject, size_t argumentCount __attribute__((unused)),
                                 const JSValueRef arguments[] __attribute__((unused)),
                                 JSValueRef* exception __attribute__((unused))) {
    return js_url_tostring(ctx, function, thisObject, argumentCount, arguments, exception);
}

// URL constructor
static JSObjectRef js_url_constructor(JSContextRef ctx, JSObjectRef constructor __attribute__((unused)),
                                       size_t argumentCount, const JSValueRef arguments[],
                                       JSValueRef* exception) {
    if (argumentCount < 1 || !JSValueIsString(ctx, arguments[0])) {
        JSStringRef error = JSStringCreateWithUTF8CString("URL constructor requires a URL string");
        *exception = JSValueMakeString(ctx, error);
        JSStringRelease(error);
        return NULL;
    }

    // Get URL string
    JSStringRef url_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return NULL;

    size_t max_size = JSStringGetMaximumUTF8CStringSize(url_str);
    char* url_input = malloc(max_size);
    JSStringGetUTF8CString(url_str, url_input, max_size);
    JSStringRelease(url_str);

    // Create private data
    URLData* data = malloc(sizeof(URLData));
    memset(data, 0, sizeof(URLData));

    // Parse URL components (using similar logic to js_url_parse)
    char* current = url_input;

    // Parse protocol
    char* protocol_end = strstr(current, "://");
    if (protocol_end) {
        size_t protocol_len = protocol_end - current;
        strncpy(data->protocol, current, protocol_len);
        data->protocol[protocol_len] = '\0';
        strcat(data->protocol, ":");
        current = protocol_end + 3;
    }

    // Parse host (hostname + port)
    char* path_start = strchr(current, '/');
    char* query_start = strchr(current, '?');
    char* hash_start = strchr(current, '#');

    char* host_end = path_start;
    if (!host_end || (query_start && query_start < host_end)) host_end = query_start;
    if (!host_end || (hash_start && hash_start < host_end)) host_end = hash_start;
    if (!host_end) host_end = current + strlen(current);

    size_t host_len = host_end - current;
    strncpy(data->host, current, host_len);
    data->host[host_len] = '\0';

    // Parse hostname and port from host
    char* port_sep = strchr(data->host, ':');
    if (port_sep) {
        size_t hostname_len = port_sep - data->host;
        strncpy(data->hostname, data->host, hostname_len);
        data->hostname[hostname_len] = '\0';
        strcpy(data->port, port_sep + 1);
    } else {
        strcpy(data->hostname, data->host);
    }

    current = host_end;

    // Parse pathname
    if (*current == '/') {
        char* query_or_hash = strchr(current, '?');
        if (!query_or_hash) query_or_hash = strchr(current, '#');
        if (query_or_hash) {
            size_t path_len = query_or_hash - current;
            strncpy(data->pathname, current, path_len);
            data->pathname[path_len] = '\0';
            current = query_or_hash;
        } else {
            strcpy(data->pathname, current);
            current += strlen(current);
        }
    } else {
        strcpy(data->pathname, "/");
    }

    // Parse search (query)
    if (*current == '?') {
        char* hash_pos = strchr(current, '#');
        if (hash_pos) {
            size_t search_len = hash_pos - current;
            strncpy(data->search, current, search_len);
            data->search[search_len] = '\0';
            current = hash_pos;
        } else {
            strcpy(data->search, current);
            current += strlen(current);
        }
    }

    // Parse hash
    if (*current == '#') {
        strcpy(data->hash, current);
    }

    // Build href (full URL)
    snprintf(data->href, sizeof(data->href), "%s//%s%s%s%s",
             data->protocol, data->host, data->pathname, data->search, data->hash);

    // Build origin (protocol + // + host)
    snprintf(data->origin, sizeof(data->origin), "%s//%s", data->protocol, data->host);

    free(url_input);

    // Create class with finalizer
    JSClassDefinition class_def = kJSClassDefinitionEmpty;
    class_def.finalize = url_finalize;
    JSClassRef class = JSClassCreate(&class_def);
    JSObjectRef instance = JSObjectMake(ctx, class, data);
    JSClassRelease(class);

    // Add properties (read-only)
    JSStringRef href_name = JSStringCreateWithUTF8CString("href");
    JSStringRef href_val = JSStringCreateWithUTF8CString(data->href);
    JSObjectSetProperty(ctx, instance, href_name, JSValueMakeString(ctx, href_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(href_name);
    JSStringRelease(href_val);

    JSStringRef protocol_name = JSStringCreateWithUTF8CString("protocol");
    JSStringRef protocol_val = JSStringCreateWithUTF8CString(data->protocol);
    JSObjectSetProperty(ctx, instance, protocol_name, JSValueMakeString(ctx, protocol_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(protocol_name);
    JSStringRelease(protocol_val);

    JSStringRef hostname_name = JSStringCreateWithUTF8CString("hostname");
    JSStringRef hostname_val = JSStringCreateWithUTF8CString(data->hostname);
    JSObjectSetProperty(ctx, instance, hostname_name, JSValueMakeString(ctx, hostname_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(hostname_name);
    JSStringRelease(hostname_val);

    JSStringRef port_name = JSStringCreateWithUTF8CString("port");
    JSStringRef port_val = JSStringCreateWithUTF8CString(data->port);
    JSObjectSetProperty(ctx, instance, port_name, JSValueMakeString(ctx, port_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(port_name);
    JSStringRelease(port_val);

    JSStringRef pathname_name = JSStringCreateWithUTF8CString("pathname");
    JSStringRef pathname_val = JSStringCreateWithUTF8CString(data->pathname);
    JSObjectSetProperty(ctx, instance, pathname_name, JSValueMakeString(ctx, pathname_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(pathname_name);
    JSStringRelease(pathname_val);

    JSStringRef search_name = JSStringCreateWithUTF8CString("search");
    JSStringRef search_val = JSStringCreateWithUTF8CString(data->search);
    JSObjectSetProperty(ctx, instance, search_name, JSValueMakeString(ctx, search_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(search_name);
    JSStringRelease(search_val);

    JSStringRef hash_name = JSStringCreateWithUTF8CString("hash");
    JSStringRef hash_val = JSStringCreateWithUTF8CString(data->hash);
    JSObjectSetProperty(ctx, instance, hash_name, JSValueMakeString(ctx, hash_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(hash_name);
    JSStringRelease(hash_val);

    JSStringRef host_name = JSStringCreateWithUTF8CString("host");
    JSStringRef host_val = JSStringCreateWithUTF8CString(data->host);
    JSObjectSetProperty(ctx, instance, host_name, JSValueMakeString(ctx, host_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(host_name);
    JSStringRelease(host_val);

    JSStringRef origin_name = JSStringCreateWithUTF8CString("origin");
    JSStringRef origin_val = JSStringCreateWithUTF8CString(data->origin);
    JSObjectSetProperty(ctx, instance, origin_name, JSValueMakeString(ctx, origin_val),
                        kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(origin_name);
    JSStringRelease(origin_val);

    // Add toString method
    JSStringRef tostring_name = JSStringCreateWithUTF8CString("toString");
    JSObjectRef tostring_func = JSObjectMakeFunctionWithCallback(ctx, tostring_name, js_url_tostring);
    JSObjectSetProperty(ctx, instance, tostring_name, tostring_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(tostring_name);

    // Add toJSON method
    JSStringRef tojson_name = JSStringCreateWithUTF8CString("toJSON");
    JSObjectRef tojson_func = JSObjectMakeFunctionWithCallback(ctx, tojson_name, js_url_tojson);
    JSObjectSetProperty(ctx, instance, tojson_name, tojson_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(tojson_name);

    return instance;
}

// URLSearchParams data structure
typedef struct URLSearchParam {
    char* key;
    char* value;
    struct URLSearchParam* next;
} URLSearchParam;

typedef struct {
    URLSearchParam* head;
    size_t count;
} URLSearchParamsData;

// URLSearchParams finalizer
static void url_search_params_finalize(JSObjectRef object) {
    URLSearchParamsData* data = JSObjectGetPrivate(object);
    if (data) {
        URLSearchParam* current = data->head;
        while (current) {
            URLSearchParam* next = current->next;
            free(current->key);
            free(current->value);
            free(current);
            current = next;
        }
        free(data);
    }
}

// URLSearchParams.append(key, value)
static JSValueRef js_url_search_params_append(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                                JSObjectRef thisObject, size_t argumentCount,
                                                const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) return JSValueMakeUndefined(ctx);

    URLSearchParamsData* data = JSObjectGetPrivate(thisObject);
    if (!data) return JSValueMakeUndefined(ctx);

    // Get key and value
    JSStringRef key_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);
    JSStringRef val_str = JSValueToStringCopy(ctx, arguments[1], exception);
    if (*exception) { JSStringRelease(key_str); return JSValueMakeUndefined(ctx); }

    size_t key_size = JSStringGetMaximumUTF8CStringSize(key_str);
    char* key = malloc(key_size);
    JSStringGetUTF8CString(key_str, key, key_size);
    JSStringRelease(key_str);

    size_t val_size = JSStringGetMaximumUTF8CStringSize(val_str);
    char* value = malloc(val_size);
    JSStringGetUTF8CString(val_str, value, val_size);
    JSStringRelease(val_str);

    // Create new param
    URLSearchParam* param = malloc(sizeof(URLSearchParam));
    param->key = key;
    param->value = value;
    param->next = NULL;

    // Append to list
    if (!data->head) {
        data->head = param;
    } else {
        URLSearchParam* current = data->head;
        while (current->next) current = current->next;
        current->next = param;
    }
    data->count++;

    return JSValueMakeUndefined(ctx);
}

// URLSearchParams.get(key)
static JSValueRef js_url_search_params_get(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                            JSObjectRef thisObject, size_t argumentCount,
                                            const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) return JSValueMakeNull(ctx);

    URLSearchParamsData* data = JSObjectGetPrivate(thisObject);
    if (!data) return JSValueMakeNull(ctx);

    JSStringRef key_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeNull(ctx);

    size_t key_size = JSStringGetMaximumUTF8CStringSize(key_str);
    char* key = malloc(key_size);
    JSStringGetUTF8CString(key_str, key, key_size);
    JSStringRelease(key_str);

    // Find first matching key
    URLSearchParam* current = data->head;
    while (current) {
        if (strcmp(current->key, key) == 0) {
            JSStringRef result_str = JSStringCreateWithUTF8CString(current->value);
            JSValueRef result = JSValueMakeString(ctx, result_str);
            JSStringRelease(result_str);
            free(key);
            return result;
        }
        current = current->next;
    }

    free(key);
    return JSValueMakeNull(ctx);
}

// URLSearchParams.has(key)
static JSValueRef js_url_search_params_has(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                            JSObjectRef thisObject, size_t argumentCount,
                                            const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) return JSValueMakeBoolean(ctx, false);

    URLSearchParamsData* data = JSObjectGetPrivate(thisObject);
    if (!data) return JSValueMakeBoolean(ctx, false);

    JSStringRef key_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeBoolean(ctx, false);

    size_t key_size = JSStringGetMaximumUTF8CStringSize(key_str);
    char* key = malloc(key_size);
    JSStringGetUTF8CString(key_str, key, key_size);
    JSStringRelease(key_str);

    // Find key
    URLSearchParam* current = data->head;
    while (current) {
        if (strcmp(current->key, key) == 0) {
            free(key);
            return JSValueMakeBoolean(ctx, true);
        }
        current = current->next;
    }

    free(key);
    return JSValueMakeBoolean(ctx, false);
}

// URLSearchParams.toString()
static JSValueRef js_url_search_params_tostring(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                                 JSObjectRef thisObject, size_t argumentCount __attribute__((unused)),
                                                 const JSValueRef arguments[] __attribute__((unused)),
                                                 JSValueRef* exception __attribute__((unused))) {
    URLSearchParamsData* data = JSObjectGetPrivate(thisObject);
    if (!data || !data->head) {
        return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(""));
    }

    // Build query string
    char* result = malloc(4096);
    result[0] = '\0';
    int first = 1;

    URLSearchParam* current = data->head;
    while (current) {
        if (!first) strcat(result, "&");
        strcat(result, current->key);
        strcat(result, "=");
        strcat(result, current->value);
        first = 0;
        current = current->next;
    }

    JSStringRef result_str = JSStringCreateWithUTF8CString(result);
    JSValueRef js_result = JSValueMakeString(ctx, result_str);
    JSStringRelease(result_str);
    free(result);

    return js_result;
}

// URLSearchParams constructor
static JSObjectRef js_url_search_params_constructor(JSContextRef ctx, JSObjectRef constructor __attribute__((unused)),
                                                     size_t argumentCount,
                                                     const JSValueRef arguments[], JSValueRef* exception) {
    // Create private data
    URLSearchParamsData* data = malloc(sizeof(URLSearchParamsData));
    data->head = NULL;
    data->count = 0;

    // Parse input if provided
    if (argumentCount > 0 && JSValueIsString(ctx, arguments[0])) {
        JSStringRef input_str = JSValueToStringCopy(ctx, arguments[0], exception);
        if (!*exception) {
            size_t input_size = JSStringGetMaximumUTF8CStringSize(input_str);
            char* input = malloc(input_size);
            JSStringGetUTF8CString(input_str, input, input_size);
            JSStringRelease(input_str);

            // Remove leading '?' if present
            char* query = input;
            if (query[0] == '?') query++;

            // Parse key=value pairs
            char* pair = strtok(query, "&");
            while (pair) {
                char* eq = strchr(pair, '=');
                if (eq) {
                    *eq = '\0';
                    char* key = pair;
                    char* value = eq + 1;

                    URLSearchParam* param = malloc(sizeof(URLSearchParam));
                    param->key = strdup(key);
                    param->value = strdup(value);
                    param->next = NULL;

                    if (!data->head) {
                        data->head = param;
                    } else {
                        URLSearchParam* current = data->head;
                        while (current->next) current = current->next;
                        current->next = param;
                    }
                    data->count++;
                }
                pair = strtok(NULL, "&");
            }

            free(input);
        }
    }

    // Create class with finalizer
    JSClassDefinition class_def = kJSClassDefinitionEmpty;
    class_def.finalize = url_search_params_finalize;
    JSClassRef class = JSClassCreate(&class_def);
    JSObjectRef instance = JSObjectMake(ctx, class, data);
    JSClassRelease(class);

    // Add methods
    JSStringRef append_name = JSStringCreateWithUTF8CString("append");
    JSObjectRef append_func = JSObjectMakeFunctionWithCallback(ctx, append_name, js_url_search_params_append);
    JSObjectSetProperty(ctx, instance, append_name, append_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(append_name);

    JSStringRef get_name = JSStringCreateWithUTF8CString("get");
    JSObjectRef get_func = JSObjectMakeFunctionWithCallback(ctx, get_name, js_url_search_params_get);
    JSObjectSetProperty(ctx, instance, get_name, get_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(get_name);

    JSStringRef has_name = JSStringCreateWithUTF8CString("has");
    JSObjectRef has_func = JSObjectMakeFunctionWithCallback(ctx, has_name, js_url_search_params_has);
    JSObjectSetProperty(ctx, instance, has_name, has_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(has_name);

    JSStringRef tostring_name = JSStringCreateWithUTF8CString("toString");
    JSObjectRef tostring_func = JSObjectMakeFunctionWithCallback(ctx, tostring_name, js_url_search_params_tostring);
    JSObjectSetProperty(ctx, instance, tostring_name, tostring_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(tostring_name);

    return instance;
}

// AbortSignal data structure
typedef struct {
    int aborted;
    JSObjectRef reason;
    JSObjectRef onabort_callback;
    JSContextRef ctx;
} AbortSignalData;

// AbortSignal finalizer
static void abort_signal_finalize(JSObjectRef object) {
    AbortSignalData* data = JSObjectGetPrivate(object);
    if (data) {
        if (data->reason) JSValueUnprotect(data->ctx, data->reason);
        if (data->onabort_callback) JSValueUnprotect(data->ctx, data->onabort_callback);
        free(data);
    }
}

// AbortController data structure
typedef struct {
    JSObjectRef signal;
    JSContextRef ctx;
} AbortControllerData;

// AbortController finalizer
static void abort_controller_finalize(JSObjectRef object) {
    AbortControllerData* data = JSObjectGetPrivate(object);
    if (data) {
        if (data->signal) JSValueUnprotect(data->ctx, data->signal);
        free(data);
    }
}

// AbortController.abort(reason) method
static JSValueRef js_abort_controller_abort(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                             JSObjectRef thisObject, size_t argumentCount,
                                             const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    AbortControllerData* controller_data = JSObjectGetPrivate(thisObject);
    if (!controller_data || !controller_data->signal) {
        return JSValueMakeUndefined(ctx);
    }

    // Get signal's private data
    AbortSignalData* signal_data = JSObjectGetPrivate(controller_data->signal);
    if (!signal_data) return JSValueMakeUndefined(ctx);

    // Set aborted to true
    signal_data->aborted = 1;

    // Set reason if provided
    if (argumentCount > 0) {
        if (signal_data->reason) {
            JSValueUnprotect(ctx, signal_data->reason);
        }
        signal_data->reason = JSValueToObject(ctx, arguments[0], NULL);
        if (signal_data->reason) {
            JSValueProtect(ctx, signal_data->reason);
        }
    }

    // Update aborted property on signal object
    JSStringRef aborted_name = JSStringCreateWithUTF8CString("aborted");
    JSObjectSetProperty(ctx, controller_data->signal, aborted_name, JSValueMakeBoolean(ctx, true),
                        kJSPropertyAttributeNone, NULL);
    JSStringRelease(aborted_name);

    // Call onabort callback if set (read from JS object property)
    JSStringRef onabort_name = JSStringCreateWithUTF8CString("onabort");
    JSValueRef onabort_val = JSObjectGetProperty(ctx, controller_data->signal, onabort_name, NULL);
    JSStringRelease(onabort_name);

    if (onabort_val && JSValueIsObject(ctx, onabort_val)) {
        JSObjectRef onabort_func = JSValueToObject(ctx, onabort_val, NULL);
        if (onabort_func && JSObjectIsFunction(ctx, onabort_func)) {
            JSObjectCallAsFunction(ctx, onabort_func, controller_data->signal, 0, NULL, NULL);
        }
    }

    return JSValueMakeUndefined(ctx);
}

// AbortSignal constructor (should not be called directly, but needed for internal use)
static JSObjectRef create_abort_signal(JSContextRef ctx) {
    // Create private data
    AbortSignalData* data = malloc(sizeof(AbortSignalData));
    data->aborted = 0;
    data->reason = NULL;
    data->onabort_callback = NULL;
    data->ctx = ctx;

    // Create class with finalizer
    JSClassDefinition class_def = kJSClassDefinitionEmpty;
    class_def.finalize = abort_signal_finalize;
    JSClassRef class = JSClassCreate(&class_def);
    JSObjectRef instance = JSObjectMake(ctx, class, data);
    JSClassRelease(class);

    // Add aborted property
    JSStringRef aborted_name = JSStringCreateWithUTF8CString("aborted");
    JSObjectSetProperty(ctx, instance, aborted_name, JSValueMakeBoolean(ctx, false),
                        kJSPropertyAttributeNone, NULL);
    JSStringRelease(aborted_name);

    // Add reason property
    JSStringRef reason_name = JSStringCreateWithUTF8CString("reason");
    JSObjectSetProperty(ctx, instance, reason_name, JSValueMakeUndefined(ctx),
                        kJSPropertyAttributeNone, NULL);
    JSStringRelease(reason_name);

    // Add onabort property (initially null)
    JSStringRef onabort_name = JSStringCreateWithUTF8CString("onabort");
    JSObjectSetProperty(ctx, instance, onabort_name, JSValueMakeNull(ctx),
                        kJSPropertyAttributeNone, NULL);
    JSStringRelease(onabort_name);

    return instance;
}

// AbortController constructor
static JSObjectRef js_abort_controller_constructor(JSContextRef ctx, JSObjectRef constructor __attribute__((unused)),
                                                    size_t argumentCount __attribute__((unused)),
                                                    const JSValueRef arguments[] __attribute__((unused)),
                                                    JSValueRef* exception __attribute__((unused))) {
    // Create signal
    JSObjectRef signal = create_abort_signal(ctx);

    // Create private data
    AbortControllerData* data = malloc(sizeof(AbortControllerData));
    data->signal = signal;
    data->ctx = ctx;
    JSValueProtect(ctx, signal);

    // Create class with finalizer
    JSClassDefinition class_def = kJSClassDefinitionEmpty;
    class_def.finalize = abort_controller_finalize;
    JSClassRef class = JSClassCreate(&class_def);
    JSObjectRef instance = JSObjectMake(ctx, class, data);
    JSClassRelease(class);

    // Add signal property (read-only)
    JSStringRef signal_name = JSStringCreateWithUTF8CString("signal");
    JSObjectSetProperty(ctx, instance, signal_name, signal, kJSPropertyAttributeReadOnly, NULL);
    JSStringRelease(signal_name);

    // Add abort method
    JSStringRef abort_name = JSStringCreateWithUTF8CString("abort");
    JSObjectRef abort_func = JSObjectMakeFunctionWithCallback(ctx, abort_name, js_abort_controller_abort);
    JSObjectSetProperty(ctx, instance, abort_name, abort_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(abort_name);

    return instance;
}

// Console.log implementation (stdout)
static JSValueRef js_console_log(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception) {
    for (size_t i = 0; i < argumentCount; i++) {
        JSStringRef js_string = JSValueToStringCopy(ctx, arguments[i], exception);
        if (*exception) return JSValueMakeUndefined(ctx);

        size_t max_size = JSStringGetMaximumUTF8CStringSize(js_string);
        char* buffer = malloc(max_size);
        JSStringGetUTF8CString(js_string, buffer, max_size);

        printf("%s", buffer);
        if (i < argumentCount - 1) printf(" ");

        free(buffer);
        JSStringRelease(js_string);
    }
    printf("\n");
    fflush(stdout);
    return JSValueMakeUndefined(ctx);
}

// Console.error/warn implementation (stderr)
static JSValueRef js_console_error(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                    JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                    const JSValueRef arguments[], JSValueRef* exception) {
    for (size_t i = 0; i < argumentCount; i++) {
        JSStringRef js_string = JSValueToStringCopy(ctx, arguments[i], exception);
        if (*exception) return JSValueMakeUndefined(ctx);

        size_t max_size = JSStringGetMaximumUTF8CStringSize(js_string);
        char* buffer = malloc(max_size);
        JSStringGetUTF8CString(js_string, buffer, max_size);

        fprintf(stderr, "%s", buffer);
        if (i < argumentCount - 1) fprintf(stderr, " ");

        free(buffer);
        JSStringRelease(js_string);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
    return JSValueMakeUndefined(ctx);
}

// HTTP write callback
static size_t http_write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t real_size = size * nmemb;
    HttpResponse* response = (HttpResponse*)userp;

    char* ptr = realloc(response->data, response->size + real_size + 1);
    if (!ptr) return 0;

    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, real_size);
    response->size += real_size;
    response->data[response->size] = 0;

    return real_size;
}

// Response.text() implementation
static JSValueRef js_response_text(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                    JSObjectRef thisObject, size_t argumentCount __attribute__((unused)),
                                    const JSValueRef arguments[] __attribute__((unused)), JSValueRef* exception __attribute__((unused))) {
    JSStringRef body_name = JSStringCreateWithUTF8CString("_body");
    JSValueRef body_value = JSObjectGetProperty(ctx, thisObject, body_name, NULL);
    JSStringRelease(body_name);

    // Store body value in global temporarily
    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef temp_name = JSStringCreateWithUTF8CString("__temp_body");
    JSObjectSetProperty(ctx, global, temp_name, body_value, kJSPropertyAttributeNone, NULL);
    JSStringRelease(temp_name);

    // Create promise using eval
    JSStringRef code = JSStringCreateWithUTF8CString("Promise.resolve(__temp_body)");
    JSValueRef result = JSEvaluateScript(ctx, code, NULL, NULL, 1, NULL);
    JSStringRelease(code);

    return result;
}

// Response.json() implementation
static JSValueRef js_response_json(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                    JSObjectRef thisObject, size_t argumentCount __attribute__((unused)),
                                    const JSValueRef arguments[] __attribute__((unused)), JSValueRef* exception) {
    JSStringRef body_name = JSStringCreateWithUTF8CString("_body");
    JSValueRef body_value = JSObjectGetProperty(ctx, thisObject, body_name, NULL);
    JSStringRelease(body_name);

    // Store body in global temporarily
    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef temp_name = JSStringCreateWithUTF8CString("__temp_body");
    JSObjectSetProperty(ctx, global, temp_name, body_value, kJSPropertyAttributeNone, NULL);
    JSStringRelease(temp_name);

    // Parse and return promise
    JSStringRef code = JSStringCreateWithUTF8CString("Promise.resolve(JSON.parse(__temp_body))");
    JSValueRef result = JSEvaluateScript(ctx, code, NULL, NULL, 1, exception);
    JSStringRelease(code);

    return result;
}

// fetch() implementation
static JSValueRef js_fetch(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                           JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                           const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef url_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(url_str);
    char* url = malloc(max_size);
    JSStringGetUTF8CString(url_str, url, max_size);
    JSStringRelease(url_str);

    // Initialize response
    HttpResponse response = {0};
    response.data = malloc(1);
    response.size = 0;

    // Initialize curl
    CURL* curl = curl_easy_init();
    if (!curl) {
        free(url);
        free(response.data);
        JSStringRef error_str = JSStringCreateWithUTF8CString("Failed to initialize HTTP client");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "krandog/0.1.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        free(url);
        free(response.data);
        JSStringRef error_str = JSStringCreateWithUTF8CString(curl_easy_strerror(res));
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    long status_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    response.status = (int)status_code;

    curl_easy_cleanup(curl);
    free(url);

    // Create Response object
    JSObjectRef response_obj = JSObjectMake(ctx, NULL, NULL);

    // response.status
    JSStringRef status_name = JSStringCreateWithUTF8CString("status");
    JSObjectSetProperty(ctx, response_obj, status_name, JSValueMakeNumber(ctx, response.status), kJSPropertyAttributeNone, NULL);
    JSStringRelease(status_name);

    // response.ok
    JSStringRef ok_name = JSStringCreateWithUTF8CString("ok");
    JSObjectSetProperty(ctx, response_obj, ok_name, JSValueMakeBoolean(ctx, response.status >= 200 && response.status < 300), kJSPropertyAttributeNone, NULL);
    JSStringRelease(ok_name);

    // response._body (internal)
    JSStringRef body_name = JSStringCreateWithUTF8CString("_body");
    JSStringRef body_str = JSStringCreateWithUTF8CString(response.data);
    JSObjectSetProperty(ctx, response_obj, body_name, JSValueMakeString(ctx, body_str), kJSPropertyAttributeNone, NULL);
    JSStringRelease(body_name);
    JSStringRelease(body_str);
    free(response.data);

    // response.text()
    JSStringRef text_name = JSStringCreateWithUTF8CString("text");
    JSObjectRef text_func = JSObjectMakeFunctionWithCallback(ctx, text_name, js_response_text);
    JSObjectSetProperty(ctx, response_obj, text_name, text_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(text_name);

    // response.json()
    JSStringRef json_name = JSStringCreateWithUTF8CString("json");
    JSObjectRef json_func = JSObjectMakeFunctionWithCallback(ctx, json_name, js_response_json);
    JSObjectSetProperty(ctx, response_obj, json_name, json_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(json_name);

    // Store response in global temporarily and return promise
    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef temp_name = JSStringCreateWithUTF8CString("__temp_response");
    JSObjectSetProperty(ctx, global, temp_name, response_obj, kJSPropertyAttributeNone, NULL);
    JSStringRelease(temp_name);

    JSStringRef code = JSStringCreateWithUTF8CString("Promise.resolve(__temp_response)");
    JSValueRef result = JSEvaluateScript(ctx, code, NULL, NULL, 1, NULL);
    JSStringRelease(code);

    return result;
}

// Parse HTTP request headers
static void parse_http_request(const char* buffer, char* method, char* path, char* version) {
    sscanf(buffer, "%s %s %s", method, path, version);
}

// TLS I/O Callbacks for SecureTransport
static OSStatus tls_read_callback(SSLConnectionRef connection, void* data, size_t* dataLength) {
    int socket_fd = *(int*)connection;
    ssize_t result = recv(socket_fd, data, *dataLength, 0);

    if (result > 0) {
        *dataLength = result;
        return noErr;
    } else if (result == 0) {
        *dataLength = 0;
        return errSSLClosedGraceful;
    } else {
        *dataLength = 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return errSSLWouldBlock;
        }
        return errSecIO;
    }
}

static OSStatus tls_write_callback(SSLConnectionRef connection, const void* data, size_t* dataLength) {
    int socket_fd = *(int*)connection;
    ssize_t result = send(socket_fd, data, *dataLength, 0);

    if (result > 0) {
        *dataLength = result;
        return noErr;
    } else if (result == 0) {
        *dataLength = 0;
        return errSSLClosedGraceful;
    } else {
        *dataLength = 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return errSSLWouldBlock;
        }
        return errSecIO;
    }
}

// Create TLS context
static TlsContext* create_tls_context(int socket_fd, int is_server, SecIdentityRef identity) {
    TlsContext* ctx = malloc(sizeof(TlsContext));
    if (!ctx) return NULL;

    memset(ctx, 0, sizeof(TlsContext));
    ctx->socket_fd = socket_fd;
    ctx->is_server = is_server;
    ctx->state = TLS_STATE_NONE;
    ctx->identity = identity;
    if (identity) CFRetain(identity);

    // Create SSL context
    ctx->ssl_ctx = SSLCreateContext(NULL, is_server ? kSSLServerSide : kSSLClientSide, kSSLStreamType);
    if (!ctx->ssl_ctx) {
        free(ctx);
        return NULL;
    }

    // Set I/O callbacks
    SSLSetIOFuncs(ctx->ssl_ctx, tls_read_callback, tls_write_callback);
    SSLSetConnection(ctx->ssl_ctx, &ctx->socket_fd);

    // Set TLS 1.2+ only
    SSLSetProtocolVersionMin(ctx->ssl_ctx, kTLSProtocol12);

    // Set identity for server
    if (is_server && identity) {
        CFArrayRef certs = CFArrayCreate(NULL, (const void**)&identity, 1, &kCFTypeArrayCallBacks);
        SSLSetCertificate(ctx->ssl_ctx, certs);
        CFRelease(certs);

        // For server, don't require client certificate
        SSLSetClientSideAuthenticate(ctx->ssl_ctx, kNeverAuthenticate);
    }

    return ctx;
}

// Destroy TLS context
static void destroy_tls_context(TlsContext* ctx) {
    if (!ctx) return;

    if (ctx->ssl_ctx) {
        SSLClose(ctx->ssl_ctx);
        CFRelease(ctx->ssl_ctx);
    }

    if (ctx->identity) {
        CFRelease(ctx->identity);
    }

    if (ctx->pending_write_data) {
        free(ctx->pending_write_data);
    }

    free(ctx);
}

// Perform TLS handshake
static int tls_handshake(TlsContext* ctx) {
    fprintf(stderr, "[DEBUG] tls_handshake: state=%d\n", ctx->state);
    if (ctx->state == TLS_STATE_CONNECTED) return 0;

    ctx->state = TLS_STATE_HANDSHAKING;
    fprintf(stderr, "[DEBUG] About to call SSLHandshake\n");
    OSStatus status = SSLHandshake(ctx->ssl_ctx);
    fprintf(stderr, "[DEBUG] SSLHandshake returned: %d\n", (int)status);

    if (status == noErr) {
        ctx->state = TLS_STATE_CONNECTED;
        return 0;
    } else if (status == errSSLWouldBlock) {
        fprintf(stderr, "[DEBUG] Would block\n");
        return -1;  // Need more data
    } else {
        fprintf(stderr, "[DEBUG] Handshake error: %d\n", (int)status);
        ctx->state = TLS_STATE_CLOSED;
        return -2;  // Error
    }
}

// Read decrypted data
static ssize_t tls_read(TlsContext* ctx, void* buffer, size_t length) {
    if (ctx->state != TLS_STATE_CONNECTED) return -1;

    size_t processed = 0;
    OSStatus status = SSLRead(ctx->ssl_ctx, buffer, length, &processed);

    if (status == noErr || status == errSSLWouldBlock) {
        return processed;
    }

    return -1;
}

// Write encrypted data
static ssize_t tls_write(TlsContext* ctx, const void* buffer, size_t length) {
    if (ctx->state != TLS_STATE_CONNECTED) return -1;

    size_t processed = 0;
    OSStatus status = SSLWrite(ctx->ssl_ctx, buffer, length, &processed);

    if (status == noErr || status == errSSLWouldBlock) {
        return processed;
    }

    return -1;
}

// Load identity from .p12/.pfx file
static SecIdentityRef load_identity_from_pfx(const char* pfx_data, size_t pfx_len, const char* passphrase) {
    CFDataRef pfx_cf = CFDataCreate(NULL, (const UInt8*)pfx_data, pfx_len);
    if (!pfx_cf) return NULL;

    CFStringRef pass_cf = NULL;
    if (passphrase) {
        pass_cf = CFStringCreateWithCString(NULL, passphrase, kCFStringEncodingUTF8);
    }

    const void* keys[] = { kSecImportExportPassphrase };
    const void* values[] = { pass_cf ? pass_cf : CFSTR("") };
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1,
                                                 &kCFTypeDictionaryKeyCallBacks,
                                                 &kCFTypeDictionaryValueCallBacks);

    CFArrayRef items = NULL;
    OSStatus status = SecPKCS12Import(pfx_cf, options, &items);

    CFRelease(pfx_cf);
    if (pass_cf) CFRelease(pass_cf);
    CFRelease(options);

    if (status != noErr || !items || CFArrayGetCount(items) == 0) {
        if (items) CFRelease(items);
        return NULL;
    }

    CFDictionaryRef item = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(item, kSecImportItemIdentity);

    if (identity) CFRetain(identity);
    CFRelease(items);

    return identity;
}

// serve() implementation - start HTTP server
static JSValueRef js_serve(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                          JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                          const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("serve() requires port and handler");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    int port = (int)JSValueToNumber(ctx, arguments[0], NULL);
    JSObjectRef handler = JSValueToObject(ctx, arguments[1], NULL);

    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("Failed to create socket");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Set socket options
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Set non-blocking
    fcntl(server_fd, F_SETFL, O_NONBLOCK);

    // Bind socket
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        close(server_fd);
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Failed to bind to port %d", port);
        JSStringRef error_str = JSStringCreateWithUTF8CString(error_msg);
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Listen
    if (listen(server_fd, 10) < 0) {
        close(server_fd);
        JSStringRef error_str = JSStringCreateWithUTF8CString("Failed to listen on socket");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Add to server list
    HttpServer* server = malloc(sizeof(HttpServer));
    server->socket_fd = server_fd;
    server->port = port;
    server->handler = handler;
    server->next = server_list;
    server_list = server;
    JSValueProtect(global_ctx, handler);

    printf("Server listening on http://localhost:%d\n", port);
    fflush(stdout);

    return JSValueMakeUndefined(ctx);
}

// serve_https() implementation - start HTTPS server
static JSValueRef js_serve_https(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                 JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                 const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 3) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("serve_https() requires port, options, and handler");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    int port = (int)JSValueToNumber(ctx, arguments[0], NULL);
    JSObjectRef options = JSValueToObject(ctx, arguments[1], NULL);
    JSObjectRef handler = JSValueToObject(ctx, arguments[2], NULL);

    // Extract certificate data from options
    JSStringRef pfx_name = JSStringCreateWithUTF8CString("pfx");
    JSValueRef pfx_val = JSObjectGetProperty(ctx, options, pfx_name, NULL);
    JSStringRelease(pfx_name);

    if (JSValueIsUndefined(ctx, pfx_val)) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("options.pfx is required");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Get pfx data (should be Buffer/Uint8Array or string)
    char* pfx_data = NULL;
    size_t pfx_len = 0;

    JSObjectRef pfx_obj = JSValueToObject(ctx, pfx_val, NULL);
    JSStringRef length_name = JSStringCreateWithUTF8CString("length");
    JSValueRef length_val = JSObjectGetProperty(ctx, pfx_obj, length_name, NULL);
    JSStringRelease(length_name);

    if (!JSValueIsUndefined(ctx, length_val)) {
        pfx_len = (size_t)JSValueToNumber(ctx, length_val, NULL);
        pfx_data = malloc(pfx_len);

        for (size_t i = 0; i < pfx_len; i++) {
            JSValueRef byte_val = JSObjectGetPropertyAtIndex(ctx, pfx_obj, i, NULL);
            pfx_data[i] = (char)JSValueToNumber(ctx, byte_val, NULL);
        }
    } else {
        // Fallback: treat as string
        JSStringRef pfx_str = JSValueToStringCopy(ctx, pfx_val, NULL);
        pfx_len = JSStringGetMaximumUTF8CStringSize(pfx_str);
        pfx_data = malloc(pfx_len);
        JSStringGetUTF8CString(pfx_str, pfx_data, pfx_len);
        pfx_len = strlen(pfx_data);
        JSStringRelease(pfx_str);
    }

    // Get passphrase if provided
    char* passphrase = NULL;
    JSStringRef pass_name = JSStringCreateWithUTF8CString("passphrase");
    JSValueRef pass_val = JSObjectGetProperty(ctx, options, pass_name, NULL);
    JSStringRelease(pass_name);

    if (!JSValueIsUndefined(ctx, pass_val)) {
        JSStringRef pass_str = JSValueToStringCopy(ctx, pass_val, NULL);
        size_t max_size = JSStringGetMaximumUTF8CStringSize(pass_str);
        passphrase = malloc(max_size);
        JSStringGetUTF8CString(pass_str, passphrase, max_size);
        JSStringRelease(pass_str);
    }

    // Load identity from pfx
    SecIdentityRef identity = load_identity_from_pfx(pfx_data, pfx_len, passphrase);
    free(pfx_data);
    if (passphrase) free(passphrase);

    if (!identity) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("Failed to load certificate from pfx");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        CFRelease(identity);
        JSStringRef error_str = JSStringCreateWithUTF8CString("Failed to create socket");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Set socket options
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Set non-blocking
    fcntl(server_fd, F_SETFL, O_NONBLOCK);

    // Bind socket
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        close(server_fd);
        CFRelease(identity);
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Failed to bind to port %d", port);
        JSStringRef error_str = JSStringCreateWithUTF8CString(error_msg);
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Listen
    if (listen(server_fd, 10) < 0) {
        close(server_fd);
        CFRelease(identity);
        JSStringRef error_str = JSStringCreateWithUTF8CString("Failed to listen on socket");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Create TLS template context
    TlsContext* tls_template = malloc(sizeof(TlsContext));
    memset(tls_template, 0, sizeof(TlsContext));
    tls_template->identity = identity;

    // Add to HTTPS server list
    HttpsServer* server = malloc(sizeof(HttpsServer));
    server->socket_fd = server_fd;
    server->port = port;
    server->handler = handler;
    server->tls_template = tls_template;
    server->next = https_server_list;
    https_server_list = server;
    JSValueProtect(global_ctx, handler);

    printf("HTTPS server listening on https://localhost:%d\n", port);
    fflush(stdout);

    return JSValueMakeUndefined(ctx);
}

// test() function - register a test
static JSValueRef js_test(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                         JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                         const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("test() requires name and callback");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef name_str = JSValueToStringCopy(ctx, arguments[0], NULL);
    size_t max_size = JSStringGetMaximumUTF8CStringSize(name_str);
    char* name = malloc(max_size);
    JSStringGetUTF8CString(name_str, name, max_size);
    JSStringRelease(name_str);

    JSObjectRef callback = JSValueToObject(ctx, arguments[1], NULL);

    Test* test = malloc(sizeof(Test));
    test->name = name;
    test->callback = callback;
    test->next = test_list;
    test_list = test;
    test_count++;
    JSValueProtect(global_ctx, callback);

    return JSValueMakeUndefined(ctx);
}

// assert() function - basic assertion
static JSValueRef js_assert(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                           JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                           const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("Assertion failed");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    bool condition = JSValueToBoolean(ctx, arguments[0]);
    if (!condition) {
        const char* message = "Assertion failed";
        if (argumentCount >= 2) {
            JSStringRef msg_str = JSValueToStringCopy(ctx, arguments[1], NULL);
            size_t max_size = JSStringGetMaximumUTF8CStringSize(msg_str);
            char* msg = malloc(max_size);
            JSStringGetUTF8CString(msg_str, msg, max_size);
            JSStringRelease(msg_str);

            JSStringRef error_str = JSStringCreateWithUTF8CString(msg);
            *exception = JSValueMakeString(ctx, error_str);
            JSStringRelease(error_str);
            free(msg);
        } else {
            JSStringRef error_str = JSStringCreateWithUTF8CString(message);
            *exception = JSValueMakeString(ctx, error_str);
            JSStringRelease(error_str);
        }
    }

    return JSValueMakeUndefined(ctx);
}

// assertEqual() function - equality assertion
static JSValueRef js_assert_equal(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                  const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 2) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("assertEqual() requires two arguments");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    JSValueRef a = arguments[0];
    JSValueRef b = arguments[1];

    bool equal = JSValueIsStrictEqual(ctx, a, b);

    if (!equal) {
        JSStringRef a_str = JSValueToStringCopy(ctx, a, NULL);
        JSStringRef b_str = JSValueToStringCopy(ctx, b, NULL);

        size_t a_size = JSStringGetMaximumUTF8CStringSize(a_str);
        size_t b_size = JSStringGetMaximumUTF8CStringSize(b_str);

        char* a_val = malloc(a_size);
        char* b_val = malloc(b_size);

        JSStringGetUTF8CString(a_str, a_val, a_size);
        JSStringGetUTF8CString(b_str, b_val, b_size);

        char error_msg[2048];
        snprintf(error_msg, sizeof(error_msg), "Expected %s to equal %s", a_val, b_val);

        JSStringRef error_str = JSStringCreateWithUTF8CString(error_msg);
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);

        JSStringRelease(a_str);
        JSStringRelease(b_str);
        free(a_val);
        free(b_val);
    }

    return JSValueMakeUndefined(ctx);
}

// run() function - run all registered tests
static JSValueRef js_run_tests(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                               JSObjectRef thisObject __attribute__((unused)), size_t argumentCount __attribute__((unused)),
                               const JSValueRef arguments[] __attribute__((unused)), JSValueRef* exception __attribute__((unused))) {
    if (!test_list) {
        printf("No tests to run\n");
        return JSValueMakeUndefined(ctx);
    }

    printf("\nRunning %d tests...\n\n", test_count);

    // Reverse test list to run in order of registration
    Test* reversed = NULL;
    Test* current = test_list;
    while (current) {
        Test* next = current->next;
        current->next = reversed;
        reversed = current;
        current = next;
    }
    test_list = reversed;

    current = test_list;
    while (current) {
        JSValueRef exception_val = NULL;
        JSObjectCallAsFunction(global_ctx, current->callback, NULL, 0, NULL, &exception_val);

        if (exception_val) {
            JSStringRef js_error = JSValueToStringCopy(global_ctx, exception_val, NULL);
            size_t max_size = JSStringGetMaximumUTF8CStringSize(js_error);
            char* error_buffer = malloc(max_size);
            JSStringGetUTF8CString(js_error, error_buffer, max_size);
            printf("  \033[0;31m✗\033[0m %s\n    %s\n", current->name, error_buffer);
            free(error_buffer);
            JSStringRelease(js_error);
            test_failed++;
        } else {
            printf("  \033[0;32m✓\033[0m %s\n", current->name);
            test_passed++;
        }

        current = current->next;
    }

    printf("\n");
    if (test_failed == 0) {
        printf("\033[0;32m%d tests passed\033[0m\n", test_passed);
    } else {
        printf("\033[0;31m%d failed\033[0m, %d passed, %d total\n", test_failed, test_passed, test_count);
    }

    return JSValueMakeUndefined(ctx);
}

// process.exit
static JSValueRef js_process_exit(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                   JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                   const JSValueRef arguments[], JSValueRef* exception __attribute__((unused))) {
    int code = 0;
    if (argumentCount > 0) {
        code = (int)JSValueToNumber(ctx, arguments[0], NULL);
    }
    exit(code);
    return JSValueMakeUndefined(ctx);
}

// process.cwd
static JSValueRef js_process_cwd(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                  JSObjectRef thisObject __attribute__((unused)), size_t argumentCount __attribute__((unused)),
                                  const JSValueRef arguments[] __attribute__((unused)), JSValueRef* exception __attribute__((unused))) {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd))) {
        JSStringRef cwd_str = JSStringCreateWithUTF8CString(cwd);
        JSValueRef result = JSValueMakeString(ctx, cwd_str);
        JSStringRelease(cwd_str);
        return result;
    }
    return JSValueMakeUndefined(ctx);
}

// process.chdir
static JSValueRef js_process_chdir(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                    JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                    const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* path = malloc(max_size);
    JSStringGetUTF8CString(path_str, path, max_size);
    JSStringRelease(path_str);

    int result = chdir(path);
    free(path);

    if (result != 0) {
        JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot change directory");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
    }

    return JSValueMakeUndefined(ctx);
}

void setup_console(JSContextRef ctx, JSObjectRef global) {
    JSObjectRef console = JSObjectMake(ctx, NULL, NULL);

    // console.log
    JSStringRef log_name = JSStringCreateWithUTF8CString("log");
    JSObjectRef log_func = JSObjectMakeFunctionWithCallback(ctx, log_name, js_console_log);
    JSObjectSetProperty(ctx, console, log_name, log_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(log_name);

    // console.error
    JSStringRef error_name = JSStringCreateWithUTF8CString("error");
    JSObjectRef error_func = JSObjectMakeFunctionWithCallback(ctx, error_name, js_console_error);
    JSObjectSetProperty(ctx, console, error_name, error_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(error_name);

    // console.warn (same as error)
    JSStringRef warn_name = JSStringCreateWithUTF8CString("warn");
    JSObjectRef warn_func = JSObjectMakeFunctionWithCallback(ctx, warn_name, js_console_error);
    JSObjectSetProperty(ctx, console, warn_name, warn_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(warn_name);

    // console.debug (same as log)
    JSStringRef debug_name = JSStringCreateWithUTF8CString("debug");
    JSObjectRef debug_func = JSObjectMakeFunctionWithCallback(ctx, debug_name, js_console_log);
    JSObjectSetProperty(ctx, console, debug_name, debug_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(debug_name);

    JSStringRef console_name = JSStringCreateWithUTF8CString("console");
    JSObjectSetProperty(ctx, global, console_name, console, kJSPropertyAttributeNone, NULL);
    JSStringRelease(console_name);
}

void setup_process(JSContextRef ctx, JSObjectRef global) {
    JSObjectRef process = JSObjectMake(ctx, NULL, NULL);

    // process.argv
    JSValueRef* argv_values = malloc(sizeof(JSValueRef) * global_argc);
    for (int i = 0; i < global_argc; i++) {
        JSStringRef arg_str = JSStringCreateWithUTF8CString(global_argv[i]);
        argv_values[i] = JSValueMakeString(ctx, arg_str);
        JSStringRelease(arg_str);
    }
    JSObjectRef argv_array = JSObjectMakeArray(ctx, global_argc, argv_values, NULL);
    free(argv_values);

    JSStringRef argv_name = JSStringCreateWithUTF8CString("argv");
    JSObjectSetProperty(ctx, process, argv_name, argv_array, kJSPropertyAttributeNone, NULL);
    JSStringRelease(argv_name);

    // process.env
    JSObjectRef env = JSObjectMake(ctx, NULL, NULL);
    extern char** environ;
    for (char** env_ptr = environ; *env_ptr != NULL; env_ptr++) {
        char* env_str = *env_ptr;
        char* equals = strchr(env_str, '=');
        if (equals) {
            size_t key_len = equals - env_str;
            char* key = malloc(key_len + 1);
            strncpy(key, env_str, key_len);
            key[key_len] = '\0';

            char* value = equals + 1;

            JSStringRef key_js = JSStringCreateWithUTF8CString(key);
            JSStringRef value_js = JSStringCreateWithUTF8CString(value);
            JSObjectSetProperty(ctx, env, key_js, JSValueMakeString(ctx, value_js), kJSPropertyAttributeNone, NULL);
            JSStringRelease(key_js);
            JSStringRelease(value_js);
            free(key);
        }
    }

    JSStringRef env_name = JSStringCreateWithUTF8CString("env");
    JSObjectSetProperty(ctx, process, env_name, env, kJSPropertyAttributeNone, NULL);
    JSStringRelease(env_name);

    // process.platform
    JSStringRef platform_name = JSStringCreateWithUTF8CString("platform");
    JSStringRef platform_value = JSStringCreateWithUTF8CString("darwin");
    JSObjectSetProperty(ctx, process, platform_name, JSValueMakeString(ctx, platform_value), kJSPropertyAttributeNone, NULL);
    JSStringRelease(platform_name);
    JSStringRelease(platform_value);

    // process.version
    JSStringRef version_name = JSStringCreateWithUTF8CString("version");
    JSStringRef version_value = JSStringCreateWithUTF8CString("krandog-0.1.0");
    JSObjectSetProperty(ctx, process, version_name, JSValueMakeString(ctx, version_value), kJSPropertyAttributeNone, NULL);
    JSStringRelease(version_name);
    JSStringRelease(version_value);

    // process.exit
    JSStringRef exit_name = JSStringCreateWithUTF8CString("exit");
    JSObjectRef exit_func = JSObjectMakeFunctionWithCallback(ctx, exit_name, js_process_exit);
    JSObjectSetProperty(ctx, process, exit_name, exit_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(exit_name);

    // process.cwd
    JSStringRef cwd_name = JSStringCreateWithUTF8CString("cwd");
    JSObjectRef cwd_func = JSObjectMakeFunctionWithCallback(ctx, cwd_name, js_process_cwd);
    JSObjectSetProperty(ctx, process, cwd_name, cwd_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(cwd_name);

    // process.chdir
    JSStringRef chdir_name = JSStringCreateWithUTF8CString("chdir");
    JSObjectRef chdir_func = JSObjectMakeFunctionWithCallback(ctx, chdir_name, js_process_chdir);
    JSObjectSetProperty(ctx, process, chdir_name, chdir_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(chdir_name);

    // Attach to global
    JSStringRef process_name = JSStringCreateWithUTF8CString("process");
    JSObjectSetProperty(ctx, global, process_name, process, kJSPropertyAttributeNone, NULL);
    JSStringRelease(process_name);
}

void setup_timers(JSContextRef ctx, JSObjectRef global) {
    JSStringRef setTimeout_name = JSStringCreateWithUTF8CString("setTimeout");
    JSObjectRef setTimeout_func = JSObjectMakeFunctionWithCallback(ctx, setTimeout_name, js_set_timeout);
    JSObjectSetProperty(ctx, global, setTimeout_name, setTimeout_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(setTimeout_name);

    JSStringRef setInterval_name = JSStringCreateWithUTF8CString("setInterval");
    JSObjectRef setInterval_func = JSObjectMakeFunctionWithCallback(ctx, setInterval_name, js_set_interval);
    JSObjectSetProperty(ctx, global, setInterval_name, setInterval_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(setInterval_name);

    JSStringRef clearTimeout_name = JSStringCreateWithUTF8CString("clearTimeout");
    JSObjectRef clearTimeout_func = JSObjectMakeFunctionWithCallback(ctx, clearTimeout_name, js_clear_timer);
    JSObjectSetProperty(ctx, global, clearTimeout_name, clearTimeout_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(clearTimeout_name);

    JSStringRef clearInterval_name = JSStringCreateWithUTF8CString("clearInterval");
    JSObjectRef clearInterval_func = JSObjectMakeFunctionWithCallback(ctx, clearInterval_name, js_clear_timer);
    JSObjectSetProperty(ctx, global, clearInterval_name, clearInterval_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(clearInterval_name);

    JSStringRef queueMicrotask_name = JSStringCreateWithUTF8CString("queueMicrotask");
    JSObjectRef queueMicrotask_func = JSObjectMakeFunctionWithCallback(ctx, queueMicrotask_name, js_queue_microtask);
    JSObjectSetProperty(ctx, global, queueMicrotask_name, queueMicrotask_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(queueMicrotask_name);
}

void setup_http_server(JSContextRef ctx, JSObjectRef global) {
    JSStringRef serve_name = JSStringCreateWithUTF8CString("serve");
    JSObjectRef serve_func = JSObjectMakeFunctionWithCallback(ctx, serve_name, js_serve);
    JSObjectSetProperty(ctx, global, serve_name, serve_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(serve_name);

    JSStringRef serve_https_name = JSStringCreateWithUTF8CString("serve_https");
    JSObjectRef serve_https_func = JSObjectMakeFunctionWithCallback(ctx, serve_https_name, js_serve_https);
    JSObjectSetProperty(ctx, global, serve_https_name, serve_https_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(serve_https_name);
}

void setup_test_runner(JSContextRef ctx, JSObjectRef global) {
    JSStringRef test_name = JSStringCreateWithUTF8CString("test");
    JSObjectRef test_func = JSObjectMakeFunctionWithCallback(ctx, test_name, js_test);
    JSObjectSetProperty(ctx, global, test_name, test_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(test_name);

    JSStringRef assert_name = JSStringCreateWithUTF8CString("assert");
    JSObjectRef assert_func = JSObjectMakeFunctionWithCallback(ctx, assert_name, js_assert);
    JSObjectSetProperty(ctx, global, assert_name, assert_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(assert_name);

    JSStringRef assertEqual_name = JSStringCreateWithUTF8CString("assertEqual");
    JSObjectRef assertEqual_func = JSObjectMakeFunctionWithCallback(ctx, assertEqual_name, js_assert_equal);
    JSObjectSetProperty(ctx, global, assertEqual_name, assertEqual_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(assertEqual_name);

    JSStringRef run_name = JSStringCreateWithUTF8CString("run");
    JSObjectRef run_func = JSObjectMakeFunctionWithCallback(ctx, run_name, js_run_tests);
    JSObjectSetProperty(ctx, global, run_name, run_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(run_name);
}

void setup_buffer(JSContextRef ctx, JSObjectRef global) {
    JSObjectRef buffer = JSObjectMake(ctx, NULL, NULL);

    JSStringRef from_name = JSStringCreateWithUTF8CString("from");
    JSObjectRef from_func = JSObjectMakeFunctionWithCallback(ctx, from_name, js_buffer_from);
    JSObjectSetProperty(ctx, buffer, from_name, from_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(from_name);

    JSStringRef alloc_name = JSStringCreateWithUTF8CString("alloc");
    JSObjectRef alloc_func = JSObjectMakeFunctionWithCallback(ctx, alloc_name, js_buffer_alloc);
    JSObjectSetProperty(ctx, buffer, alloc_name, alloc_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(alloc_name);

    JSStringRef buffer_name = JSStringCreateWithUTF8CString("Buffer");
    JSObjectSetProperty(ctx, global, buffer_name, buffer, kJSPropertyAttributeNone, NULL);
    JSStringRelease(buffer_name);
}

// Event loop - process timers, microtasks, and HTTP servers
void run_event_loop() {
    // Initialize kqueue if not already done
    if (kq == -1) {
        kq = kqueue();
        if (kq == -1) {
            return;
        }
    }

    // Drain initial microtasks from script execution
    drain_microtasks();
    process_async_ops();
    process_streams();

    // Register server sockets with kqueue
    HttpServer* server = server_list;
    while (server) {
        struct kevent kev;
        EV_SET(&kev, server->socket_fd, EVFILT_READ, EV_ADD, 0, 0, server);
        kevent(kq, &kev, 1, NULL, 0, NULL);
        server = server->next;
    }

    // Register HTTPS server sockets with kqueue
    HttpsServer* https_server = https_server_list;
    while (https_server) {
        struct kevent kev;
        EV_SET(&kev, https_server->socket_fd, EVFILT_READ, EV_ADD, 0, 0, https_server);
        kevent(kq, &kev, 1, NULL, 0, NULL);
        https_server = https_server->next;
    }

    // Event loop runs if we have timers, servers, websockets, TCP sockets, TLS sockets, or UDP sockets
    while (timer_queue || server_list || https_server_list || websocket_list || tcp_socket_list || tcp_server_list || tls_socket_list || udp_socket_list) {
        // Calculate timeout based on next timer
        struct timespec timeout;
        timeout.tv_sec = 0;
        timeout.tv_nsec = 100000000;  // Default 100ms timeout
        struct timespec* timeout_ptr = &timeout;

        if (timer_queue) {
            // Find next timer
            uint64_t now = get_time_ms();
            uint64_t min_time = UINT64_MAX;
            Timer* current = timer_queue;
            while (current) {
                if (!current->cancelled && current->target_time_ms < min_time) {
                    min_time = current->target_time_ms;
                }
                current = current->next;
            }

            if (min_time != UINT64_MAX) {
                int64_t wait_ms = (int64_t)min_time - (int64_t)now;
                if (wait_ms < 0) wait_ms = 0;
                if (wait_ms > 100) wait_ms = 100; // Cap at 100ms for responsiveness

                timeout.tv_sec = wait_ms / 1000;
                timeout.tv_nsec = (wait_ms % 1000) * 1000000;
                timeout_ptr = &timeout;
            }
        } else if (server_list) {
            // No timers, just servers - wait up to 100ms
            timeout.tv_sec = 0;
            timeout.tv_nsec = 100000000;
            timeout_ptr = &timeout;
        }

        // Wait for server events with timeout
        struct kevent events[10];
        int nev = kevent(kq, NULL, 0, events, 10, timeout_ptr);

        // Process server events
        for (int i = 0; i < nev; i++) {
                // Handle WRITE events (for WebSocket client handshake)
                if (events[i].filter == EVFILT_WRITE) {
                    // Check if this is a WebSocket client that needs to send handshake
                    JSObjectRef obj = (JSObjectRef)events[i].udata;
                    WebSocket* ws = JSObjectGetPrivate(obj);

                    if (ws && ws->is_client && ws->ready_state == 0 && ws->handshake_len > 0) {
                        // Socket is now writable, send the handshake
                        ssize_t sent = send(ws->socket_fd, ws->handshake_buffer, ws->handshake_len, 0);

                        if (sent > 0) {
                            // Handshake sent successfully
                            ws->handshake_len = 0;  // Mark as sent

                            // Switch to READ events to receive the server response
                            struct kevent read_ev;
                            EV_SET(&read_ev, ws->socket_fd, EVFILT_READ, EV_ADD, 0, 0, obj);
                            kevent(kq, &read_ev, 1, NULL, 0, NULL);
                        } else {
                            // Send failed - trigger error
                            if (ws->onerror) {
                                JSObjectCallAsFunction(global_ctx, ws->onerror, obj, 0, NULL, NULL);
                            }
                            ws->ready_state = 3;  // CLOSED
                            if (ws->onclose) {
                                JSObjectCallAsFunction(global_ctx, ws->onclose, obj, 0, NULL, NULL);
                            }
                        }
                    }

                    drain_microtasks();
                    continue;
                }

                if (events[i].filter == EVFILT_READ) {

                    // Check if this is a TLS socket (must check before casting to JSObjectRef)
                    TlsSocket* tls_sock = NULL;
                    for (TlsSocket* ts = tls_socket_list; ts; ts = ts->next) {
                        if (ts == (TlsSocket*)events[i].udata) {
                            tls_sock = ts;
                            break;
                        }
                    }

                    if (tls_sock) {
                        fprintf(stderr, "[DEBUG] TLS socket event on fd %d, state %d\n", tls_sock->socket_fd, tls_sock->tls_ctx->state);
                        // Handle TLS socket
                        if (tls_sock->tls_ctx->state == TLS_STATE_NONE || tls_sock->tls_ctx->state == TLS_STATE_HANDSHAKING) {
                            // Perform TLS handshake
                            fprintf(stderr, "[DEBUG] Starting TLS handshake\n");
                            int result = tls_handshake(tls_sock->tls_ctx);
                            fprintf(stderr, "[DEBUG] Handshake result: %d\n", result);
                            if (result == 0) {
                                // Handshake complete - now we can read HTTP request
                                tls_sock->tls_ctx->state = TLS_STATE_CONNECTED;
                            } else if (result == -1) {
                                // Would block - try again later
                                drain_microtasks();
                                continue;
                            } else {
                                // Handshake failed
                                close(tls_sock->socket_fd);
                                drain_microtasks();
                                continue;
                            }
                        }

                        if (tls_sock->tls_ctx->state == TLS_STATE_CONNECTED && tls_sock->is_server && tls_sock->handler) {
                            // Read HTTP request through TLS
                            char temp_buf[8192];
                            ssize_t bytes_read = tls_read(tls_sock->tls_ctx, temp_buf, sizeof(temp_buf) - 1);

                            if (bytes_read < 0) {
                                // Error - close connection
                                destroy_tls_context(tls_sock->tls_ctx);
                                close(tls_sock->socket_fd);
                                tls_sock->socket_fd = -1;
                                drain_microtasks();
                                continue;
                            }

                            if (bytes_read > 0) {
                                temp_buf[bytes_read] = '\0';

                                // Append to read buffer
                                if (tls_sock->read_buffer_len + bytes_read < sizeof(tls_sock->read_buffer)) {
                                    memcpy(tls_sock->read_buffer + tls_sock->read_buffer_len, temp_buf, bytes_read);
                                    tls_sock->read_buffer_len += bytes_read;
                                    tls_sock->read_buffer[tls_sock->read_buffer_len] = '\0';
                                }

                                // Check if we have a complete HTTP request (ends with \r\n\r\n)
                                if (strstr(tls_sock->read_buffer, "\r\n\r\n")) {
                                    // Parse HTTP request (similar to HTTP server)
                                    char method[16] = {0};
                                    char path[1024] = {0};
                                    char version[16] = {0};
                                    parse_http_request(tls_sock->read_buffer, method, path, version);

                                    // Create request object
                                    JSObjectRef req = JSObjectMake(global_ctx, NULL, NULL);

                                    JSStringRef method_name = JSStringCreateWithUTF8CString("method");
                                    JSStringRef method_val = JSStringCreateWithUTF8CString(method);
                                    JSObjectSetProperty(global_ctx, req, method_name, JSValueMakeString(global_ctx, method_val), kJSPropertyAttributeNone, NULL);
                                    JSStringRelease(method_name);
                                    JSStringRelease(method_val);

                                    JSStringRef pathname_name = JSStringCreateWithUTF8CString("pathname");
                                    JSStringRef pathname_val = JSStringCreateWithUTF8CString(path);
                                    JSObjectSetProperty(global_ctx, req, pathname_name, JSValueMakeString(global_ctx, pathname_val), kJSPropertyAttributeNone, NULL);
                                    JSStringRelease(pathname_name);
                                    JSStringRelease(pathname_val);

                                    // Call handler
                                    JSValueRef args[] = {req};
                                    JSValueRef response = JSObjectCallAsFunction(global_ctx, tls_sock->handler, NULL, 1, args, NULL);

                                    // Parse response and send via TLS
                                    if (response && JSValueIsObject(global_ctx, response)) {
                                        JSObjectRef response_obj = JSValueToObject(global_ctx, response, NULL);

                                        // Get status
                                        int status = 200;
                                        JSStringRef status_name = JSStringCreateWithUTF8CString("status");
                                        JSValueRef status_val = JSObjectGetProperty(global_ctx, response_obj, status_name, NULL);
                                        if (!JSValueIsUndefined(global_ctx, status_val)) {
                                            status = (int)JSValueToNumber(global_ctx, status_val, NULL);
                                        }
                                        JSStringRelease(status_name);

                                        // Get body
                                        JSStringRef body_name = JSStringCreateWithUTF8CString("body");
                                        JSValueRef body_val = JSObjectGetProperty(global_ctx, response_obj, body_name, NULL);
                                        JSStringRef body_str = JSValueToStringCopy(global_ctx, body_val, NULL);
                                        size_t body_max = JSStringGetMaximumUTF8CStringSize(body_str);
                                        char* body = malloc(body_max);
                                        JSStringGetUTF8CString(body_str, body, body_max);
                                        JSStringRelease(body_str);
                                        JSStringRelease(body_name);

                                        // Build HTTP response
                                        char http_response[8192];
                                        int resp_len = snprintf(http_response, sizeof(http_response),
                                            "HTTP/1.1 %d OK\r\n"
                                            "Content-Type: text/plain\r\n"
                                            "Content-Length: %zu\r\n"
                                            "Connection: close\r\n"
                                            "\r\n"
                                            "%s", status, strlen(body), body);

                                        // Send response through TLS
                                        tls_write(tls_sock->tls_ctx, http_response, resp_len);

                                        free(body);
                                    }

                                    // Close connection after sending response
                                    destroy_tls_context(tls_sock->tls_ctx);
                                    close(tls_sock->socket_fd);
                                    tls_sock->socket_fd = -1;
                                }
                                // If bytes_read == 0, just continue - no data yet, wait for next event
                            }
                        }

                        drain_microtasks();
                        continue;
                    }

                    // Check if this is an HTTPS server
                    HttpsServer* https_srv = NULL;
                    for (HttpsServer* hs = https_server_list; hs; hs = hs->next) {
                        if (hs == (HttpsServer*)events[i].udata) {
                            https_srv = hs;
                            break;
                        }
                    }

                    if (https_srv) {
                        // Accept HTTPS connection
                        struct sockaddr_in client_addr;
                        socklen_t client_len = sizeof(client_addr);
                        int client_fd = accept(https_srv->socket_fd, (struct sockaddr*)&client_addr, &client_len);

                        if (client_fd >= 0) {
                            fprintf(stderr, "[DEBUG] Accepted HTTPS connection on fd %d\n", client_fd);
                            fcntl(client_fd, F_SETFL, O_NONBLOCK);

                            // Create TLS context for this connection
                            TlsContext* tls_ctx = create_tls_context(client_fd, 1, https_srv->tls_template->identity);
                            fprintf(stderr, "[DEBUG] TLS context created: %p\n", (void*)tls_ctx);
                            if (tls_ctx) {
                                fprintf(stderr, "[DEBUG] About to create TLS socket wrapper\n");
                                // Create TLS socket wrapper
                                TlsSocket* tls_sock = malloc(sizeof(TlsSocket));
                                fprintf(stderr, "[DEBUG] TLS socket allocated: %p\n", (void*)tls_sock);
                                memset(tls_sock, 0, sizeof(TlsSocket));
                                tls_sock->socket_fd = client_fd;
                                tls_sock->tls_ctx = tls_ctx;
                                tls_sock->is_server = 1;
                                tls_sock->connecting = 0;
                                tls_sock->handler = https_srv->handler;
                                tls_sock->on_secure_connect = NULL;
                                tls_sock->on_data = NULL;
                                tls_sock->on_end = NULL;
                                tls_sock->on_error = NULL;
                                tls_sock->read_buffer_len = 0;
                                fprintf(stderr, "[DEBUG] About to add to list\n");
                                tls_sock->next = tls_socket_list;
                                tls_socket_list = tls_sock;
                                fprintf(stderr, "[DEBUG] Added to list\n");

                                // Protect handler from GC
                                JSValueProtect(global_ctx, https_srv->handler);
                                fprintf(stderr, "[DEBUG] Protected handler\n");

                                // Register socket with kqueue for TLS handshake/data
                                struct kevent cev;
                                fprintf(stderr, "[DEBUG] kq=%d, client_fd=%d\n", kq, client_fd);
                                EV_SET(&cev, client_fd, EVFILT_READ, EV_ADD, 0, 0, tls_sock);
                                fprintf(stderr, "[DEBUG] EV_SET done, about to call kevent\n");
                                int kq_result = kevent(kq, &cev, 1, NULL, 0, NULL);
                                fprintf(stderr, "[DEBUG] kqueue register result: %d, errno: %d, fd: %d, tls_sock: %p\n", kq_result, errno, client_fd, (void*)tls_sock);
                                fprintf(stderr, "[DEBUG] Finished TLS socket setup\n");
                            } else {
                                fprintf(stderr, "[DEBUG] TLS context creation failed\n");
                                close(client_fd);
                            }
                        }

                        fprintf(stderr, "[DEBUG] About to drain microtasks\n");
                        drain_microtasks();
                        fprintf(stderr, "[DEBUG] About to continue\n");
                        continue;
                    }

                    // Check if this is an HTTP server
                    HttpServer* http_srv = NULL;
                    for (HttpServer* hs = server_list; hs; hs = hs->next) {
                        if (hs == (HttpServer*)events[i].udata) {
                            http_srv = hs;
                            break;
                        }
                    }

                    if (http_srv) {
                        // Handle HTTP server - jump to existing HTTP handling code below
                        // (we'll keep the existing code that follows)
                    }

                    JSObjectRef obj = (JSObjectRef)events[i].udata;

                    // Check if this is a TCP socket
                    TcpSocket* tcp_sock = JSObjectGetPrivate(obj);
                    if (tcp_sock && !tcp_sock->is_server) {
                        // Handle TCP socket data
                        char temp_buf[8192];
                        ssize_t bytes_read = recv(tcp_sock->socket_fd, temp_buf, sizeof(temp_buf), 0);

                        if (bytes_read <= 0) {
                            // Connection closed or error
                            if (tcp_sock->on_end && bytes_read == 0) {
                                JSObjectCallAsFunction(global_ctx, tcp_sock->on_end, obj, 0, NULL, NULL);
                            }
                            if (tcp_sock->on_close) {
                                JSObjectCallAsFunction(global_ctx, tcp_sock->on_close, obj, 0, NULL, NULL);
                            }

                            // Unregister from kqueue
                            struct kevent cev;
                            EV_SET(&cev, tcp_sock->socket_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                            kevent(kq, &cev, 1, NULL, 0, NULL);

                            // Close socket
                            close(tcp_sock->socket_fd);

                            // Mark as closed (socket_fd = -1 indicates closed)
                            tcp_sock->socket_fd = -1;

                            continue;
                        }

                        // Call ondata callback
                        if (tcp_sock->on_data) {
                            temp_buf[bytes_read] = '\0';
                            JSStringRef data_str = JSStringCreateWithUTF8CString(temp_buf);
                            JSValueRef data_val = JSValueMakeString(global_ctx, data_str);
                            JSStringRelease(data_str);

                            JSValueRef args[] = {data_val};
                            JSObjectCallAsFunction(global_ctx, tcp_sock->on_data, obj, 1, args, NULL);
                        }

                        drain_microtasks();
                        continue;
                    }

                    // Check if this is a TCP server
                    TcpServer* tcp_server = NULL;
                    for (TcpServer* srv = tcp_server_list; srv; srv = srv->next) {
                        JSStringRef server_ptr_name = JSStringCreateWithUTF8CString("_serverptr");
                        JSValueRef server_ptr_val = JSObjectGetProperty(global_ctx, obj, server_ptr_name, NULL);
                        JSStringRelease(server_ptr_name);

                        if (!JSValueIsUndefined(global_ctx, server_ptr_val)) {
                            uintptr_t ptr = (uintptr_t)JSValueToNumber(global_ctx, server_ptr_val, NULL);
                            if (ptr == (uintptr_t)srv) {
                                tcp_server = srv;
                                break;
                            }
                        }
                    }

                    if (tcp_server) {
                        // Accept TCP connection
                        struct sockaddr_in client_addr;
                        socklen_t client_len = sizeof(client_addr);
                        int client_fd = accept(tcp_server->socket_fd, (struct sockaddr*)&client_addr, &client_len);

                        if (client_fd >= 0) {
                            fcntl(client_fd, F_SETFL, O_NONBLOCK);

                            // Create socket for client
                            TcpSocket* client_sock = malloc(sizeof(TcpSocket));
                            client_sock->socket_fd = client_fd;
                            client_sock->is_server = 0;
                            client_sock->connecting = 0;
                            client_sock->on_data = NULL;
                            client_sock->on_end = NULL;
                            client_sock->on_error = NULL;
                            client_sock->on_close = NULL;
                            client_sock->on_connect = NULL;
                            client_sock->read_buffer_len = 0;
                            client_sock->next = tcp_socket_list;
                            tcp_socket_list = client_sock;

                            JSObjectRef client_obj = create_tcp_socket_object(global_ctx, client_sock);

                            // Add to kqueue
                            struct kevent cev;
                            EV_SET(&cev, client_fd, EVFILT_READ, EV_ADD, 0, 0, client_obj);
                            kevent(kq, &cev, 1, NULL, 0, NULL);
                            JSValueProtect(global_ctx, client_obj);

                            // Call connection handler
                            if (tcp_server->on_connection) {
                                JSValueRef args[] = {client_obj};
                                JSObjectCallAsFunction(global_ctx, tcp_server->on_connection, NULL, 1, args, NULL);
                            }

                            drain_microtasks();
                        }
                        continue;
                    }

                    // Check if this is a WebSocket client
                    WebSocket* ws = JSObjectGetPrivate(obj);

                    if (ws && ws->is_client) {
                        // Handle WebSocket client data
                        char temp_buf[8192];
                        ssize_t bytes_read = recv(ws->socket_fd, temp_buf, sizeof(temp_buf), 0);

                        if (bytes_read <= 0) {
                            ws->ready_state = 3;  // CLOSED
                            if (ws->onclose) {
                                JSObjectCallAsFunction(global_ctx, ws->onclose, obj, 0, NULL, NULL);
                            }
                            continue;
                        }

                        // Append to read buffer
                        if (ws->read_buffer_len + bytes_read < sizeof(ws->read_buffer)) {
                            memcpy(ws->read_buffer + ws->read_buffer_len, temp_buf, bytes_read);
                            ws->read_buffer_len += bytes_read;
                        }

                        // Check for HTTP upgrade response first
                        if (ws->ready_state == 0) {
                            if (strstr(ws->read_buffer, "\r\n\r\n")) {
                                if (strstr(ws->read_buffer, "101")) {
                                    ws->ready_state = 1;  // OPEN
                                    if (ws->onopen) {
                                        JSObjectCallAsFunction(global_ctx, ws->onopen, obj, 0, NULL, NULL);
                                    }
                                    // Remove HTTP response from buffer
                                    char* end = strstr(ws->read_buffer, "\r\n\r\n") + 4;
                                    size_t remaining = ws->read_buffer_len - (end - ws->read_buffer);
                                    memmove(ws->read_buffer, end, remaining);
                                    ws->read_buffer_len = remaining;
                                }
                            }
                            continue;
                        }

                        // Parse WebSocket frames
                        while (ws->read_buffer_len > 0) {
                            int opcode;
                            unsigned char* payload;
                            size_t payload_len;
                            size_t frame_len;

                            int result = ws_parse_frame((unsigned char*)ws->read_buffer, ws->read_buffer_len,
                                                        &opcode, &payload, &payload_len, &frame_len);

                            if (result < 0) break;  // Need more data

                            // Remove parsed frame from buffer
                            memmove(ws->read_buffer, ws->read_buffer + frame_len, ws->read_buffer_len - frame_len);
                            ws->read_buffer_len -= frame_len;

                            // Handle frame based on opcode
                            if (opcode == WS_OPCODE_TEXT || opcode == WS_OPCODE_BINARY) {
                                if (ws->onmessage) {
                                    JSStringRef data_str = JSStringCreateWithUTF8CString((char*)payload);
                                    JSValueRef data_val = JSValueMakeString(global_ctx, data_str);
                                    JSStringRelease(data_str);

                                    if (ws->is_client) {
                                        // Client-side: pass event with data property
                                        JSObjectRef event = JSObjectMake(global_ctx, NULL, NULL);
                                        JSStringRef data_name = JSStringCreateWithUTF8CString("data");
                                        JSObjectSetProperty(global_ctx, event, data_name, data_val, kJSPropertyAttributeNone, NULL);
                                        JSStringRelease(data_name);

                                        JSValueRef args[] = {event};
                                        JSObjectCallAsFunction(global_ctx, ws->onmessage, obj, 1, args, NULL);
                                    } else {
                                        // Server-side: pass req with ws and data
                                        JSObjectRef req = JSObjectMake(global_ctx, NULL, NULL);

                                        JSStringRef ws_name = JSStringCreateWithUTF8CString("ws");
                                        JSObjectSetProperty(global_ctx, req, ws_name, obj, kJSPropertyAttributeNone, NULL);
                                        JSStringRelease(ws_name);

                                        JSStringRef data_name = JSStringCreateWithUTF8CString("data");
                                        JSObjectSetProperty(global_ctx, req, data_name, data_val, kJSPropertyAttributeNone, NULL);
                                        JSStringRelease(data_name);

                                        JSStringRef type_name = JSStringCreateWithUTF8CString("type");
                                        JSStringRef type_val = JSStringCreateWithUTF8CString("websocket");
                                        JSObjectSetProperty(global_ctx, req, type_name, JSValueMakeString(global_ctx, type_val), kJSPropertyAttributeNone, NULL);
                                        JSStringRelease(type_name);
                                        JSStringRelease(type_val);

                                        JSValueRef args[] = {req};
                                        JSObjectCallAsFunction(global_ctx, ws->onmessage, NULL, 1, args, NULL);
                                    }
                                }
                            } else if (opcode == WS_OPCODE_PING) {
                                // Send pong
                                unsigned char frame[256];
                                size_t pong_len = ws_encode_frame(frame, payload, payload_len, WS_OPCODE_PONG, 1);
                                send(ws->socket_fd, frame, pong_len, 0);
                            } else if (opcode == WS_OPCODE_CLOSE) {
                                ws->ready_state = 3;
                                if (ws->onclose) {
                                    JSObjectCallAsFunction(global_ctx, ws->onclose, obj, 0, NULL, NULL);
                                }
                            }

                            free(payload);
                        }

                        drain_microtasks();
                        continue;
                    }

                    // Check if this is a UDP socket
                    int is_udp = 0;
                    UdpSocket* udp_sock = NULL;
                    for (UdpSocket* sock = udp_socket_list; sock; sock = sock->next) {
                        if (sock->socket_fd == (int)events[i].ident) {
                            is_udp = 1;
                            udp_sock = sock;
                            break;
                        }
                    }

                    if (is_udp && udp_sock) {
                        // Receive UDP packet
                        char buffer[8192];
                        struct sockaddr_in from_addr;
                        socklen_t from_len = sizeof(from_addr);

                        ssize_t bytes = recvfrom(udp_sock->socket_fd, buffer, sizeof(buffer) - 1, 0,
                                                (struct sockaddr*)&from_addr, &from_len);

                        if (bytes > 0 && udp_sock->on_message) {
                            // Convert address to string
                            char from_ip[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &from_addr.sin_addr, from_ip, sizeof(from_ip));

                            // Create Buffer (Uint8Array) from received data
                            JSValueRef* byte_values = malloc(sizeof(JSValueRef) * bytes);
                            for (ssize_t i = 0; i < bytes; i++) {
                                byte_values[i] = JSValueMakeNumber(global_ctx, (unsigned char)buffer[i]);
                            }
                            JSObjectRef byte_array = JSObjectMakeArray(global_ctx, bytes, byte_values, NULL);
                            free(byte_values);

                            // Create Uint8Array from array
                            JSObjectRef global = JSContextGetGlobalObject(global_ctx);
                            JSStringRef temp_name = JSStringCreateWithUTF8CString("__temp_udp_data");
                            JSObjectSetProperty(global_ctx, global, temp_name, byte_array, kJSPropertyAttributeNone, NULL);
                            JSStringRelease(temp_name);

                            JSStringRef code = JSStringCreateWithUTF8CString("Buffer.from(__temp_udp_data)");
                            JSValueRef msg_val = JSEvaluateScript(global_ctx, code, NULL, NULL, 1, NULL);
                            JSStringRelease(code);

                            // Create rinfo object {address, port, family}
                            JSObjectRef rinfo = JSObjectMake(global_ctx, NULL, NULL);

                            JSStringRef addr_name = JSStringCreateWithUTF8CString("address");
                            JSStringRef addr_val = JSStringCreateWithUTF8CString(from_ip);
                            JSObjectSetProperty(global_ctx, rinfo, addr_name, JSValueMakeString(global_ctx, addr_val),
                                              kJSPropertyAttributeNone, NULL);
                            JSStringRelease(addr_name);
                            JSStringRelease(addr_val);

                            JSStringRef port_name = JSStringCreateWithUTF8CString("port");
                            JSObjectSetProperty(global_ctx, rinfo, port_name, JSValueMakeNumber(global_ctx, ntohs(from_addr.sin_port)),
                                              kJSPropertyAttributeNone, NULL);
                            JSStringRelease(port_name);

                            JSStringRef family_name = JSStringCreateWithUTF8CString("family");
                            JSStringRef family_val = JSStringCreateWithUTF8CString("IPv4");
                            JSObjectSetProperty(global_ctx, rinfo, family_name, JSValueMakeString(global_ctx, family_val),
                                              kJSPropertyAttributeNone, NULL);
                            JSStringRelease(family_name);
                            JSStringRelease(family_val);

                            // Call handler(msg, rinfo)
                            JSValueRef args[] = {msg_val, rinfo};
                            JSObjectCallAsFunction(global_ctx, udp_sock->on_message, NULL, 2, args, NULL);
                        }

                        drain_microtasks();
                        continue;
                    }

                    // Otherwise it's an HTTP server (if http_srv was matched above)
                    if (http_srv) {
                        HttpServer* srv = http_srv;

                        // Accept connection
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int client_fd = accept(srv->socket_fd, (struct sockaddr*)&client_addr, &client_len);

                    if (client_fd >= 0) {
                        // Set socket to blocking for request read
                        fcntl(client_fd, F_SETFL, 0);

                        // Read request
                        char buffer[8192] = {0};
                        ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

                        if (bytes_read > 0) {
                            buffer[bytes_read] = '\0';

                            // Find body before tokenizing (strtok modifies buffer)
                            char body_buffer[4096] = {0};
                            char* body_start = strstr(buffer, "\r\n\r\n");
                            if (body_start) {
                                body_start += 4;  // Skip \r\n\r\n
                                strncpy(body_buffer, body_start, sizeof(body_buffer) - 1);
                            }

                            // Parse request
                            char method[16] = {0};
                            char path[1024] = {0};
                            char version[16] = {0};
                            parse_http_request(buffer, method, path, version);

                            // Parse headers
                            JSObjectRef headers = JSObjectMake(global_ctx, NULL, NULL);
                            char* line = strtok(buffer + strlen(method) + strlen(path) + strlen(version) + 3, "\r\n");
                            while (line && strlen(line) > 0) {
                                char* colon = strchr(line, ':');
                                if (colon) {
                                    *colon = '\0';
                                    char* key = line;
                                    char* value = colon + 1;
                                    while (*value == ' ') value++;

                                    JSStringRef key_str = JSStringCreateWithUTF8CString(key);
                                    JSStringRef value_str = JSStringCreateWithUTF8CString(value);
                                    JSObjectSetProperty(global_ctx, headers, key_str, JSValueMakeString(global_ctx, value_str), kJSPropertyAttributeNone, NULL);
                                    JSStringRelease(key_str);
                                    JSStringRelease(value_str);
                                }
                                line = strtok(NULL, "\r\n");
                            }

                            // Create request object
                            JSObjectRef req = JSObjectMake(global_ctx, NULL, NULL);

                            JSStringRef method_name = JSStringCreateWithUTF8CString("method");
                            JSStringRef method_value = JSStringCreateWithUTF8CString(method);
                            JSObjectSetProperty(global_ctx, req, method_name, JSValueMakeString(global_ctx, method_value), kJSPropertyAttributeNone, NULL);
                            JSStringRelease(method_name);
                            JSStringRelease(method_value);

                            JSStringRef url_name = JSStringCreateWithUTF8CString("url");
                            JSStringRef url_value = JSStringCreateWithUTF8CString(path);
                            JSObjectSetProperty(global_ctx, req, url_name, JSValueMakeString(global_ctx, url_value), kJSPropertyAttributeNone, NULL);
                            JSStringRelease(url_name);
                            JSStringRelease(url_value);

                            JSStringRef headers_name = JSStringCreateWithUTF8CString("headers");
                            JSObjectSetProperty(global_ctx, req, headers_name, headers, kJSPropertyAttributeNone, NULL);
                            JSStringRelease(headers_name);

                            // Parse query string from path
                            char pathname[1024] = {0};
                            char querystring[1024] = {0};
                            char* query_start = strchr(path, '?');
                            if (query_start) {
                                size_t path_len = query_start - path;
                                strncpy(pathname, path, path_len);
                                pathname[path_len] = '\0';
                                strcpy(querystring, query_start + 1);
                            } else {
                                strcpy(pathname, path);
                            }

                            // Add pathname
                            JSStringRef pathname_name = JSStringCreateWithUTF8CString("pathname");
                            JSStringRef pathname_value = JSStringCreateWithUTF8CString(pathname);
                            JSObjectSetProperty(global_ctx, req, pathname_name, JSValueMakeString(global_ctx, pathname_value), kJSPropertyAttributeNone, NULL);
                            JSStringRelease(pathname_name);
                            JSStringRelease(pathname_value);

                            // Parse query string into object
                            JSObjectRef query = JSObjectMake(global_ctx, NULL, NULL);
                            if (strlen(querystring) > 0) {
                                char* query_copy = strdup(querystring);
                                char* pair = strtok(query_copy, "&");
                                while (pair) {
                                    char* eq = strchr(pair, '=');
                                    if (eq) {
                                        *eq = '\0';
                                        char* key = pair;
                                        char* value = eq + 1;

                                        JSStringRef key_str = JSStringCreateWithUTF8CString(key);
                                        JSStringRef value_str = JSStringCreateWithUTF8CString(value);
                                        JSObjectSetProperty(global_ctx, query, key_str, JSValueMakeString(global_ctx, value_str), kJSPropertyAttributeNone, NULL);
                                        JSStringRelease(key_str);
                                        JSStringRelease(value_str);
                                    }
                                    pair = strtok(NULL, "&");
                                }
                                free(query_copy);
                            }

                            JSStringRef query_name = JSStringCreateWithUTF8CString("query");
                            JSObjectSetProperty(global_ctx, req, query_name, query, kJSPropertyAttributeNone, NULL);
                            JSStringRelease(query_name);

                            // Parse request body (use saved body_buffer)
                            if (strlen(body_buffer) > 0) {
                                // Add raw body
                                JSStringRef body_name = JSStringCreateWithUTF8CString("body");
                                JSStringRef body_value = JSStringCreateWithUTF8CString(body_buffer);
                                JSObjectSetProperty(global_ctx, req, body_name, JSValueMakeString(global_ctx, body_value), kJSPropertyAttributeNone, NULL);
                                JSStringRelease(body_name);
                                JSStringRelease(body_value);

                                // Try to parse JSON body if Content-Type is application/json
                                JSStringRef content_type_key = JSStringCreateWithUTF8CString("Content-Type");
                                JSValueRef content_type_val = JSObjectGetProperty(global_ctx, headers, content_type_key, NULL);
                                JSStringRelease(content_type_key);

                                if (!JSValueIsUndefined(global_ctx, content_type_val)) {
                                    JSStringRef ct_str = JSValueToStringCopy(global_ctx, content_type_val, NULL);
                                    char ct_buf[128] = {0};
                                    JSStringGetUTF8CString(ct_str, ct_buf, sizeof(ct_buf));
                                    JSStringRelease(ct_str);

                                    if (strstr(ct_buf, "application/json")) {
                                        // Parse JSON body
                                        JSStringRef json_str = JSStringCreateWithUTF8CString(body_buffer);
                                        JSValueRef json_val = JSValueMakeFromJSONString(global_ctx, json_str);
                                        JSStringRelease(json_str);

                                        if (json_val && !JSValueIsUndefined(global_ctx, json_val)) {
                                            JSStringRef json_name = JSStringCreateWithUTF8CString("json");
                                            JSObjectSetProperty(global_ctx, req, json_name, json_val, kJSPropertyAttributeNone, NULL);
                                            JSStringRelease(json_name);
                                        }
                                    }
                                }
                            }

                            // Check for WebSocket upgrade
                            JSStringRef upgrade_key = JSStringCreateWithUTF8CString("Upgrade");
                            JSValueRef upgrade_val = JSObjectGetProperty(global_ctx, headers, upgrade_key, NULL);
                            JSStringRelease(upgrade_key);

                            int is_websocket = 0;
                            char ws_key[256] = {0};
                            if (!JSValueIsUndefined(global_ctx, upgrade_val)) {
                                JSStringRef upgrade_str = JSValueToStringCopy(global_ctx, upgrade_val, NULL);
                                char upgrade_buf[64] = {0};
                                JSStringGetUTF8CString(upgrade_str, upgrade_buf, sizeof(upgrade_buf));
                                JSStringRelease(upgrade_str);

                                if (strcasecmp(upgrade_buf, "websocket") == 0) {
                                    is_websocket = 1;

                                    // Get Sec-WebSocket-Key
                                    JSStringRef key_name = JSStringCreateWithUTF8CString("Sec-WebSocket-Key");
                                    JSValueRef key_val = JSObjectGetProperty(global_ctx, headers, key_name, NULL);
                                    JSStringRelease(key_name);
                                    if (!JSValueIsUndefined(global_ctx, key_val)) {
                                        JSStringRef key_str = JSValueToStringCopy(global_ctx, key_val, NULL);
                                        JSStringGetUTF8CString(key_str, ws_key, sizeof(ws_key));
                                        JSStringRelease(key_str);
                                    }
                                }
                            }

                            if (is_websocket && strlen(ws_key) > 0) {
                                // Handle WebSocket upgrade
                                char accept_key[64] = {0};
                                ws_generate_accept_key(ws_key, accept_key);

                                char response[512];
                                snprintf(response, sizeof(response),
                                         "HTTP/1.1 101 Switching Protocols\r\n"
                                         "Upgrade: websocket\r\n"
                                         "Connection: Upgrade\r\n"
                                         "Sec-WebSocket-Accept: %s\r\n"
                                         "\r\n", accept_key);

                                send(client_fd, response, strlen(response), 0);

                                // Create server-side WebSocket
                                WebSocket* ws = malloc(sizeof(WebSocket));
                                ws->socket_fd = client_fd;
                                ws->is_client = 0;
                                ws->ready_state = 1;  // OPEN
                                ws->onopen = NULL;
                                ws->onmessage = srv->handler;  // Use server handler for messages
                                ws->onerror = NULL;
                                ws->onclose = NULL;
                                ws->url = NULL;
                                ws->read_buffer_len = 0;
                                ws->handshake_len = 0;  // Server-side doesn't need handshake
                                ws->next = websocket_list;
                                websocket_list = ws;

                                // Create JS WebSocket object for this connection
                                JSClassDefinition ws_class_def = kJSClassDefinitionEmpty;
                                ws_class_def.finalize = websocket_finalizer;
                                ws_class_def.setProperty = websocket_set_property;
                                JSClassRef ws_class = JSClassCreate(&ws_class_def);
                                JSObjectRef ws_obj = JSObjectMake(global_ctx, ws_class, ws);
                                JSClassRelease(ws_class);

                                // Add send/close methods
                                JSStringRef send_name = JSStringCreateWithUTF8CString("send");
                                JSObjectRef send_func = JSObjectMakeFunctionWithCallback(global_ctx, send_name, js_websocket_send);
                                JSObjectSetProperty(global_ctx, ws_obj, send_name, send_func, kJSPropertyAttributeNone, NULL);
                                JSStringRelease(send_name);

                                JSStringRef close_name = JSStringCreateWithUTF8CString("close");
                                JSObjectRef close_func = JSObjectMakeFunctionWithCallback(global_ctx, close_name, js_websocket_close);
                                JSObjectSetProperty(global_ctx, ws_obj, close_name, close_func, kJSPropertyAttributeNone, NULL);
                                JSStringRelease(close_name);

                                // Set non-blocking
                                fcntl(client_fd, F_SETFL, O_NONBLOCK);

                                // Add to kqueue for frame reading
                                struct kevent ws_ev;
                                EV_SET(&ws_ev, client_fd, EVFILT_READ, EV_ADD, 0, 0, ws_obj);
                                kevent(kq, &ws_ev, 1, NULL, 0, NULL);
                                JSValueProtect(global_ctx, ws_obj);

                                // Don't close client_fd - WebSocket keeps it open
                                continue;  // Skip normal HTTP handling
                            }

                            // Normal HTTP handling - call handler
                            JSValueRef args[] = {req};
                            JSValueRef exception = NULL;
                            JSValueRef result = JSObjectCallAsFunction(global_ctx, srv->handler, NULL, 1, args, &exception);

                            // Build response
                            char response[16384] = {0};
                            if (exception || !result || JSValueIsUndefined(global_ctx, result)) {
                                snprintf(response, sizeof(response),
                                    "HTTP/1.1 500 Internal Server Error\r\n"
                                    "Content-Type: text/plain\r\n"
                                    "Connection: close\r\n\r\n"
                                    "Internal Server Error\r\n");
                            } else {
                                JSObjectRef res_obj = JSValueToObject(global_ctx, result, NULL);

                                // Get status (default 200)
                                int status = 200;
                                JSStringRef status_name = JSStringCreateWithUTF8CString("status");
                                JSValueRef status_val = JSObjectGetProperty(global_ctx, res_obj, status_name, NULL);
                                JSStringRelease(status_name);
                                if (!JSValueIsUndefined(global_ctx, status_val)) {
                                    status = (int)JSValueToNumber(global_ctx, status_val, NULL);
                                }

                                // Get body (default empty)
                                char body[8192] = {0};
                                JSStringRef body_name = JSStringCreateWithUTF8CString("body");
                                JSValueRef body_val = JSObjectGetProperty(global_ctx, res_obj, body_name, NULL);
                                JSStringRelease(body_name);
                                if (!JSValueIsUndefined(global_ctx, body_val)) {
                                    JSStringRef body_str = JSValueToStringCopy(global_ctx, body_val, NULL);
                                    JSStringGetUTF8CString(body_str, body, sizeof(body));
                                    JSStringRelease(body_str);
                                }

                                // Get Content-Type (default text/plain)
                                char content_type[256] = "text/plain";
                                JSStringRef type_name = JSStringCreateWithUTF8CString("type");
                                JSValueRef type_val = JSObjectGetProperty(global_ctx, res_obj, type_name, NULL);
                                JSStringRelease(type_name);
                                if (!JSValueIsUndefined(global_ctx, type_val)) {
                                    JSStringRef type_str = JSValueToStringCopy(global_ctx, type_val, NULL);
                                    JSStringGetUTF8CString(type_str, content_type, sizeof(content_type));
                                    JSStringRelease(type_str);
                                }

                                // Build response with headers
                                char* resp_ptr = response;
                                resp_ptr += snprintf(resp_ptr, sizeof(response) - (resp_ptr - response),
                                    "HTTP/1.1 %d OK\r\n"
                                    "Content-Type: %s\r\n", status, content_type);

                                // Add custom headers if provided
                                JSStringRef headers_name = JSStringCreateWithUTF8CString("headers");
                                JSValueRef headers_val = JSObjectGetProperty(global_ctx, res_obj, headers_name, NULL);
                                JSStringRelease(headers_name);

                                if (!JSValueIsUndefined(global_ctx, headers_val) && JSValueIsObject(global_ctx, headers_val)) {
                                    JSObjectRef headers_obj = JSValueToObject(global_ctx, headers_val, NULL);
                                    JSPropertyNameArrayRef prop_names = JSObjectCopyPropertyNames(global_ctx, headers_obj);
                                    size_t prop_count = JSPropertyNameArrayGetCount(prop_names);

                                    for (size_t i = 0; i < prop_count; i++) {
                                        JSStringRef prop_name = JSPropertyNameArrayGetNameAtIndex(prop_names, i);
                                        JSValueRef prop_val = JSObjectGetProperty(global_ctx, headers_obj, prop_name, NULL);

                                        char header_name[256];
                                        char header_value[1024];
                                        JSStringGetUTF8CString(prop_name, header_name, sizeof(header_name));

                                        JSStringRef val_str = JSValueToStringCopy(global_ctx, prop_val, NULL);
                                        JSStringGetUTF8CString(val_str, header_value, sizeof(header_value));
                                        JSStringRelease(val_str);

                                        resp_ptr += snprintf(resp_ptr, sizeof(response) - (resp_ptr - response),
                                            "%s: %s\r\n", header_name, header_value);
                                    }
                                    JSPropertyNameArrayRelease(prop_names);
                                }

                                // Finish headers and add body
                                resp_ptr += snprintf(resp_ptr, sizeof(response) - (resp_ptr - response),
                                    "Content-Length: %zu\r\n"
                                    "Connection: close\r\n\r\n"
                                    "%s", strlen(body), body);
                            }

                            // Send response
                            send(client_fd, response, strlen(response), 0);
                            drain_microtasks();
                            process_async_ops();
    process_streams();
                        }

                        close(client_fd);
                    }
                    } // End of if (http_srv)
                } else if (events[i].filter == EVFILT_WRITE) {
                    // Handle TCP socket connection completion
                    JSObjectRef obj = (JSObjectRef)events[i].udata;
                    TcpSocket* tcp_sock = JSObjectGetPrivate(obj);

                    if (tcp_sock && !tcp_sock->is_server && tcp_sock->connecting) {
                        tcp_sock->connecting = 0;

                        // Remove EVFILT_WRITE watch
                        struct kevent wev;
                        EV_SET(&wev, tcp_sock->socket_fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
                        kevent(kq, &wev, 1, NULL, 0, NULL);

                        // Check if connection succeeded
                        int error = 0;
                        socklen_t len = sizeof(error);
                        getsockopt(tcp_sock->socket_fd, SOL_SOCKET, SO_ERROR, &error, &len);

                        if (error == 0) {
                            // Connection successful
                            if (tcp_sock->on_connect) {
                                JSObjectCallAsFunction(global_ctx, tcp_sock->on_connect, obj, 0, NULL, NULL);
                            }
                        } else {
                            // Connection failed
                            if (tcp_sock->on_error) {
                                JSStringRef error_str = JSStringCreateWithUTF8CString("Connection failed");
                                JSValueRef error_val = JSValueMakeString(global_ctx, error_str);
                                JSStringRelease(error_str);

                                JSValueRef args[] = {error_val};
                                JSObjectCallAsFunction(global_ctx, tcp_sock->on_error, obj, 1, args, NULL);
                            }
                        }

                        drain_microtasks();
                    }
                }
            }

        // Process ready timers
        uint64_t now = get_time_ms();
        Timer* current = timer_queue;
        while (current) {
            if (!current->cancelled && current->target_time_ms <= now) {
                // Execute timer callback
                JSValueRef exception = NULL;
                JSObjectCallAsFunction(global_ctx, current->callback, NULL, 0, NULL, &exception);

                if (exception) {
                    JSStringRef js_error = JSValueToStringCopy(global_ctx, exception, NULL);
                    size_t max_size = JSStringGetMaximumUTF8CStringSize(js_error);
                    char* error_buffer = malloc(max_size);
                    JSStringGetUTF8CString(js_error, error_buffer, max_size);
                    fprintf(stderr, "Timer error: %s\n", error_buffer);
                    free(error_buffer);
                    JSStringRelease(js_error);
                }

                // Drain microtasks after each macrotask
                drain_microtasks();
                process_async_ops();
    process_streams();

                // Reschedule if interval
                if (current->is_interval) {
                    current->target_time_ms = get_time_ms() + current->interval_ms;
                } else {
                    current->cancelled = 1;
                }
            }
            current = current->next;
        }

        // Clean up cancelled timers
        Timer** ptr = &timer_queue;
        while (*ptr) {
            if ((*ptr)->cancelled) {
                Timer* to_free = *ptr;
                *ptr = (*ptr)->next;
                JSValueUnprotect(global_ctx, to_free->callback);
                free(to_free);
            } else {
                ptr = &(*ptr)->next;
            }
        }
    }

    // Final microtask drain
    drain_microtasks();
    process_async_ops();
    process_streams();

    close(kq);
}

static char* read_file(const char* path) {
    FILE* file = fopen(path, "r");
    if (!file) return NULL;

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* content = malloc(size + 1);
    fread(content, 1, size, file);
    content[size] = '\0';
    fclose(file);

    return content;
}

// Check if specifier is bare (npm package name)
static int is_bare_specifier(const char* specifier) {
    return specifier[0] != '.' && specifier[0] != '/';
}

// Read package.json entry point
static char* read_package_entry(const char* package_dir) {
    char pkg_path[PATH_MAX];
    snprintf(pkg_path, sizeof(pkg_path), "%s/package.json", package_dir);

    char* content = read_file(pkg_path);
    if (!content) return NULL;

    // Simple JSON parsing for "main" or "module" field
    char* entry = NULL;

    // Look for "module" first (ES modules)
    char* module_field = strstr(content, "\"module\"");
    if (module_field) {
        char* value_start = strchr(module_field, ':');
        if (value_start) {
            value_start = strchr(value_start, '"');
            if (value_start) {
                value_start++;
                char* value_end = strchr(value_start, '"');
                if (value_end) {
                    size_t len = value_end - value_start;
                    entry = malloc(len + 1);
                    strncpy(entry, value_start, len);
                    entry[len] = '\0';
                }
            }
        }
    }

    // Fall back to "main"
    if (!entry) {
        char* main_field = strstr(content, "\"main\"");
        if (main_field) {
            char* value_start = strchr(main_field, ':');
            if (value_start) {
                value_start = strchr(value_start, '"');
                if (value_start) {
                    value_start++;
                    char* value_end = strchr(value_start, '"');
                    if (value_end) {
                        size_t len = value_end - value_start;
                        entry = malloc(len + 1);
                        strncpy(entry, value_start, len);
                        entry[len] = '\0';
                    }
                }
            }
        }
    }

    free(content);
    return entry ? entry : strdup("index.js");
}

// Find package in node_modules
static char* find_in_node_modules(const char* start_dir, const char* package_name) {
    char current[PATH_MAX];
    strncpy(current, start_dir, PATH_MAX);

    // Walk up directory tree looking for node_modules
    while (1) {
        char nm_path[PATH_MAX];
        snprintf(nm_path, sizeof(nm_path), "%s/node_modules/%s", current, package_name);

        struct stat st;
        if (stat(nm_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            // Found the package directory
            char* entry = read_package_entry(nm_path);
            char* full_path = malloc(PATH_MAX);
            snprintf(full_path, PATH_MAX, "%s/%s", nm_path, entry);
            free(entry);

            char* real = realpath(full_path, NULL);
            free(full_path);
            return real ? real : strdup(nm_path);
        }

        // Move up one directory
        char* last_slash = strrchr(current, '/');
        if (!last_slash || last_slash == current) {
            break;  // Reached root
        }
        *last_slash = '\0';
    }

    return NULL;
}

static char* resolve_module(const char* base_dir, const char* specifier) {
    char* resolved = malloc(PATH_MAX);

    // Handle bare specifiers (npm packages)
    if (is_bare_specifier(specifier)) {
        char* npm_path = find_in_node_modules(base_dir, specifier);
        if (npm_path) {
            free(resolved);
            return npm_path;
        }
        // If not found in node_modules, fall through to regular resolution
    }

    // Handle absolute paths
    if (specifier[0] == '/') {
        strncpy(resolved, specifier, PATH_MAX);
    } else {
        snprintf(resolved, PATH_MAX, "%s/%s", base_dir, specifier);
    }

    char* real = realpath(resolved, NULL);
    if (real) {
        free(resolved);
        return real;
    }

    return resolved;
}

// Load and execute an ES module
static JSValueRef load_es_module(JSContextRef ctx, const char* path, JSValueRef* exception);

// __krandog_import implementation - dynamic import for transpiled code
static JSValueRef js_krandog_import(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                                     JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                                     const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* module_path = malloc(max_size);
    JSStringGetUTF8CString(path_str, module_path, max_size);
    JSStringRelease(path_str);

    // Handle node: protocol
    const char* actual_module = module_path;
    if (strncmp(module_path, "node:", 5) == 0) {
        actual_module = module_path + 5;  // Skip "node:" prefix
    }

    // Check for built-in modules
    if (strcmp(actual_module, "fs") == 0 || strcmp(actual_module, "path") == 0 ||
        strcmp(actual_module, "child_process") == 0 || strcmp(actual_module, "crypto") == 0 ||
        strcmp(actual_module, "net") == 0 || strcmp(actual_module, "url") == 0 ||
        strcmp(actual_module, "util") == 0 || strcmp(actual_module, "events") == 0 ||
        strcmp(actual_module, "os") == 0 || strcmp(actual_module, "http") == 0 ||
        strcmp(actual_module, "https") == 0 || strcmp(actual_module, "dns") == 0 ||
        strcmp(actual_module, "dgram") == 0 || strcmp(actual_module, "zlib") == 0) {
        JSValueRef result = load_es_module(ctx, actual_module, exception);
        free(module_path);
        return result;
    }

    char* resolved_path = resolve_module(current_dir, module_path);
    free(module_path);

    JSValueRef result = load_es_module(ctx, resolved_path, exception);
    free(resolved_path);

    return result;
}

// Transpile ES module to executable code
static char* transpile_es_module(const char* source, const char* filepath) {
    size_t source_len = strlen(source);
    size_t buffer_size = source_len * 10 + 10000; // Large buffer for transpiled code
    char* transpiled = malloc(buffer_size);
    char* out = transpiled;

    // Get dirname from filepath
    char* filepath_copy = strdup(filepath);
    char* dir = dirname(filepath_copy);

    out += sprintf(out, "(function() {\n");
    out += sprintf(out, "const __filename = '%s';\n", filepath);
    out += sprintf(out, "const __dirname = '%s';\n", dir);
    out += sprintf(out, "const __exports = {};\n");
    out += sprintf(out, "const __default = { value: undefined };\n\n");

    free(filepath_copy);

    // Track exported names for later assignment
    char exported_names[50][256];
    int export_count = 0;

    const char* in = source;
    char* line = malloc(source_len + 1);

    while (*in) {
        // Read one line
        char* line_ptr = line;
        while (*in && *in != '\n') {
            *line_ptr++ = *in++;
        }
        if (*in == '\n') in++;
        *line_ptr = '\0';

        if (strlen(line) == 0) {
            out += sprintf(out, "\n");
            continue;
        }

        char* trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;

        if (strncmp(trimmed, "import ", 7) == 0) {
            char* import_spec = trimmed + 7;

            // import * as name from './file' - check this FIRST
            if (strstr(import_spec, "* as ")) {
                char name[256] = {0};
                char path[512] = {0};
                sscanf(import_spec, "* as %s from '%[^']'", name, path);
                if (path[0] == '\0') {
                    sscanf(import_spec, "* as %s from \"%[^\"]\"", name, path);
                }
                out += sprintf(out, "const %s = __krandog_import('%s');\n", name, path);
            }
            // import default, { named } from './file' - mixed import
            // Check that comma comes BEFORE the brace
            else if (strchr(import_spec, ',') != NULL && strchr(import_spec, '{') != NULL &&
                     strchr(import_spec, ',') < strchr(import_spec, '{')) {
                char default_name[256] = {0};
                char names[512] = {0};
                char path[512] = {0};

                // Parse: "default, { a, b } from './file'"
                sscanf(import_spec, "%[^,]", default_name);
                char* brace_start = strchr(import_spec, '{') + 1;
                char* brace_end = strchr(brace_start, '}');
                if (brace_end) {
                    strncpy(names, brace_start, brace_end - brace_start);
                    char* from = strstr(brace_end, "from");
                    if (from) {
                        sscanf(from, "from '%[^']'", path);
                        if (path[0] == '\0') {
                            sscanf(from, "from \"%[^\"]\"", path);
                        }
                    }
                }

                // Trim default name
                char* dn_end = default_name + strlen(default_name) - 1;
                while (dn_end > default_name && (*dn_end == ' ' || *dn_end == '\t')) dn_end--;
                *(dn_end + 1) = '\0';

                out += sprintf(out, "const __m = __krandog_import('%s');\n", path);
                out += sprintf(out, "const %s = __m.default;\n", default_name);

                // Parse named imports
                char* name = strtok(names, ",");
                while (name) {
                    while (*name == ' ') name++;
                    char* end_ptr = name + strlen(name) - 1;
                    while (end_ptr > name && (*end_ptr == ' ' || *end_ptr == '\n')) end_ptr--;
                    *(end_ptr + 1) = '\0';
                    out += sprintf(out, "const %s = __m.%s;\n", name, name);
                    name = strtok(NULL, ",");
                }
            }
            // import default from './file'
            else if (strchr(import_spec, '{') == NULL && strstr(import_spec, " from ")) {
                char name[256] = {0};
                char path[512] = {0};
                sscanf(import_spec, "%s from '%[^']'", name, path);
                if (path[0] == '\0') {
                    sscanf(import_spec, "%s from \"%[^\"]\"", name, path);
                }
                out += sprintf(out, "const %s = __krandog_import('%s').default;\n", name, path);
            }
            // import { named } from './file'
            else if (strstr(import_spec, "{")) {
                char names[512] = {0};
                char path[512] = {0};
                char* start = strchr(import_spec, '{') + 1;
                char* end = strchr(start, '}');
                if (end) {
                    strncpy(names, start, end - start);
                    char* from = strstr(end, "from");
                    if (from) {
                        sscanf(from, "from '%[^']'", path);
                        if (path[0] == '\0') {
                            sscanf(from, "from \"%[^\"]\"", path);
                        }
                    }
                }
                out += sprintf(out, "const __m = __krandog_import('%s');\n", path);
                char* name = strtok(names, ",");
                while (name) {
                    while (*name == ' ') name++;
                    char* end_ptr = name + strlen(name) - 1;
                    while (end_ptr > name && (*end_ptr == ' ' || *end_ptr == '\n')) end_ptr--;
                    *(end_ptr + 1) = '\0';
                    out += sprintf(out, "const %s = __m.%s;\n", name, name);
                    name = strtok(NULL, ",");
                }
            }
            else if (strstr(import_spec, "* as ")) {
                char name[256] = {0};
                char path[512] = {0};
                sscanf(import_spec, "* as %s from '%[^']'", name, path);
                if (path[0] == '\0') {
                    sscanf(import_spec, "* as %s from \"%[^\"]\"", name, path);
                }
                out += sprintf(out, "const %s = __krandog_import('%s');\n", name, path);
            }
        }
        else if (strncmp(trimmed, "export default ", 15) == 0) {
            char* expr = trimmed + 15;
            out += sprintf(out, "__default.value = %s;\n", expr);
        }
        else if (strncmp(trimmed, "export function ", 16) == 0) {
            char* rest = trimmed + 7;
            out += sprintf(out, "%s\n", rest);

            // Extract and save function name for later export
            char name[256] = {0};
            sscanf(rest, "function %[^(]", name);
            // Trim whitespace
            char* name_end = name + strlen(name) - 1;
            while (name_end > name && (*name_end == ' ' || *name_end == '\t')) name_end--;
            *(name_end + 1) = '\0';

            strncpy(exported_names[export_count++], name, 256);
        }
        else if (strncmp(trimmed, "export ", 7) == 0 && strchr(trimmed, '{') == NULL) {
            char* rest = trimmed + 7;
            out += sprintf(out, "%s\n", rest);

            // Extract and save variable name
            char type[16] = {0};
            char name[256] = {0};
            sscanf(rest, "%s %[^ =]", type, name);
            strncpy(exported_names[export_count++], name, 256);
        }
        else {
            out += sprintf(out, "%s\n", line);
        }
    }

    free(line);

    // Add all exports at the end
    for (int i = 0; i < export_count; i++) {
        out += sprintf(out, "__exports.%s = %s;\n", exported_names[i], exported_names[i]);
    }

    out += sprintf(out, "\nif (__default.value !== undefined) __exports.default = __default.value;\n");
    out += sprintf(out, "return __exports;\n");
    out += sprintf(out, "})()");

    return transpiled;
}

static JSValueRef load_es_module(JSContextRef ctx, const char* path, JSValueRef* exception) {
    // Check for built-in modules
    if (strcmp(path, "fs") == 0 || strcmp(path, "path") == 0 || strcmp(path, "child_process") == 0 ||
        strcmp(path, "crypto") == 0 || strcmp(path, "net") == 0 || strcmp(path, "url") == 0 ||
        strcmp(path, "util") == 0 || strcmp(path, "events") == 0 || strcmp(path, "os") == 0 ||
        strcmp(path, "http") == 0 || strcmp(path, "https") == 0 || strcmp(path, "dns") == 0 ||
        strcmp(path, "dgram") == 0 || strcmp(path, "zlib") == 0) {
        JSStringRef cache_key = JSStringCreateWithUTF8CString(path);
        JSValueRef cached = JSObjectGetProperty(ctx, module_cache, cache_key, NULL);

        if (!JSValueIsUndefined(ctx, cached)) {
            JSStringRelease(cache_key);
            return cached;
        }

        JSObjectRef builtin_module;
        if (strcmp(path, "fs") == 0) {
            builtin_module = create_fs_module(ctx);
        } else if (strcmp(path, "path") == 0) {
            builtin_module = create_path_module(ctx);
        } else if (strcmp(path, "crypto") == 0) {
            builtin_module = create_crypto_module(ctx);
        } else if (strcmp(path, "net") == 0) {
            builtin_module = create_net_module_final(ctx);
        } else if (strcmp(path, "url") == 0) {
            builtin_module = create_url_module(ctx);
        } else if (strcmp(path, "util") == 0) {
            builtin_module = create_util_module(ctx);
        } else if (strcmp(path, "events") == 0) {
            builtin_module = create_events_module(ctx);
        } else if (strcmp(path, "os") == 0) {
            builtin_module = create_os_module(ctx);
        } else if (strcmp(path, "http") == 0) {
            builtin_module = create_http_module(ctx);
        } else if (strcmp(path, "https") == 0) {
            builtin_module = create_https_module(ctx);
        } else if (strcmp(path, "dns") == 0) {
            builtin_module = create_dns_module(ctx);
        } else if (strcmp(path, "dgram") == 0) {
            builtin_module = create_dgram_module(ctx);
        } else if (strcmp(path, "zlib") == 0) {
            builtin_module = create_zlib_module(ctx);
        } else {
            builtin_module = create_child_process_module(ctx);
        }

        // Wrap in module exports object with default property
        JSObjectRef exports = JSObjectMake(ctx, NULL, NULL);
        JSStringRef default_name = JSStringCreateWithUTF8CString("default");
        JSObjectSetProperty(ctx, exports, default_name, builtin_module, kJSPropertyAttributeNone, NULL);
        JSStringRelease(default_name);

        // Also copy all properties to exports for named imports
        JSPropertyNameArrayRef props = JSObjectCopyPropertyNames(ctx, builtin_module);
        size_t prop_count = JSPropertyNameArrayGetCount(props);
        for (size_t i = 0; i < prop_count; i++) {
            JSStringRef prop_name = JSPropertyNameArrayGetNameAtIndex(props, i);
            JSValueRef prop_value = JSObjectGetProperty(ctx, builtin_module, prop_name, NULL);
            JSObjectSetProperty(ctx, exports, prop_name, prop_value, kJSPropertyAttributeNone, NULL);
        }
        JSPropertyNameArrayRelease(props);

        JSObjectSetProperty(ctx, module_cache, cache_key, exports, kJSPropertyAttributeNone, NULL);
        JSStringRelease(cache_key);
        return exports;
    }

    // Check cache
    JSStringRef cache_key = JSStringCreateWithUTF8CString(path);
    JSValueRef cached = JSObjectGetProperty(ctx, module_cache, cache_key, NULL);

    if (!JSValueIsUndefined(ctx, cached)) {
        JSStringRelease(cache_key);
        return cached;
    }

    // Read module
    char* source = read_file(path);
    if (!source) {
        JSStringRelease(cache_key);
        JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot find module");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Save and switch directory
    char saved_dir[PATH_MAX];
    strncpy(saved_dir, current_dir, PATH_MAX);
    char* module_dir_path = strdup(path);
    char* module_dir = dirname(module_dir_path);
    strncpy(current_dir, module_dir, PATH_MAX);

    // Transpile and execute
    char* transpiled = transpile_es_module(source, path);
    free(source);

    JSStringRef js_code = JSStringCreateWithUTF8CString(transpiled);
    JSValueRef result = JSEvaluateScript(ctx, js_code, NULL, NULL, 1, exception);
    JSStringRelease(js_code);
    free(transpiled);
    free(module_dir_path);

    // Restore directory
    strncpy(current_dir, saved_dir, PATH_MAX);

    if (*exception) {
        JSStringRelease(cache_key);
        return JSValueMakeUndefined(ctx);
    }

    // Cache the result
    JSObjectSetProperty(ctx, module_cache, cache_key, result, kJSPropertyAttributeNone, NULL);
    JSStringRelease(cache_key);

    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <script.js>\n", argv[0]);
        return 1;
    }

    // Store argc/argv globally for process object
    global_argc = argc;
    global_argv = argv;

    char* script_path = realpath(argv[1], NULL);
    if (!script_path) {
        fprintf(stderr, "Error: Cannot resolve path '%s'\n", argv[1]);
        return 1;
    }

    char* source = read_file(script_path);
    if (!source) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", script_path);
        free(script_path);
        return 1;
    }

    // Create JavaScript context
    JSGlobalContextRef ctx = JSGlobalContextCreate(NULL);
    global_ctx = ctx;  // Store for event loop
    JSObjectRef global = JSContextGetGlobalObject(ctx);

    // Initialize module cache
    module_cache = JSObjectMake(ctx, NULL, NULL);

    // Set current directory
    char* script_dir_path = strdup(script_path);
    char* script_dir = dirname(script_dir_path);
    strncpy(current_dir, script_dir, PATH_MAX);
    free(script_dir_path);

    // Initialize curl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Setup runtime APIs
    setup_console(ctx, global);
    setup_timers(ctx, global);
    setup_process(ctx, global);
    setup_http_server(ctx, global);
    setup_test_runner(ctx, global);
    setup_buffer(ctx, global);

    // Setup fetch
    JSStringRef fetch_name = JSStringCreateWithUTF8CString("fetch");
    JSObjectRef fetch_func = JSObjectMakeFunctionWithCallback(ctx, fetch_name, js_fetch);
    JSObjectSetProperty(ctx, global, fetch_name, fetch_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(fetch_name);

    // Setup WebSocket constructor
    JSClassDefinition ws_constructor_def = kJSClassDefinitionEmpty;
    ws_constructor_def.callAsConstructor = js_websocket_constructor;
    JSClassRef ws_constructor_class = JSClassCreate(&ws_constructor_def);
    JSObjectRef ws_constructor = JSObjectMake(ctx, ws_constructor_class, NULL);
    JSClassRelease(ws_constructor_class);

    JSStringRef ws_name = JSStringCreateWithUTF8CString("WebSocket");
    JSObjectSetProperty(ctx, global, ws_name, ws_constructor, kJSPropertyAttributeNone, NULL);
    JSStringRelease(ws_name);

    // Setup TextEncoder constructor
    JSClassDefinition text_encoder_def = kJSClassDefinitionEmpty;
    text_encoder_def.callAsConstructor = js_text_encoder_constructor;
    JSClassRef text_encoder_class = JSClassCreate(&text_encoder_def);
    JSObjectRef text_encoder_constructor = JSObjectMake(ctx, text_encoder_class, NULL);
    JSClassRelease(text_encoder_class);

    JSStringRef text_encoder_name = JSStringCreateWithUTF8CString("TextEncoder");
    JSObjectSetProperty(ctx, global, text_encoder_name, text_encoder_constructor, kJSPropertyAttributeNone, NULL);
    JSStringRelease(text_encoder_name);

    // Setup TextDecoder constructor
    JSClassDefinition text_decoder_def = kJSClassDefinitionEmpty;
    text_decoder_def.callAsConstructor = js_text_decoder_constructor;
    JSClassRef text_decoder_class = JSClassCreate(&text_decoder_def);
    JSObjectRef text_decoder_constructor = JSObjectMake(ctx, text_decoder_class, NULL);
    JSClassRelease(text_decoder_class);

    JSStringRef text_decoder_name = JSStringCreateWithUTF8CString("TextDecoder");
    JSObjectSetProperty(ctx, global, text_decoder_name, text_decoder_constructor, kJSPropertyAttributeNone, NULL);
    JSStringRelease(text_decoder_name);

    // Setup atob function
    JSStringRef atob_name = JSStringCreateWithUTF8CString("atob");
    JSObjectRef atob_func = JSObjectMakeFunctionWithCallback(ctx, atob_name, js_atob);
    JSObjectSetProperty(ctx, global, atob_name, atob_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(atob_name);

    // Setup btoa function
    JSStringRef btoa_name = JSStringCreateWithUTF8CString("btoa");
    JSObjectRef btoa_func = JSObjectMakeFunctionWithCallback(ctx, btoa_name, js_btoa);
    JSObjectSetProperty(ctx, global, btoa_name, btoa_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(btoa_name);

    // Setup URL constructor
    JSClassDefinition url_def = kJSClassDefinitionEmpty;
    url_def.callAsConstructor = js_url_constructor;
    JSClassRef url_class = JSClassCreate(&url_def);
    JSObjectRef url_constructor = JSObjectMake(ctx, url_class, NULL);
    JSClassRelease(url_class);

    JSStringRef url_name = JSStringCreateWithUTF8CString("URL");
    JSObjectSetProperty(ctx, global, url_name, url_constructor, kJSPropertyAttributeNone, NULL);
    JSStringRelease(url_name);

    // Setup URLSearchParams constructor
    JSClassDefinition url_search_params_def = kJSClassDefinitionEmpty;
    url_search_params_def.callAsConstructor = js_url_search_params_constructor;
    JSClassRef url_search_params_class = JSClassCreate(&url_search_params_def);
    JSObjectRef url_search_params_constructor = JSObjectMake(ctx, url_search_params_class, NULL);
    JSClassRelease(url_search_params_class);

    JSStringRef url_search_params_name = JSStringCreateWithUTF8CString("URLSearchParams");
    JSObjectSetProperty(ctx, global, url_search_params_name, url_search_params_constructor, kJSPropertyAttributeNone, NULL);
    JSStringRelease(url_search_params_name);

    // Setup AbortController constructor
    JSClassDefinition abort_controller_def = kJSClassDefinitionEmpty;
    abort_controller_def.callAsConstructor = js_abort_controller_constructor;
    JSClassRef abort_controller_class = JSClassCreate(&abort_controller_def);
    JSObjectRef abort_controller_constructor = JSObjectMake(ctx, abort_controller_class, NULL);
    JSClassRelease(abort_controller_class);

    JSStringRef abort_controller_name = JSStringCreateWithUTF8CString("AbortController");
    JSObjectSetProperty(ctx, global, abort_controller_name, abort_controller_constructor, kJSPropertyAttributeNone, NULL);
    JSStringRelease(abort_controller_name);

    // Setup __krandog_import for module loading
    JSStringRef import_name = JSStringCreateWithUTF8CString("__krandog_import");
    JSObjectRef import_func = JSObjectMakeFunctionWithCallback(ctx, import_name, js_krandog_import);
    JSObjectSetProperty(ctx, global, import_name, import_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(import_name);

    // Setup stream helpers
    JSStringRef stream_write_name = JSStringCreateWithUTF8CString("__stream_write");
    JSObjectRef stream_write_func = JSObjectMakeFunctionWithCallback(ctx, stream_write_name, js_stream_write);
    JSObjectSetProperty(ctx, global, stream_write_name, stream_write_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(stream_write_name);

    JSStringRef stream_end_name = JSStringCreateWithUTF8CString("__stream_end");
    JSObjectRef stream_end_func = JSObjectMakeFunctionWithCallback(ctx, stream_end_name, js_stream_end);
    JSObjectSetProperty(ctx, global, stream_end_name, stream_end_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(stream_end_name);

    // Setup UDP helpers
    JSStringRef udp_bind_name = JSStringCreateWithUTF8CString("__udp_bind");
    JSObjectRef udp_bind_func = JSObjectMakeFunctionWithCallback(ctx, udp_bind_name, js_udp_bind);
    JSObjectSetProperty(ctx, global, udp_bind_name, udp_bind_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(udp_bind_name);

    JSStringRef udp_send_name = JSStringCreateWithUTF8CString("__udp_send");
    JSObjectRef udp_send_func = JSObjectMakeFunctionWithCallback(ctx, udp_send_name, js_udp_send);
    JSObjectSetProperty(ctx, global, udp_send_name, udp_send_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(udp_send_name);

    JSStringRef udp_on_message_name = JSStringCreateWithUTF8CString("__udp_on_message");
    JSObjectRef udp_on_message_func = JSObjectMakeFunctionWithCallback(ctx, udp_on_message_name, js_udp_on_message);
    JSObjectSetProperty(ctx, global, udp_on_message_name, udp_on_message_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(udp_on_message_name);

    JSStringRef udp_on_error_name = JSStringCreateWithUTF8CString("__udp_on_error");
    JSObjectRef udp_on_error_func = JSObjectMakeFunctionWithCallback(ctx, udp_on_error_name, js_udp_on_error);
    JSObjectSetProperty(ctx, global, udp_on_error_name, udp_on_error_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(udp_on_error_name);

    JSStringRef udp_close_name = JSStringCreateWithUTF8CString("__udp_close");
    JSObjectRef udp_close_func = JSObjectMakeFunctionWithCallback(ctx, udp_close_name, js_udp_close);
    JSObjectSetProperty(ctx, global, udp_close_name, udp_close_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(udp_close_name);

    JSValueRef exception = NULL;

    // Check if it's an ES module
    int is_module = strstr(source, "import ") != NULL || strstr(source, "export ") != NULL;

    if (is_module) {
        char* transpiled = transpile_es_module(source, script_path);
        JSStringRef js_code = JSStringCreateWithUTF8CString(transpiled);
        JSEvaluateScript(ctx, js_code, NULL, NULL, 1, &exception);
        JSStringRelease(js_code);
        free(transpiled);
    } else {
        // Set __dirname and __filename for non-module scripts
        char* script_dir_copy = strdup(script_path);
        char* dir = dirname(script_dir_copy);

        JSStringRef dirname_name = JSStringCreateWithUTF8CString("__dirname");
        JSStringRef dirname_value = JSStringCreateWithUTF8CString(dir);
        JSObjectSetProperty(ctx, global, dirname_name, JSValueMakeString(ctx, dirname_value), kJSPropertyAttributeNone, NULL);
        JSStringRelease(dirname_name);
        JSStringRelease(dirname_value);

        JSStringRef filename_name = JSStringCreateWithUTF8CString("__filename");
        JSStringRef filename_value = JSStringCreateWithUTF8CString(script_path);
        JSObjectSetProperty(ctx, global, filename_name, JSValueMakeString(ctx, filename_value), kJSPropertyAttributeNone, NULL);
        JSStringRelease(filename_name);
        JSStringRelease(filename_value);

        free(script_dir_copy);

        JSStringRef js_code = JSStringCreateWithUTF8CString(source);
        JSEvaluateScript(ctx, js_code, NULL, NULL, 1, &exception);
        JSStringRelease(js_code);
    }

    free(source);
    free(script_path);

    if (exception) {
        JSStringRef js_error = JSValueToStringCopy(ctx, exception, NULL);
        size_t max_size = JSStringGetMaximumUTF8CStringSize(js_error);
        char* error_buffer = malloc(max_size);
        JSStringGetUTF8CString(js_error, error_buffer, max_size);
        fprintf(stderr, "Error: %s\n", error_buffer);
        free(error_buffer);
        JSStringRelease(js_error);
        JSGlobalContextRelease(ctx);
        return 1;
    }

    // Run event loop to process timers
    run_event_loop();

    // Cleanup
    curl_global_cleanup();

    JSGlobalContextRelease(ctx);
    return 0;
}
