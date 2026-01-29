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

    return fs;
}

// Console.log implementation
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
    JSStringRef log_name = JSStringCreateWithUTF8CString("log");
    JSObjectRef log_func = JSObjectMakeFunctionWithCallback(ctx, log_name, js_console_log);
    JSObjectSetProperty(ctx, console, log_name, log_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(log_name);

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

// Event loop - process timers and microtasks
void run_event_loop() {
    kq = kqueue();
    if (kq == -1) {
        return;
    }

    // Drain initial microtasks from script execution
    drain_microtasks();

    while (timer_queue) {
        // Find next timer to fire
        Timer* next = NULL;
        uint64_t now = get_time_ms();
        uint64_t min_time = UINT64_MAX;

        Timer* current = timer_queue;
        while (current) {
            if (!current->cancelled && current->target_time_ms < min_time) {
                min_time = current->target_time_ms;
                next = current;
            }
            current = current->next;
        }

        if (!next) break;

        // Wait until timer is ready
        now = get_time_ms();
        if (next->target_time_ms > now) {
            usleep((next->target_time_ms - now) * 1000);
        }

        // Execute callback (macrotask)
        if (!next->cancelled) {
            JSValueRef exception = NULL;
            JSObjectCallAsFunction(global_ctx, next->callback, NULL, 0, NULL, &exception);

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

            // Reschedule if interval
            if (next->is_interval) {
                next->target_time_ms = get_time_ms() + next->interval_ms;
            } else {
                next->cancelled = 1;
            }
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

static char* resolve_module(const char* base_dir, const char* specifier) {
    char* resolved = malloc(PATH_MAX);

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

    // Check for built-in modules
    if (strcmp(module_path, "fs") == 0 || strcmp(module_path, "path") == 0) {
        JSValueRef result = load_es_module(ctx, module_path, exception);
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
static char* transpile_es_module(const char* source) {
    size_t source_len = strlen(source);
    size_t buffer_size = source_len * 10 + 10000; // Large buffer for transpiled code
    char* transpiled = malloc(buffer_size);
    char* out = transpiled;

    out += sprintf(out, "(function() {\n");
    out += sprintf(out, "const __exports = {};\n");
    out += sprintf(out, "const __default = { value: undefined };\n\n");

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
    if (strcmp(path, "fs") == 0 || strcmp(path, "path") == 0) {
        JSStringRef cache_key = JSStringCreateWithUTF8CString(path);
        JSValueRef cached = JSObjectGetProperty(ctx, module_cache, cache_key, NULL);

        if (!JSValueIsUndefined(ctx, cached)) {
            JSStringRelease(cache_key);
            return cached;
        }

        JSObjectRef builtin_module;
        if (strcmp(path, "fs") == 0) {
            builtin_module = create_fs_module(ctx);
        } else {
            builtin_module = create_path_module(ctx);
        }

        // Wrap in module exports object with default property
        JSObjectRef exports = JSObjectMake(ctx, NULL, NULL);
        JSStringRef default_name = JSStringCreateWithUTF8CString("default");
        JSObjectSetProperty(ctx, exports, default_name, builtin_module, kJSPropertyAttributeNone, NULL);
        JSStringRelease(default_name);

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
    char* transpiled = transpile_es_module(source);
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

    // Setup fetch
    JSStringRef fetch_name = JSStringCreateWithUTF8CString("fetch");
    JSObjectRef fetch_func = JSObjectMakeFunctionWithCallback(ctx, fetch_name, js_fetch);
    JSObjectSetProperty(ctx, global, fetch_name, fetch_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(fetch_name);

    // Setup __krandog_import for module loading
    JSStringRef import_name = JSStringCreateWithUTF8CString("__krandog_import");
    JSObjectRef import_func = JSObjectMakeFunctionWithCallback(ctx, import_name, js_krandog_import);
    JSObjectSetProperty(ctx, global, import_name, import_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(import_name);

    JSValueRef exception = NULL;

    // Check if it's an ES module
    int is_module = strstr(source, "import ") != NULL || strstr(source, "export ") != NULL;

    if (is_module) {
        char* transpiled = transpile_es_module(source);
        JSStringRef js_code = JSStringCreateWithUTF8CString(transpiled);
        JSEvaluateScript(ctx, js_code, NULL, NULL, 1, &exception);
        JSStringRelease(js_code);
        free(transpiled);
    } else {
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
