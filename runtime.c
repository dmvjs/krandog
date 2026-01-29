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

// Module cache
static JSObjectRef module_cache = NULL;
static char current_dir[PATH_MAX];

// Event loop
static JSGlobalContextRef global_ctx = NULL;
static int kq = -1;

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

    // Setup runtime APIs
    setup_console(ctx, global);
    setup_timers(ctx, global);

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

    JSGlobalContextRelease(ctx);
    return 0;
}
