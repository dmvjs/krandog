#include <JavaScriptCore/JavaScriptCore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>

// Global module cache
static JSObjectRef module_cache = NULL;

// Current working directory for module resolution
static char current_dir[PATH_MAX];

// Read file contents
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

// Resolve module path (handle ./ and relative paths)
static char* resolve_path(const char* from_dir, const char* module_path) {
    char* resolved = malloc(PATH_MAX);

    if (module_path[0] == '/') {
        // Absolute path
        strncpy(resolved, module_path, PATH_MAX);
    } else {
        // Relative path
        snprintf(resolved, PATH_MAX, "%s/%s", from_dir, module_path);
    }

    // Normalize the path (resolve ..)
    char* real = realpath(resolved, NULL);
    if (real) {
        free(resolved);
        return real;
    }

    return resolved;
}

// require() implementation
static JSValueRef js_require(JSContextRef ctx, JSObjectRef function __attribute__((unused)),
                             JSObjectRef thisObject __attribute__((unused)), size_t argumentCount,
                             const JSValueRef arguments[], JSValueRef* exception) {
    if (argumentCount < 1) {
        return JSValueMakeUndefined(ctx);
    }

    // Get the module path
    JSStringRef path_str = JSValueToStringCopy(ctx, arguments[0], exception);
    if (*exception) return JSValueMakeUndefined(ctx);

    size_t max_size = JSStringGetMaximumUTF8CStringSize(path_str);
    char* module_path = malloc(max_size);
    JSStringGetUTF8CString(path_str, module_path, max_size);
    JSStringRelease(path_str);

    // Resolve the full path
    char* resolved_path = resolve_path(current_dir, module_path);
    free(module_path);

    // Check cache
    JSStringRef cache_key = JSStringCreateWithUTF8CString(resolved_path);
    JSValueRef cached = JSObjectGetProperty(ctx, module_cache, cache_key, NULL);

    if (!JSValueIsUndefined(ctx, cached)) {
        JSStringRelease(cache_key);
        free(resolved_path);
        return cached;
    }

    // Read module file
    char* source = read_file(resolved_path);
    if (!source) {
        free(resolved_path);
        JSStringRelease(cache_key);

        // Create error
        JSStringRef error_str = JSStringCreateWithUTF8CString("Cannot find module");
        *exception = JSValueMakeString(ctx, error_str);
        JSStringRelease(error_str);
        return JSValueMakeUndefined(ctx);
    }

    // Create module object
    JSObjectRef module = JSObjectMake(ctx, NULL, NULL);
    JSObjectRef exports = JSObjectMake(ctx, NULL, NULL);

    JSStringRef exports_name = JSStringCreateWithUTF8CString("exports");
    JSObjectSetProperty(ctx, module, exports_name, exports, kJSPropertyAttributeNone, NULL);
    JSStringRelease(exports_name);

    // Save current directory and switch to module's directory
    char saved_dir[PATH_MAX];
    strncpy(saved_dir, current_dir, PATH_MAX);

    char* module_dir_path = strdup(resolved_path);
    char* module_dir = dirname(module_dir_path);
    strncpy(current_dir, module_dir, PATH_MAX);

    // Wrap module code in a function to create scope
    size_t wrapped_size = strlen(source) + 256;
    char* wrapped = malloc(wrapped_size);
    snprintf(wrapped, wrapped_size,
        "(function(module, exports) {\n%s\n})",
        source);

    // Execute the module
    JSStringRef wrapped_str = JSStringCreateWithUTF8CString(wrapped);
    JSValueRef fn_value = JSEvaluateScript(ctx, wrapped_str, NULL, NULL, 1, exception);
    JSStringRelease(wrapped_str);
    free(wrapped);
    free(source);

    if (*exception) {
        free(resolved_path);
        free(module_dir_path);
        JSStringRelease(cache_key);
        strncpy(current_dir, saved_dir, PATH_MAX);
        return JSValueMakeUndefined(ctx);
    }

    // Call the module function with module and exports
    JSObjectRef fn = JSValueToObject(ctx, fn_value, exception);
    if (*exception) {
        free(resolved_path);
        free(module_dir_path);
        JSStringRelease(cache_key);
        strncpy(current_dir, saved_dir, PATH_MAX);
        return JSValueMakeUndefined(ctx);
    }

    JSValueRef args[2] = { module, exports };
    JSObjectCallAsFunction(ctx, fn, NULL, 2, args, exception);

    // Restore directory
    strncpy(current_dir, saved_dir, PATH_MAX);
    free(module_dir_path);

    if (*exception) {
        free(resolved_path);
        JSStringRelease(cache_key);
        return JSValueMakeUndefined(ctx);
    }

    // Get module.exports (might have been reassigned)
    JSStringRef module_exports_name = JSStringCreateWithUTF8CString("exports");
    JSValueRef result = JSObjectGetProperty(ctx, module, module_exports_name, NULL);
    JSStringRelease(module_exports_name);

    // Cache the result
    JSObjectSetProperty(ctx, module_cache, cache_key, result, kJSPropertyAttributeNone, NULL);
    JSStringRelease(cache_key);
    free(resolved_path);

    return result;
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

// Set up the console object
void setup_console(JSContextRef ctx, JSObjectRef global) {
    // Create console object
    JSObjectRef console = JSObjectMake(ctx, NULL, NULL);

    // Create console.log function
    JSStringRef log_name = JSStringCreateWithUTF8CString("log");
    JSObjectRef log_func = JSObjectMakeFunctionWithCallback(ctx, log_name, js_console_log);
    JSObjectSetProperty(ctx, console, log_name, log_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(log_name);

    // Attach console to global
    JSStringRef console_name = JSStringCreateWithUTF8CString("console");
    JSObjectSetProperty(ctx, global, console_name, console, kJSPropertyAttributeNone, NULL);
    JSStringRelease(console_name);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <script.js>\n", argv[0]);
        return 1;
    }

    // Read the file
    FILE* file = fopen(argv[1], "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", argv[1]);
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* script = malloc(file_size + 1);
    fread(script, 1, file_size, file);
    script[file_size] = '\0';
    fclose(file);

    // Create JavaScript context
    JSGlobalContextRef ctx = JSGlobalContextCreate(NULL);
    JSObjectRef global = JSContextGetGlobalObject(ctx);

    // Initialize module cache
    module_cache = JSObjectMake(ctx, NULL, NULL);

    // Set current directory to the script's directory
    char* script_path = realpath(argv[1], NULL);
    if (script_path) {
        char* script_dir_path = strdup(script_path);
        char* script_dir = dirname(script_dir_path);
        strncpy(current_dir, script_dir, PATH_MAX);
        free(script_path);
        free(script_dir_path);
    } else {
        getcwd(current_dir, PATH_MAX);
    }

    // Setup runtime APIs
    setup_console(ctx, global);

    // Setup require()
    JSStringRef require_name = JSStringCreateWithUTF8CString("require");
    JSObjectRef require_func = JSObjectMakeFunctionWithCallback(ctx, require_name, js_require);
    JSObjectSetProperty(ctx, global, require_name, require_func, kJSPropertyAttributeNone, NULL);
    JSStringRelease(require_name);

    // Execute JavaScript
    JSStringRef js_script = JSStringCreateWithUTF8CString(script);
    JSValueRef exception = NULL;
    JSEvaluateScript(ctx, js_script, NULL, NULL, 1, &exception);

    if (exception) {
        JSStringRef js_error = JSValueToStringCopy(ctx, exception, NULL);
        size_t max_size = JSStringGetMaximumUTF8CStringSize(js_error);
        char* error_buffer = malloc(max_size);
        JSStringGetUTF8CString(js_error, error_buffer, max_size);
        fprintf(stderr, "Error: %s\n", error_buffer);
        free(error_buffer);
        JSStringRelease(js_error);
        free(script);
        JSStringRelease(js_script);
        JSGlobalContextRelease(ctx);
        return 1;
    }

    free(script);
    JSStringRelease(js_script);
    JSGlobalContextRelease(ctx);

    return 0;
}
