#include <JavaScriptCore/JavaScriptCore.h>
#include <stdio.h>
#include <stdlib.h>

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

    // Setup runtime APIs
    setup_console(ctx, global);

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
