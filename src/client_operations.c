#include "client_internal.h"
#include <errno.h>

static int command(shroot_context *context, const char *name, const char *first,
        const char *second, const struct shroot_io *io, shroot_job **out) {
    struct shroot_arguments args = {0};
    shroot_argument(&args, name);
    if (first) shroot_argument(&args, first);
    if (second) shroot_argument(&args, second);
    return shroot_client_start(context, &args, io, out);
}
static int store_command(shroot_store *store, const char *name, const char *argument,
        const struct shroot_io *io, shroot_job **out) {
    if (!store) { if (out) *out = NULL; return -EINVAL; }
    return command(store->context, name, store->path, argument, io, out);
}
#define STORE_OPERATION(name, operation) \
    int name(shroot_store *store, const struct shroot_io *io, shroot_job **out) { \
        return store_command(store, operation, NULL, io, out); \
    }
STORE_OPERATION(shroot_inspect, "inspect")
STORE_OPERATION(shroot_prepare, "prepare")
STORE_OPERATION(shroot_maintain, "maintain")
STORE_OPERATION(shroot_remove, "remove")
STORE_OPERATION(shroot_sources, "sources")
STORE_OPERATION(shroot_relative_sources, "relative-sources")
STORE_OPERATION(shroot_launches, "launches")
STORE_OPERATION(shroot_applications, "applications")
#undef STORE_OPERATION
#define STORE_ARGUMENT(name, operation) \
    int name(shroot_store *store, const char *argument, const struct shroot_io *io, shroot_job **out) { \
        if (!argument || !*argument) { if (out) *out = NULL; return -EINVAL; } \
        return store_command(store, operation, argument, io, out); \
    }
STORE_ARGUMENT(shroot_clone, "create")
STORE_ARGUMENT(shroot_backup, "backup")
STORE_ARGUMENT(shroot_stop, "stop")
STORE_ARGUMENT(shroot_icon, "icon")
#undef STORE_ARGUMENT
int shroot_import_oci(shroot_context *context, const struct shroot_oci_import *options,
        const struct shroot_io *io, shroot_job **out) {
    struct shroot_arguments args = {0};
    shroot_argument(&args, "import");
    shroot_argument(&args, options ? options->layout : NULL);
    shroot_argument(&args, options ? options->destination : NULL);
    if (options) {
        shroot_argument(&args, options->preserve_ownership ? "--preserve-ownership" : "--map-current-user");
        shroot_option(&args, "--reference", options->reference);
        shroot_option(&args, "--layers", options->layers);
        shroot_option(&args, "--blobs", options->blobs);
    }
    return shroot_client_start(context, &args, io, out);
}
int shroot_import_archive(shroot_context *context, enum shroot_archive_kind kind,
        const char *archive, const char *destination, const struct shroot_io *io, shroot_job **out) {
    if (!archive || !destination || !*archive || !*destination || (kind != SHROOT_ROOTFS && kind != SHROOT_BACKUP)) {
        if (out) *out = NULL;
        return -EINVAL;
    }
    return command(context, kind == SHROOT_ROOTFS ? "rootfs" : "restore", archive, destination, io, out);
}
int shroot_export_tree(shroot_store *store, const char *path, const char *destination,
        const struct shroot_io *io, shroot_job **out) {
    struct shroot_arguments args = {0};
    shroot_argument(&args, "export-tree");
    shroot_argument(&args, store ? store->path : NULL);
    shroot_argument(&args, path); shroot_argument(&args, destination);
    return shroot_client_start(store ? store->context : NULL, &args, io, out);
}
int shroot_resolver(shroot_store *store, const char *servers, int replace,
        const struct shroot_io *io, shroot_job **out) {
    struct shroot_arguments args = {0};
    shroot_argument(&args, "resolver");
    shroot_argument(&args, store ? store->path : NULL);
    shroot_argument(&args, servers);
    if (replace) shroot_argument(&args, "--replace");
    return shroot_client_start(store ? store->context : NULL, &args, io, out);
}
int shroot_recover_staging(shroot_context *context, const char *directory, const struct shroot_io *io, shroot_job **out) {
    if (!directory || !*directory) { if (out) *out = NULL; return -EINVAL; }
    return command(context, "recover-staging", directory, NULL, io, out);
}
int shroot_relocate_library(shroot_context *context, const char *source, const char *destination,
        const struct shroot_io *io, shroot_job **out) {
    if (!source || !*source || !destination || !*destination) { if (out) *out = NULL; return -EINVAL; }
    return command(context, "relocate-library", source, destination, io, out);
}
int shroot_remove_layer(shroot_context *context, const char *path, const struct shroot_io *io, shroot_job **out) {
    if (!path || !*path) { if (out) *out = NULL; return -EINVAL; }
    return command(context, "remove-layer", path, NULL, io, out);
}
int shroot_storage_format(shroot_context *context, const struct shroot_io *io, shroot_job **out) {
    return command(context, "format", NULL, NULL, io, out);
}
int shroot_import_version(shroot_context *context, const struct shroot_io *io, shroot_job **out) {
    return command(context, "import-version", NULL, NULL, io, out);
}
static void options(struct shroot_arguments *args, const char *name, const char *const *values) {
    if (values) for (size_t i = 0; values[i]; ++i) shroot_option(args, name, values[i]);
}
static int launch_command(shroot_context *context, const char *library, const char *selector,
        const struct shroot_launch_options *launch, const struct shroot_io *io, shroot_job **out) {
    struct shroot_arguments args = {0};
    if (!launch || launch->kind < SHROOT_RUN || launch->kind > SHROOT_LOGIN || launch->flags & ~15u
            || (launch->bind_count && !launch->binds) || (launch->route_count && !launch->routes)) {
        if (out) *out = NULL;
        return -EINVAL;
    }
    if (library) { shroot_argument(&args,"library"); shroot_argument(&args,library); }
    shroot_argument(&args, launch->kind == SHROOT_RUN ? "run" : launch->kind == SHROOT_EXEC ? "exec" : "login");
    shroot_argument(&args, selector);
    shroot_option(&args, "--user", launch->user);
    shroot_option(&args, "--cwd", launch->cwd);
    shroot_option(&args, "--entrypoint", launch->entrypoint);
    shroot_option(&args, "--hostname", launch->hostname);
    shroot_option(&args, "--gamepad-endpoint", launch->gamepad_endpoint);
    shroot_option(&args, "--network", launch->network);
    shroot_option(&args, "--ip", launch->ip);
    shroot_option(&args, "--ip6", launch->ip6);
    options(&args, "--subnet", launch->subnets);
    options(&args, "--gateway", launch->gateways);
    options(&args, "--env", launch->environment);
    options(&args, "--dns", launch->dns);
    options(&args, "-p", launch->ports);
    const char *binds[] = {"--bind", "--bind-ro", "--bind-create", "--bind-store-ro", "--bind-ro-create"};
    for (size_t i = 0; i < launch->bind_count; ++i) {
        const struct shroot_bind *bind = &launch->binds[i];
        if (bind->kind < SHROOT_BIND || bind->kind > SHROOT_BIND_READONLY_CREATE) { args.error = -EINVAL; break; }
        shroot_argument(&args, binds[bind->kind]);
        shroot_argument(&args, bind->source); shroot_argument(&args, bind->target);
    }
    for (size_t i = 0; i < launch->route_count; ++i) {
        const struct shroot_socket_route *route = &launch->routes[i];
        const char *names[] = {"--socket-path", "--socket-abstract", "--socket-resource-path", "--socket-resource-abstract"};
        if (route->kind < SHROOT_SOCKET_PATH || route->kind > SHROOT_SOCKET_RESOURCE_ABSTRACT) { args.error = -EINVAL; break; }
        shroot_argument(&args, names[route->kind]);
        shroot_argument(&args, route->source); shroot_argument(&args, route->target);
    }
    if (launch->flags & SHROOT_STATISTICS) shroot_argument(&args, "--statistics");
    if (launch->flags & SHROOT_MAGICDESK_CONNECTION) shroot_argument(&args, "--magicdesk");
    if (launch->flags & (SHROOT_DIAGNOSTICS | SHROOT_SIGNAL_DIAGNOSTICS))
        shroot_argument(&args, launch->flags & SHROOT_SIGNAL_DIAGNOSTICS ? "--diagnostics=signals" : "--diagnostics");
    shroot_argument(&args, "--");
    if (launch->arguments) for (size_t i = 0; launch->arguments[i]; ++i) shroot_argument(&args, launch->arguments[i]);
    return shroot_client_start(context, &args, io, out);
}
int shroot_launch(shroot_store *store,const struct shroot_launch_options *launch,const struct shroot_io *io,shroot_job **out) {
    return launch_command(store ? store->context : NULL,NULL,store ? store->path : NULL,launch,io,out);
}
int shroot_environment_launch(shroot_library *lib,const char *name,const struct shroot_launch_options *launch,
        const struct shroot_io *io,shroot_job **out) {
    return launch_command(lib ? lib->context : NULL,lib ? lib->path : NULL,name,launch,io,out);
}
static void library_arguments(struct shroot_arguments *args,shroot_library *lib,const char *operation) {
    shroot_argument(args,"library");
    shroot_argument(args,lib ? lib->path : NULL);
    shroot_argument(args,operation);
}
static int library_command(shroot_library *lib,const char *operation,const char *first,const char *second,
        const struct shroot_io *io,shroot_job **out) {
    struct shroot_arguments args={0};
    library_arguments(&args,lib,operation);
    if (first) shroot_argument(&args,first);
    if (second) shroot_argument(&args,second);
    return shroot_client_start(lib ? lib->context : NULL,&args,io,out);
}
#define LIBRARY_OPERATION(function,operation) \
    int function(shroot_library *lib,const struct shroot_io *io,shroot_job **out) { \
        return library_command(lib,operation,NULL,NULL,io,out); \
    }
LIBRARY_OPERATION(shroot_library_initialize,"init")
LIBRARY_OPERATION(shroot_library_list,"list")
LIBRARY_OPERATION(shroot_library_prune,"prune")
#undef LIBRARY_OPERATION
#define ENVIRONMENT_OPERATION(function,operation) \
    int function(shroot_library *lib,const char *name,const struct shroot_io *io,shroot_job **out) { \
        if (!name || !*name) { if (out) *out=NULL; return -EINVAL; } \
        return library_command(lib,operation,name,NULL,io,out); \
    }
ENVIRONMENT_OPERATION(shroot_environment_resolve,"resolve")
ENVIRONMENT_OPERATION(shroot_environment_remove,"remove")
#undef ENVIRONMENT_OPERATION
int shroot_environment_install(shroot_library *lib,const struct shroot_install_options *options,
        const struct shroot_io *io,shroot_job **out) {
    if (!options || options->kind<SHROOT_SOURCE_ROOTFS || options->kind>SHROOT_SOURCE_REGISTRY
            || (options->kind!=SHROOT_SOURCE_REGISTRY && (options->ca_file || options->ca_directory))) {
        if (out) *out=NULL;
        return -EINVAL;
    }
    struct shroot_arguments args={0};
    library_arguments(&args,lib,"install");
    const char *kinds[]={"rootfs","oci","registry"};
    shroot_argument(&args,kinds[options->kind]);
    shroot_argument(&args,options->source); shroot_argument(&args,options->name);
    shroot_option(&args,"--resolver",options->resolver);
    shroot_option(&args,"--ca-file",options->ca_file);
    shroot_option(&args,"--ca-directory",options->ca_directory);
    return shroot_client_start(lib ? lib->context : NULL,&args,io,out);
}
int shroot_environment_restore(shroot_library *lib,const char *archive,const char *name,const struct shroot_io *io,shroot_job **out) {
    if (!archive || !name) { if (out) *out=NULL; return -EINVAL; }
    return library_command(lib,"restore",archive,name,io,out);
}
int shroot_environment_backup(shroot_library *lib,const char *name,const char *archive,const struct shroot_io *io,shroot_job **out) {
    if (!archive || !name) { if (out) *out=NULL; return -EINVAL; }
    return library_command(lib,"backup",name,archive,io,out);
}
int shroot_environment_resolver(shroot_library *lib,const char *name,const char *servers,int replace,
        const struct shroot_io *io,shroot_job **out) {
    struct shroot_arguments args={0};
    library_arguments(&args,lib,"resolver");
    shroot_argument(&args,name); shroot_argument(&args,servers);
    if (replace) shroot_argument(&args,"--replace");
    return shroot_client_start(lib ? lib->context : NULL,&args,io,out);
}
