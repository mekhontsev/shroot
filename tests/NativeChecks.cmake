# Component assertions remain in their existing C fixtures. CTest owns only
# invocation, isolation and failure bounds, independently of Android transports.
if(CMAKE_CROSSCOMPILING)
    return()
endif()
find_package(Python3 COMPONENTS Interpreter REQUIRED)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/list_unittests.py")
add_test(NAME fixture_contracts COMMAND "${Python3_EXECUTABLE}" -m unittest discover
    -s "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit")
set_tests_properties(fixture_contracts PROPERTIES LABELS transport TIMEOUT 120)
set(component_runner "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_component.py")
find_program(SHROOT_HERD7 herd7)
if(SHROOT_HERD7)
    add_test(NAME model_exchange_ordering COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_exchange_ordering.py" --herd "${SHROOT_HERD7}")
    set_tests_properties(model_exchange_ordering PROPERTIES LABELS model TIMEOUT 100)
endif()
add_custom_target(shroot-check-fixtures DEPENDS
    shroot-cli test_client test_client_worker test_client_integration client-guest
    bootstrap supervisor run service image resource_guest test_database test_image_registry test_host_policy
    audit_const audit_mutable audit_weak audit_tls audit_current)
function(shroot_component name target)
    add_dependencies(shroot-check-fixtures ${target})
    add_test(NAME component_${name} COMMAND "${Python3_EXECUTABLE}" "${component_runner}"
        --timeout 90 -- $<TARGET_FILE:${target}> ${ARGN})
    set_tests_properties(component_${name} PROPERTIES LABELS component TIMEOUT 100)
endfunction()
foreach(name socket_routes host_open process_limits pid_namespace mapping_reader
        task_memory received_fds netlink_attributes directory_record interception_memory
        interception_buffers input_devices input_uinput render_device launch_registry
        native_mounts binfmt_rule cooperative_native exchange_model guest_copy freestanding_memory
        signal_delivery seccomp_policy image_arguments argument_vector
        open_job robust_futex)
    shroot_component(${name} test_${name})
endforeach()
foreach(group frame alias native kernel)
    shroot_component(svc_machine_signal_${group} test_svc_machine_signal --group ${group})
endforeach()
foreach(name event_signal pending task_wait fuse_transport supervisor_state file_metadata fd_filter_remote)
    shroot_component(${name} ${name})
endforeach()
foreach(case filters cursors races events epoll weak readiness)
    shroot_component(control_event_${case} control_event --case ${case})
endforeach()
shroot_component(task_wait_idle task_wait_live --idle)
shroot_component(task_wait_small task_wait_live --small)
shroot_component(task_wait_live task_wait_live --live)
shroot_component(task_wait_cancel task_wait_live --cancel)
shroot_component(kernel_baseline kernel_baseline)
shroot_component(fs_worker fs_dispatch --worker-pause @WORK@/store)
shroot_component(broker_identity fs_dispatch --broker-identity @WORK@/store)
add_dependencies(shroot-check-fixtures test_signal_checkpoint)
add_test(NAME component_signal_checkpoint COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_signal_checkpoint.py" "${CMAKE_CURRENT_BINARY_DIR}" --executor local --mode controls)
set_tests_properties(component_signal_checkpoint PROPERTIES LABELS component TIMEOUT 100)
add_test(NAME benchmark_signal_checkpoint COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_signal_checkpoint.py" "${CMAKE_CURRENT_BINARY_DIR}" --executor local --mode benchmark)
set_tests_properties(benchmark_signal_checkpoint PROPERTIES LABELS benchmark TIMEOUT 100 RUN_SERIAL TRUE)
shroot_component(lwip_context test_lwip_context)
add_test(NAME component_os_info COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_os_info.py" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(component_os_info PROPERTIES LABELS component TIMEOUT 30)
foreach(case signals uts mapping ipc registry network route route-lifetimes socket-filter ethernet
        tc endpoint nft launch private-loopback ipv6 tun ownership)
    shroot_component(task_resources_${case} test_task_resources --case ${case})
endforeach()
foreach(mode exit kill exec exec-fault exec-real-first exec-private-first exec-directed
        subreaper-exit subreaper-kill subreaper-ignore subreaper-nochildwait
        subreaper-readers subreaper-readers-kill subreaper-reader-reap)
    shroot_component(robust_futex_${mode} test_robust_futex --native ${mode})
endforeach()
shroot_component(elf test_elf @WORK@/elf)
shroot_component(rpc test_rpc @WORK@/rpc)
shroot_component(rpc_directory_cursor test_rpc --directory-cursor)
shroot_component(rpc_reply_framing test_rpc --reply-framing)
foreach(case namespace native paths metadata recovery)
    shroot_component(inodes_${case} test_inodes @WORK@/store --case ${case})
endforeach()
foreach(name schema snapshot image_layer durability native_leaf publication import)
    shroot_component(${name} test_${name} @WORK@/store)
endforeach()
function(shroot_unittests name)
    set(source "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_${name}.py")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${source}")
    execute_process(COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/list_unittests.py" "${source}"
        OUTPUT_VARIABLE cases OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
    if(NOT cases)
        message(FATAL_ERROR "No unittest cases found in ${source}")
    endif()
    string(REPLACE "\n" ";" cases "${cases}")
    foreach(case IN LISTS cases)
        add_test(NAME ${name}_${case} COMMAND "${Python3_EXECUTABLE}" "${source}"
            "${CMAKE_CURRENT_BINARY_DIR}" "${case}" -v)
        set_tests_properties(${name}_${case} PROPERTIES LABELS integration TIMEOUT 180)
    endforeach()
endfunction()
shroot_unittests(library)
shroot_unittests(oci)
set(client_cases api cli attachments lifetime network)
foreach(case IN LISTS client_cases)
    add_test(NAME client_runtime_${case} COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_client_runtime.py" "${CMAKE_CURRENT_BINARY_DIR}" --case ${case})
    set_tests_properties(client_runtime_${case} PROPERTIES LABELS integration TIMEOUT 180)
endforeach()
add_test(NAME registry COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_registry.py" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(registry PROPERTIES LABELS integration TIMEOUT 180)
add_test(NAME external_folders COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_external_folders.py" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(external_folders PROPERTIES LABELS integration TIMEOUT 180)
foreach(name host_integration local_executor)
    add_test(NAME ${name} COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_${name}.py")
    set_tests_properties(${name} PROPERTIES LABELS transport TIMEOUT 60)
endforeach()
foreach(name bundle_layout lwip_prepare)
    add_test(NAME ${name} COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_${name}.py")
    set_tests_properties(${name} PROPERTIES LABELS packaging TIMEOUT 60)
endforeach()
add_test(NAME native_suite COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_native_suite.py" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(native_suite PROPERTIES LABELS integration TIMEOUT 180)
add_dependencies(shroot-check-fixtures debugger_guest test_signal_delivery test_svc_machine_signal)
set(nested_runner "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_nested_runtime.py")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${nested_runner}")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${nested_runner}"
    "${CMAKE_CURRENT_BINARY_DIR}" --list-scenarios
    OUTPUT_VARIABLE debugger_cases OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
if(NOT debugger_cases)
    message(FATAL_ERROR "No nested debugger cases found")
endif()
string(REPLACE "\n" ";" debugger_cases "${debugger_cases}")
foreach(entry 0 1)
    foreach(case IN LISTS debugger_cases)
        string(REPLACE ":" "_" name "${case}")
        add_test(NAME nested_debugger_${entry}_${name} COMMAND "${Python3_EXECUTABLE}"
            "${nested_runner}" "${CMAKE_CURRENT_BINARY_DIR}" --case debugger --entry ${entry} --scenario "${case}")
        set_tests_properties(nested_debugger_${entry}_${name} PROPERTIES LABELS integration TIMEOUT 180)
    endforeach()
endforeach()
foreach(case signals nested)
    if(case STREQUAL "nested")
        add_test(NAME nested_nested COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_nested_runtime.py" "${CMAKE_CURRENT_BINARY_DIR}" --case nested)
        set_tests_properties(nested_nested PROPERTIES LABELS "integration;recursive" TIMEOUT 180)
    else()
        foreach(entry 0 1)
            add_test(NAME nested_${case}_${entry} COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_nested_runtime.py" "${CMAKE_CURRENT_BINARY_DIR}"
                --case ${case} --entry ${entry})
            set_tests_properties(nested_${case}_${entry} PROPERTIES LABELS integration TIMEOUT 180)
        endforeach()
    endif()
endforeach()
if(SHROOT_STATIC_RUNTIME AND SHROOT_SQLITE STREQUAL "bundled")
    foreach(case IN LISTS client_cases)
        add_test(NAME bundle_${case} COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_bundle.py" "${CMAKE_CURRENT_BINARY_DIR}"
            --case ${case} --cmake "${CMAKE_COMMAND}" --readelf "${CMAKE_READELF}")
        set_tests_properties(bundle_${case} PROPERTIES LABELS integration TIMEOUT 240)
    endforeach()
endif()
