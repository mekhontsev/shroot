# Component assertions remain in their existing C fixtures. CTest owns only
# invocation, isolation and failure bounds, independently of Android transports.
if(CMAKE_CROSSCOMPILING)
    return()
endif()
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME fixture_contracts COMMAND "${Python3_EXECUTABLE}" -m unittest discover
    -s "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit")
set_tests_properties(fixture_contracts PROPERTIES LABELS transport TIMEOUT 120)
set(component_runner "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_component.py")
add_custom_target(shroot-check-fixtures DEPENDS
    shroot-cli test_client test_client_worker test_client_integration client-guest
    bootstrap supervisor run service image test_database test_image_registry test_host_policy
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
        native_mounts binfmt_rule cooperative_native guest_copy freestanding_memory
        signal_delivery seccomp_policy svc_machine_signal image_arguments argument_vector
        open_job robust_futex)
    shroot_component(${name} test_${name})
endforeach()
foreach(name control_event event_signal pending task_wait task_wait_live fuse_transport supervisor_state)
    shroot_component(${name} ${name})
endforeach()
shroot_component(task_wait_idle task_wait_live --idle)
shroot_component(task_wait_small task_wait_live --small)
shroot_component(kernel_baseline kernel_baseline)
add_dependencies(shroot-check-fixtures test_signal_checkpoint)
add_test(NAME component_signal_checkpoint COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_signal_checkpoint.py" "${CMAKE_CURRENT_BINARY_DIR}" --executor local)
set_tests_properties(component_signal_checkpoint PROPERTIES LABELS component TIMEOUT 100)
shroot_component(lwip_context test_lwip_context)
shroot_component(task_resources test_task_resources)
foreach(mode exit kill exec exec-fault exec-real-first exec-private-first exec-directed
        subreaper-exit subreaper-kill subreaper-ignore subreaper-nochildwait
        subreaper-readers subreaper-readers-kill subreaper-reader-reap)
    shroot_component(robust_futex_${mode} test_robust_futex --native ${mode})
endforeach()
shroot_component(elf test_elf @WORK@/elf)
foreach(name inodes schema snapshot image_layer durability native_leaf publication)
    shroot_component(${name} test_${name} @WORK@/store)
endforeach()
add_test(NAME oci COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_oci.py" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(oci library registry client_runtime PROPERTIES LABELS integration TIMEOUT 180)
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
add_dependencies(shroot-check-fixtures debugger_guest)
foreach(case debugger nested)
    add_test(NAME nested_${case} COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_nested_runtime.py" "${CMAKE_CURRENT_BINARY_DIR}" --case ${case})
    set_tests_properties(nested_${case} PROPERTIES LABELS integration TIMEOUT 180)
endforeach()
if(SHROOT_STATIC_RUNTIME AND SHROOT_SQLITE STREQUAL "bundled")
    add_test(NAME bundle COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_bundle.py" "${CMAKE_CURRENT_BINARY_DIR}"
        --cmake "${CMAKE_COMMAND}" --readelf "${CMAKE_READELF}")
    set_tests_properties(bundle PROPERTIES LABELS integration TIMEOUT 240)
endif()
