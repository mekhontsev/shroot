# Component assertions remain in their existing C fixtures. CTest owns only
# invocation, isolation and failure bounds, independently of Android transports.
if(CMAKE_CROSSCOMPILING)
    return()
endif()
find_package(Python3 COMPONENTS Interpreter REQUIRED)
set(component_runner "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_component.py")
add_custom_target(shroot-check-fixtures DEPENDS
    shroot-cli test_client test_client_worker test_client_integration client-guest
    bootstrap supervisor run service image test_database test_image_registry test_host_policy)
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
shroot_component(lwip_context test_lwip_context)
foreach(mode exit kill exec exec-fault exec-real-first exec-private-first exec-directed
        subreaper-exit subreaper-kill subreaper-ignore subreaper-nochildwait
        subreaper-readers subreaper-readers-kill subreaper-reader-reap)
    shroot_component(robust_futex_${mode} test_robust_futex --native ${mode})
endforeach()
shroot_component(elf test_elf @WORK@/elf)
foreach(name inodes schema snapshot image_layer)
    shroot_component(${name} test_${name} @WORK@/store)
endforeach()
add_test(NAME oci COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_oci.py" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(oci library registry client_runtime PROPERTIES LABELS integration TIMEOUT 180)
