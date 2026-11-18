# Publish this SDK's extensionless C++ header from its own export targets.
# Deferred registration sees the optional targets enabled by this configuration.
function(_iisdk_iinetwork_module_imports)
    set(_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../src/ModuleImports")
    set(_entries "iiNetwork|IISDK_IMPORT_IINETWORK_ALL")
    set(_includedir "${CMAKE_INSTALL_INCLUDEDIR}")
    if(NOT _includedir)
        set(_includedir include)
    endif()
    set(_publish FALSE)
    foreach(_entry IN LISTS _entries)
        string(REPLACE "|" ";" _fields "${_entry}")
        list(GET _fields 0 _target)
        list(GET _fields 1 _capability)
        if(NOT TARGET "${_target}")
            continue()
        endif()
        set(_publish TRUE)
        # The directory is exported as a relocatable usage requirement.
        target_include_directories("${_target}" INTERFACE
            "$<BUILD_INTERFACE:${_root}>"
            "$<INSTALL_INTERFACE:${_includedir}/iisdk>")
        target_compile_definitions("${_target}" INTERFACE "${_capability}=1")
    endforeach()
    if(_publish)
        install(FILES "${_root}/iiNetwork" DESTINATION "${_includedir}/iisdk")
    endif()
endfunction()

cmake_language(DEFER CALL _iisdk_iinetwork_module_imports)
