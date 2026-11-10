string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef nonce)
set(work "${PROJECT_BUILD}/curl-contract-${nonce}")
execute_process(COMMAND "${CMAKE_COMMAND}" -S "${PROJECT_SOURCE}/tests/cmake/curl_alias" -B "${work}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
file(REMOVE_RECURSE "${work}")
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Curl alias configure failed (${result}): ${output}\n${error}")
endif()
