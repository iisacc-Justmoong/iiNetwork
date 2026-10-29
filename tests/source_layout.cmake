if(NOT SOURCE_ROOT)
    message(FATAL_ERROR "SOURCE_ROOT is required")
endif()
if(EXISTS "${SOURCE_ROOT}/src/iiNetwork")
    message(FATAL_ERROR "The source tree must not repeat the project name")
endif()
foreach(_file Core/Network.h Core/Network.cpp Core/Layers.h Core/Layers.cpp
        Transport/Transport.h Transport/Transport.cpp Security/Tls.h Security/Tls.cpp
        Session/Session.h Session/Session.cpp Presentation/Presentation.h Presentation/Presentation.cpp
        Application/Application.h Application/Application.cpp Application/Realtime.h Application/Realtime.cpp)
    if(NOT EXISTS "${SOURCE_ROOT}/src/${_file}")
        message(FATAL_ERROR "Missing source in its responsibility directory: ${_file}")
    endif()
endforeach()
