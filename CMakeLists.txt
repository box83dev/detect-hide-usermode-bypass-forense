cmake_minimum_required(VERSION 3.20)
project(unhide VERSION 1.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_executable(unhide
  src/main.cpp
  src/core/models.cpp
  src/utils/registry.cpp
  src/utils/signature.cpp
  src/utils/processes.cpp
  src/scan/config.cpp
  src/scan/files.cpp
  src/scan/compare.cpp
  src/detection/modules.cpp
  src/detection/hooks.cpp
  src/detection/persistence.cpp
  src/report/console.cpp
  src/report/report.cpp
)
target_include_directories(unhide PRIVATE include)
target_link_libraries(unhide PRIVATE psapi wintrust crypt32 advapi32 shell32)
if(MSVC)
  target_compile_options(unhide PRIVATE /W4 /EHsc /utf-8)
endif()
set_target_properties(unhide PROPERTIES OUTPUT_NAME unhide)
install(TARGETS unhide RUNTIME DESTINATION bin)
