add_library(MetalCLib STATIC
d3d12/dxdevice.cc
vulkan/vkdevice.cc
)

add_library(MetalSwift SHARED
headers/Metal.swift)
# target_sources(MetalSwift PRIVATE
#     d3d12/dxdevice.cc
#     vulkan/vkdevice.cc
# )
  
target_compile_options(MetalSwift PRIVATE
  "SHELL:-Xcc -DNONAMELESSUNION"
  "SHELL:-Xcc -DCOBJMACROS")
target_link_libraries(MetalSwift PUBLIC
  $<$<VERSION_LESS:${CMAKE_Swift_COMPILER_VERSION},5.3>:Gdi32>
  ComCtl32
  User32
  MetalCLib)
if(WITH_SWIFT_LOG)
  target_compile_definitions(MetalSwift PRIVATE
    WITH_SWIFT_LOG)
  if(TARGET SwiftLog::Logging)
    target_link_libraries(MetalSwift PUBLIC
      SwiftLog::Logging)
  endif()
endif()
set_target_properties(MetalSwift PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY}
  INTERFACE_LINK_DIRECTORIES $<TARGET_LINKER_FILE_DIR:MetalSwift>)

swift_install(TARGETS MetalSwift)