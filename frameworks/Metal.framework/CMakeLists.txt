set(MTL_SRCS
    Sources/Metal.mm
    Sources/MTLCommands.mm
    Sources/MTLDevice.mm
    Sources/MTLObjects.mm
    Sources/MTLPipeline.mm
    Sources/MTLRaytracing.mm
    Sources/MTLResource.mm
)
add_library(Metal SHARED ${MTL_SRCS})
#target_link_libraries(Foundation CoreFoundation)
set_target_properties(Metal PROPERTIES
	INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}"
	COMPILE_FLAGS "-Xclang -fblocks -fobjc-runtime=gnustep-2.0 -x objective-c++"
	LINKER_LANGUAGE C
)