set (FOUNDATION_SRCS
    Sources/NSString.m
    Sources/NSContainer.m
    Sources/NSObject.m
)

#source_group(string FILES ${FOUNDATION_SRCS})

add_library(Foundation SHARED ${FOUNDATION_SRCS})
#target_link_libraries(Foundation CoreFoundation)
set_target_properties(Foundation PROPERTIES
	INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}"
	COMPILE_FLAGS "-Xclang -fblocks -fobjc-runtime=gnustep-2.0"
	LINKER_LANGUAGE C
)
