find_package(LLVM REQUIRED CONFIG)
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")


add_executable(metal-dis AppleIRDump.cpp)

target_include_directories(metal-dis
  PUBLIC  ${LLVM_INCLUDE_DIRS})

target_compile_features(metal-dis PRIVATE cxx_std_14)

llvm_map_components_to_libnames(LLVM_LIBRARIES core)

target_link_libraries(metal-dis ${LLVM_LIBRARIES} LLVMBitReader)