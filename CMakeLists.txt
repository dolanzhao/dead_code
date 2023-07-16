cmake_minimum_required(VERSION 3.7)
#项目名字
project(deadcode)
#设置编译版本
set (CMAKE_CXX_STANDARD 14)
# 1.自己项目的头文件和cpp
set(SOURCE_FILES
        src/trace/cpps/main.cpp
        src/trace/headers/directory_iterator.h src/trace/cpps/directory_iterator.cpp
        src/trace/headers/file_reader.h src/trace/cpps/file_reader.cpp
        src/trace/headers/reader.h src/trace/cpps/reader.cpp
        src/trace/headers/record_file_reader.h src/trace/headers/record_file_reader.cpp
        src/trace/headers/memref.h src/trace/headers/memtrace_stream.h src/trace/headers/utils.h
        src/trace/headers/trace_entry.h src/trace/cpps/trace_entry.cpp
        src/trace/headers/analyzer.h src/trace/cpps/analyzer.cpp
        src/trace/headers/analyzer_runner.h src/trace/cpps/analyzer_runner.cpp
        src/trace/headers/analysis_tool.h
        src/trace/headers/dead_code_analysis.h src/trace/cpps/dead_code_analysis.cpp)

# 设置外部库链接
set(ZLIB_INCLUDE src/xed/include)
set(ZLIB_LIBRARIES src/xed/lib)

# 链接外部库
include_directories(${ZLIB_INCLUDE})
link_directories(${ZLIB_LIBRARIES})
find_package (Threads)
# 设置编译文件
add_executable(deadcode ${SOURCE_FILES})

#将第三方库链接在一起
target_link_libraries (deadcode libxed.a Threads::Threads)




