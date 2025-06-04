cmake_minimum_required(VERSION 3.10)
project(heresy)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找必要的库
find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(fmt REQUIRED)  # 用于格式化输出
find_package(nlohmann_json REQUIRED)  # 用于处理JSON

# 收集源文件
file(GLOB SOURCES "src/*.cpp")

# 生成可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

# 包含目录
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# 链接库
target_link_libraries(${PROJECT_NAME} PRIVATE
    CURL::libcurl
    SQLite::SQLite3
    fmt::fmt
    nlohmann_json::nlohmann_json
)

# 安装目标
install(TARGETS ${PROJECT_NAME} DESTINATION bin) 