cmake_minimum_required(VERSION 3.22.1)
project("system")

# ابحث عن مكتبة Dobby الموجودة مسبقًا
set(DOBBY_LIB ${CMAKE_SOURCE_DIR}/../jniLibs/arm64-v8a/libdobby.so)

# أضف المكتبة الخاصة بك
add_library(system SHARED native-lib.cpp)

# اربط مع المكتبات الضرورية
target_include_directories(system PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(system
    android
    log
    ${DOBBY_LIB}
)
