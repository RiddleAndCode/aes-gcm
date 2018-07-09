
file(GLOB SOURCES "*.c")
add_library(aesgcm STATIC
    ${SOURCES}
)
 
target_include_directories(aesgcm PUBLIC
    ../include
)