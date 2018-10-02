include_directories(.)


add_library(ethsnarks_common STATIC export.cpp import.cpp stubs.cpp utils.cpp)
target_link_libraries(ethsnarks_common ethsnarks_gadgets ff)

add_library(miximus_objs OBJECT mod/miximus.cpp)

add_library(miximus_static STATIC $<TARGET_OBJECTS:miximus_objs>)
target_link_libraries(miximus_static ethsnarks_common)


add_library(miximus SHARED $<TARGET_OBJECTS:miximus_objs>)
target_link_libraries(miximus ethsnarks_common)
set_property(TARGET miximus PROPERTY POSITION_INDEPENDENT_CODE ON)


add_library(hashpreimage SHARED mod/hashpreimage.cpp)
target_link_libraries(hashpreimage ethsnarks_common crypto)
set_property(TARGET hashpreimage PROPERTY POSITION_INDEPENDENT_CODE ON)


add_executable(miximus_cli miximus_cli.cpp)
target_link_libraries(miximus_cli miximus_static)


add_executable(hashpreimage_cli hashpreimage_cli.cpp)
target_link_libraries(hashpreimage_cli ethsnarks_common crypto)


add_executable(verify verify.cpp)
target_link_libraries(verify ethsnarks_common)


add_subdirectory(test)
add_subdirectory(r1cs_gg_ppzksnark_zok)
add_subdirectory(gadgets)
add_subdirectory(jubjub)
