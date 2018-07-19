include_directories(.)

add_library(
  miximus
  SHARED
  miximus.cpp
)

target_link_libraries(
  miximus
  snark
)


add_executable(
  miximus_genKeys
  miximus_genKeys.cpp
)
target_link_libraries(
  miximus_genKeys
  miximus
)

add_executable(
  verify
  verify.cpp
)
target_link_libraries(
  verify
  miximus
)


add_executable(
  tests
  tests.cpp
)
target_link_libraries(
  tests
  miximus
)

add_executable(
  test_vkraw2json
  test_vkraw2json.cpp
)
target_link_libraries(
  test_vkraw2json
  miximus
)


add_executable(
  test_proof_raw2json
  test_proof_raw2json.cpp
)
target_link_libraries(
  test_proof_raw2json
  miximus
)

set_property(TARGET miximus PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(
  miximus
  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
