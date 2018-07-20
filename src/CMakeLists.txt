include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft)

add_library(miximus SHARED miximus.cpp)

target_link_libraries(miximus snark)
set_property(TARGET miximus PROPERTY POSITION_INDEPENDENT_CODE ON)


add_executable(miximus_genKeys miximus_genKeys.cpp)
target_link_libraries(miximus_genKeys miximus)


add_executable(verify verify.cpp)
target_link_libraries(verify snark)


add_executable(test_vk_raw2json test_vk_raw2json.cpp)
target_link_libraries(test_vk_raw2json snark)


add_executable(test_load_proofkey test_load_proofkey.cpp)
target_link_libraries(test_load_proofkey snark)


add_executable(test_proof_raw2json test_proof_raw2json.cpp)
target_link_libraries(test_proof_raw2json snark)

