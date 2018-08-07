include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft)


add_library(miximus SHARED miximus.cpp)
target_link_libraries(miximus snark)
set_property(TARGET miximus PROPERTY POSITION_INDEPENDENT_CODE ON)


add_library(hashpreimage SHARED mod/hashpreimage.cpp)
target_link_libraries(hashpreimage snark)
set_property(TARGET hashpreimage PROPERTY POSITION_INDEPENDENT_CODE ON)


add_executable(miximus_genKeys miximus_genKeys.cpp)
target_link_libraries(miximus_genKeys miximus)


add_executable(hashpreimage_cli hashpreimage_cli.cpp)
target_link_libraries(hashpreimage_cli snark)


add_executable(verify verify.cpp)
target_link_libraries(verify snark)


add_executable(test_vk_raw2json test/test_vk_raw2json.cpp)
target_link_libraries(test_vk_raw2json snark)


add_executable(test_load_proofkey test/test_load_proofkey.cpp)
target_link_libraries(test_load_proofkey snark)


add_executable(test_shamir_poly test/test_shamir_poly.cpp)
target_link_libraries(test_shamir_poly snark)


add_executable(test_sha256_full_gadget test/test_sha256_full_gadget.cpp)
target_link_libraries(test_sha256_full_gadget snark)


add_executable(test_proof_raw2json test/test_proof_raw2json.cpp)
target_link_libraries(test_proof_raw2json snark)


add_executable(test_field_packing test/test_field_packing.cpp)
target_link_libraries(test_field_packing snark)


add_executable(test_hashpreimage test/test_hashpreimage.cpp)
target_link_libraries(test_hashpreimage snark)


add_executable(test_one_of_n test/test_one_of_n.cpp)
target_link_libraries(test_one_of_n snark)
