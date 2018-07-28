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


add_library(mod_hashpreimage SHARED mod_hashpreimage.cpp)
target_link_libraries(mod_hashpreimage snark)
set_property(TARGET mod_hashpreimage PROPERTY POSITION_INDEPENDENT_CODE ON)

add_executable(mod_hashpreimage_genKeys mod_hashpreimage_genKeys.cpp)
target_link_libraries(mod_hashpreimage_genKeys snark)

add_executable(mod_hashpreimage_prove mod_hashpreimage_prove.cpp)
target_link_libraries(mod_hashpreimage_prove snark)



add_executable(verify verify.cpp)
target_link_libraries(verify snark)


add_executable(test_vk_raw2json test_vk_raw2json.cpp)
target_link_libraries(test_vk_raw2json snark)


add_executable(test_load_proofkey test_load_proofkey.cpp)
target_link_libraries(test_load_proofkey snark)


add_executable(test_sha256_full_gadget test_sha256_full_gadget.cpp)
target_link_libraries(test_sha256_full_gadget snark)


add_executable(test_proof_raw2json test_proof_raw2json.cpp)
target_link_libraries(test_proof_raw2json snark)


add_executable(test_field_packing test_field_packing.cpp)
target_link_libraries(test_field_packing snark)
