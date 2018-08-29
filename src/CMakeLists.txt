include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft)

add_library(ethsnarks_common STATIC export.cpp import.cpp stubs.cpp utils.cpp)
target_link_libraries(ethsnarks_common snark)

add_library(miximus_objs OBJECT mod/miximus.cpp)

add_library(miximus_static STATIC $<TARGET_OBJECTS:miximus_objs>)
target_link_libraries(miximus_static ethsnarks_common)

add_library(miximus SHARED $<TARGET_OBJECTS:miximus_objs>)
target_link_libraries(miximus miximus_static)
set_property(TARGET miximus PROPERTY POSITION_INDEPENDENT_CODE ON)

add_library(hashpreimage SHARED mod/hashpreimage.cpp)
target_link_libraries(hashpreimage ethsnarks_common)
set_property(TARGET hashpreimage PROPERTY POSITION_INDEPENDENT_CODE ON)


add_executable(miximus_cli miximus_cli.cpp)
target_link_libraries(miximus_cli miximus_static)


add_executable(hashpreimage_cli hashpreimage_cli.cpp)
target_link_libraries(hashpreimage_cli ethsnarks_common)


add_executable(verify verify.cpp)
target_link_libraries(verify ethsnarks_common)


add_executable(test_vk_raw2json test/test_vk_raw2json.cpp)
target_link_libraries(test_vk_raw2json ethsnarks_common)


add_executable(test_load_proofkey test/test_load_proofkey.cpp)
target_link_libraries(test_load_proofkey ethsnarks_common)


add_executable(test_shamir_poly test/test_shamir_poly.cpp)
target_link_libraries(test_shamir_poly ethsnarks_common)


add_executable(test_sha256_full_gadget test/test_sha256_full_gadget.cpp)
target_link_libraries(test_sha256_full_gadget ethsnarks_common)


add_executable(test_proof_raw2json test/test_proof_raw2json.cpp)
target_link_libraries(test_proof_raw2json ethsnarks_common)


add_executable(test_field_packing test/test_field_packing.cpp)
target_link_libraries(test_field_packing ethsnarks_common)


add_executable(test_hashpreimage test/test_hashpreimage.cpp)
target_link_libraries(test_hashpreimage ethsnarks_common)


add_executable(test_one_of_n test/test_one_of_n.cpp)
target_link_libraries(test_one_of_n ethsnarks_common)


add_executable(test_longsightf test/test_longsightf.cpp)
target_link_libraries(test_longsightf ethsnarks_common)


add_executable(test_longsightf_bits test/test_longsightf_bits.cpp)
target_link_libraries(test_longsightf_bits ethsnarks_common)


add_executable(test_longsightf_merkletree test/test_longsightf_merkletree.cpp)
target_link_libraries(test_longsightf_merkletree ethsnarks_common)


add_executable(test_r1cs_gg_ppzksnark_zok r1cs_gg_ppzksnark_zok/tests/test_r1cs_gg_zok_ppzksnark.cpp)
target_link_libraries(test_r1cs_gg_ppzksnark_zok ethsnarks_common)

