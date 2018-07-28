#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

char *hashpreimage_prove( const char *pk_file, const uint8_t *preimage_bytes64 );

int hashpreimage_genkeys( const char *pk_file, const char *vk_file );

bool hashpreimage_verify( const char *vk_json, const char *proof_json );

#ifdef __cplusplus
} // extern "C"
#endif
