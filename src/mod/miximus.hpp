#ifndef MIXIMUS_HPP_
#define MIXIMUS_HPP_

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

const extern size_t MIXIMUS_TREE_DEPTH;

char *miximus_prove(
    const char *pk_file,
    const char *in_root,
    const char *in_nullifier,
    const char *in_exthash,
    const char *in_spend_preimage,
    const char *in_address,
    const char **in_path
);

int miximus_genkeys( const char *pk_file, const char *vk_file );

bool miximus_verify( const char *vk_json, const char *proof_json );

size_t miximus_tree_depth( void );

#ifdef __cplusplus
}
#endif

#endif
