include_directories(.)

add_library(ethsnarks_jubjub STATIC
  curve.cpp
  pedersen_commitment.cpp
)
