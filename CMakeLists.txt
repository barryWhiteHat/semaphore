cmake_minimum_required(VERSION 2.8)

project(ethsnarks)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  # Common compilation flags and warning configuration
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wfatal-errors -Wno-unused-variable")
   if("${MULTICORE}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
  endif()
    # Default optimizations flags (to override, use -DOPT_FLAGS=...)
endif()


set(
  CURVE
  "ALT_BN128"
  CACHE
  STRING
  "Default curve: one of ALT_BN128, BN128, EDWARDS, MNT4, MNT6"
)

set(
  DEPENDS_DIR
  "${CMAKE_CURRENT_SOURCE_DIR}/depends"
  CACHE
  STRING
  "Optionally specify the dependency installation directory relative to the source directory (default: inside dependency folder)"
)

set(
  DEPENDS_DIR_LIBSNARK
  "${CMAKE_CURRENT_SOURCE_DIR}/depends/libsnark/"
  CACHE
  STRING
  "Optionally specify the dependency installation directory relative to the source directory (default: inside dependency folder)"
)

set(
  DEPENDS_DIR_LIBFF
  "${DEPENDS_DIR_LIBSNARK}/depends/libff/"
  CACHE
  STRING
  "Optionally specify the dependency installation directory relative to the source directory (default: inside dependency folder)"
)

set(
  OPT_FLAGS
  ""
  CACHE
  STRING
  "Override C++ compiler optimization flags"
)

option(
  MULTICORE
  "Enable parallelized execution, using OpenMP"
  OFF
)

option(
  BINARY_OUTPUT
  "Use binary output for serialisation"
  ON
)

option(
  PERFORMANCE
  "Enable link-time and aggressive optimizations"
  OFF
)

option(
  WITH_PROCPS
  "Use procps for memory profiling"
  OFF
)

option(
  VERBOSE
  "Print internal messages"
  ON
)

option(
  DEBUG
  "Enable debugging mode"
  ON
)

option(
  CPPDEBUG
  "Enable debugging of C++ STL (does not imply DEBUG)"
  ON
)


add_definitions(-DCURVE_${CURVE})

if(${CURVE} STREQUAL "BN128")
  add_definitions(-DBN_SUPPORT_SNARK=1)
endif()

if("${VERBOSE}")
  add_definitions(-DVERBOSE=1)
endif()

if("${MULTICORE}")
  add_definitions(-DMULTICORE=1)
endif()

if("${DEBUG}")
  add_definitions(-DDEBUG=1)
  add_compile_options(-g)
else()
  add_compile_options(-O3)
endif()


if("${BINARY_OUTPUT}")
  add_definitions(-DBINARY_OUTPUT)
endif()

if("${MONTGOMERY_OUTPUT}")
  add_definitions(-DMONTGOMERY_OUTPUT)
endif()

if(NOT "${USE_PT_COMPRESSION}")
  add_definitions(-DNO_PT_COMPRESSION=1)
endif()


if("${USE_MIXED_ADDITION}")
  add_definitions(-DUSE_MIXED_ADDITION=1)
endif()

if("${CPPDEBUG}")
  add_definitions(-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC)
endif()

include(FindPkgConfig)
if("${WITH_PROCPS}")
  pkg_check_modules(
    PROCPS
    REQUIRED

    libprocps
  )
else()
  add_definitions(
    -DNO_PROCPS
  )
endif()


find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARY gmp)
if(GMP_LIBRARY MATCHES ${CMAKE_SHARED_LIBRARY_SUFFIX})
  set(gmp_library_type SHARED)
else()
  set(gmp_library_type STATIC)
endif()
message(STATUS "GMP: ${GMP_LIBRARY}, ${GMP_INCLUDE_DIR}")
add_library(GMP::gmp ${gmp_library_type} IMPORTED)
set_target_properties(
  GMP::gmp PROPERTIES
  IMPORTED_LOCATION ${GMP_LIBRARY}
  INTERFACE_INCLUDE_DIRECTORIES ${GMP_INCLUDE_DIR}
)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)


add_compile_options(-fPIC)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OPT_FLAGS}")

include(FindPkgConfig)
if("${WITH_PROCPS}")
  pkg_check_modules(PROCPS REQUIRED libprocps)
else()
  add_definitions(-DNO_PROCPS)
endif()

include_directories(
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft)


add_library(
  ff
  STATIC

  ${DEPENDS_DIR_LIBFF}/libff/algebra/curves/alt_bn128/alt_bn128_g1.cpp
  ${DEPENDS_DIR_LIBFF}/libff/algebra/curves/alt_bn128/alt_bn128_g2.cpp
  ${DEPENDS_DIR_LIBFF}/libff/algebra/curves/alt_bn128/alt_bn128_init.cpp
  ${DEPENDS_DIR_LIBFF}/libff/algebra/curves/alt_bn128/alt_bn128_pairing.cpp
  ${DEPENDS_DIR_LIBFF}/libff/algebra/curves/alt_bn128/alt_bn128_pp.cpp
  ${DEPENDS_DIR_LIBFF}/libff/common/double.cpp
  ${DEPENDS_DIR_LIBFF}/libff/common/profiling.cpp
  ${DEPENDS_DIR_LIBFF}/libff/common/utils.cpp
)

target_link_libraries(ff GMP::gmp gmpxx ${PROCPS_LIBRARIES})

#add_subdirectory(depends)
add_subdirectory(src)

