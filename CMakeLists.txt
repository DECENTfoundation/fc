#
# Defines fc library target.

if (POLICY CMP0025)
    # Compiler id for Apple Clang is now AppleClang
    cmake_policy(SET CMP0025 NEW)
endif()

if (POLICY CMP0048)
    # The ``project()`` command manages VERSION variables.
    cmake_policy(SET CMP0048 NEW)
endif()

CMAKE_MINIMUM_REQUIRED( VERSION 3.10.2 )
PROJECT( fc LANGUAGES CXX C )

# Compile in C++14 mode
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compile in C99 mode
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Setup module path to make visible used CMake extensions
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules")

SET( CMAKE_DEBUG_POSTFIX _debug )
SET( BUILD_SHARED_LIBS NO )

# Configure secp256k1-zkp
set( SECP256K1_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/secp256k1-zkp" )
file( GLOB SECP256K1_HEADERS "${SECP256K1_DIR}/*.h" "${SECP256K1_DIR}/include/*.h" )
add_library( secp256k1 "${SECP256K1_DIR}/src/secp256k1.c" ${SECP256K1_HEADERS} )

target_include_directories( secp256k1 PRIVATE "${SECP256K1_DIR}" PUBLIC "${SECP256K1_DIR}/include" )

IF(WIN32)
  MESSAGE(STATUS "Configuring fc to build on Win32")

  target_compile_definitions( secp256k1 PRIVATE USE_FIELD_10X26 USE_FIELD_INV_BUILTIN USE_NUM_NONE USE_SCALAR_8X32 USE_SCALAR_INV_BUILTIN )
  set( PLATFORM_SPECIFIC_LIBS WS2_32.lib Userenv.lib crypt32.lib )
ELSE(WIN32)
  MESSAGE(STATUS "Configuring fc to build on Unix/Apple")

  target_compile_definitions( secp256k1 PRIVATE HAVE___INT128 USE_FIELD_5X52 USE_FIELD_INV_BUILTIN USE_NUM_NONE USE_SCALAR_4X64 USE_SCALAR_INV_BUILTIN )
ENDIF(WIN32)

IF(NOT "$ENV{OPENSSL_ROOT_DIR}" STREQUAL "")
  set(OPENSSL_ROOT_DIR $ENV{OPENSSL_ROOT_DIR} )
  set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
  message(STATUS "Setting up OpenSSL root and include vars to ${OPENSSL_ROOT_DIR}, ${OPENSSL_INCLUDE_DIR}")
ENDIF()

find_package(OpenSSL 1.0 REQUIRED)

SET(BOOST_COMPONENTS thread filesystem program_options serialization unit_test_framework coroutine iostreams)
SET(Boost_USE_STATIC_LIBS ON CACHE BOOL "Use static Boost libraries")
IF( WIN32 )
  SET(Boost_USE_STATIC_RUNTIME ${Boost_USE_STATIC_LIBS} CACHE BOOL "Use static runtime")
ENDIF()

SET(Boost_NO_BOOST_CMAKE ON)
find_package(Boost 1.65.1 REQUIRED COMPONENTS ${BOOST_COMPONENTS})

# We are now building in support for deflate compression into our websockets layer by default,
# which requires zlib.  Aside from that, all of fc compiles without zlib, so this could be
# made optional without much effort
# (important exception, apple: as of 10.10 yosemite, the OpenSSL static libraries shipped with
# os x have a dependency on zlib)
# On a side note, fc's fc::zlib_compress() function uses a separate implementation of zlib
# from the miniz library.  If we're comfortable requiring an external zlib, we can
# reimplement fc::zlib_compress() to call the real zlib, and remove miniz.c from our
# repository.
find_package( ZLIB REQUIRED )

add_subdirectory( vendor/websocketpp EXCLUDE_FROM_ALL )
add_subdirectory( vendor/udt4 )

set( fc_sources
     src/uint128.cpp
     src/variant.cpp
     src/exception.cpp
     src/monitoring.cpp
     src/variant_object.cpp
     src/thread/thread.cpp
     src/thread/thread_specific.cpp
     src/thread/future.cpp
     src/thread/task.cpp
     src/thread/spin_lock.cpp
     src/thread/spin_yield_lock.cpp
     src/thread/mutex.cpp
     src/thread/non_preemptable_scope_check.cpp
     src/thread/shared_ptr.cpp
     src/asio.cpp
     src/string.cpp
     src/time.cpp
     src/utf8.cpp
     src/io/iostream.cpp
     src/io/datastream.cpp
     src/io/fstream.cpp
     src/io/sstream.cpp
     src/io/json.cpp
     src/io/varint.cpp
     src/io/console.cpp
     src/filesystem.cpp
     src/interprocess/signals.cpp
     src/interprocess/mmap_struct.cpp
     src/rpc/cli.cpp
     src/rpc/http_api.cpp
     src/rpc/state.cpp
     src/rpc/websocket_api.cpp
     src/log/log_message.cpp
     src/log/logger.cpp
     src/log/appender.cpp
     src/log/console_appender.cpp
     src/log/file_appender.cpp
     src/log/gelf_appender.cpp
     src/log/logger_config.cpp
     src/crypto/_digest_common.cpp
     src/crypto/openssl.cpp
     src/crypto/aes.cpp
     src/crypto/crc.cpp
     src/crypto/city.cpp
     src/crypto/base58.cpp
     src/crypto/base64.cpp
     src/crypto/bigint.cpp
     src/crypto/hex.cpp
     src/crypto/sha1.cpp
     src/crypto/ripemd160.cpp
     src/crypto/sha256.cpp
     src/crypto/sha224.cpp
     src/crypto/sha512.cpp
     src/crypto/blowfish.cpp
     src/crypto/elliptic_common.cpp
     src/crypto/elliptic_secp256k1.cpp
     src/crypto/rand.cpp
     src/network/tcp_socket.cpp
     src/network/udp_socket.cpp
     src/network/udt_socket.cpp
     src/network/http/http_connection.cpp
     src/network/http/http_server.cpp
     src/network/http/websocket.cpp
     src/network/ntp.cpp
     src/network/ip.cpp
     src/network/rate_limiting.cpp
     src/network/resolve.cpp
     src/network/url.cpp
     src/compress/smaz.cpp
     src/compress/zlib.cpp
     )

file( GLOB_RECURSE fc_headers ${CMAKE_CURRENT_SOURCE_DIR} *.hpp *.h )
add_library( fc STATIC ${fc_sources} ${fc_headers} )

# begin readline stuff
find_package(Curses)
find_package(Readline)

if (READLINE_FOUND)
  target_compile_definitions (fc PRIVATE HAVE_READLINE)
  set(readline_libraries ${Readline_LIBRARY})
  if (CURSES_FOUND)
    list(APPEND readline_libraries ${CURSES_LIBRARY})
  endif()
  set(readline_includes ${Readline_INCLUDE_DIR})
elseif (NOT WIN32)
  message(FATAL_ERROR "Readline not found")
endif()
# end readline stuff

IF(WIN32)
  target_compile_options(fc PRIVATE /WX)
  target_compile_definitions(fc PRIVATE _CRT_NONSTDC_NO_DEPRECATE _CRT_SECURE_NO_WARNINGS _SCL_SECURE_NO_WARNINGS PUBLIC NOMINMAX _WIN32_WINNT=0x0A00
    # The current version of websockets doesn't correctly guess what 'chrono' implementation boost::asio uses
    # on the recommended build platform of VC++12/boost_1.58.  Force it here until websocket gets their
    # autodetecting code to do the right thing.
    _WEBSOCKETPP_CPP11_CHRONO_
  )
ELSE()
  target_compile_options(fc PUBLIC -fvisibility=hidden $<$<COMPILE_LANGUAGE:CXX>:-fvisibility-inlines-hidden> -Wall PRIVATE -Werror)

  IF(APPLE)
    target_compile_options(fc PUBLIC -stdlib=libc++)
  ELSE()
    target_compile_options(fc PUBLIC -fnon-call-exceptions)
  ENDIF()
ENDIF()

# This will become unnecessary once we update to websocketpp which fixes upstream issue #395
target_compile_definitions(fc PRIVATE WEBSOCKETPP_STRICT_MASKING BOOST_ASIO_HAS_STD_CHRONO BOOST_COROUTINES_NO_DEPRECATION_WARNING)

target_include_directories(fc
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    "${readline_includes}"

  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/cyoencode-1.0.2/src
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/udt4/src
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/websocketpp
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/secp256k1-zkp
    ${ZLIB_INCLUDE_DIR}
  )

target_link_libraries( fc PUBLIC udt Boost::thread Boost::filesystem Boost::program_options Boost::serialization Boost::coroutine Boost::iostreams Boost::disable_autolinking ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} ${PLATFORM_SPECIFIC_LIBS} ${readline_libraries} secp256k1 )

if(MSVC)
  set_source_files_properties( src/network/http/websocket.cpp PROPERTIES COMPILE_FLAGS "/bigobj" )
endif(MSVC)

add_executable( api tests/api.cpp )
target_link_libraries( api fc )

add_executable( blind tests/all_tests.cpp tests/crypto/blind.cpp )
target_link_libraries( blind fc )

add_executable( ntp_test tests/all_tests.cpp tests/network/ntp_test.cpp )
target_link_libraries( ntp_test fc )

add_executable( task_cancel_test tests/all_tests.cpp tests/thread/task_cancel.cpp )
target_link_libraries( task_cancel_test fc )

add_executable( bloom_test tests/all_tests.cpp tests/bloom_test.cpp )
target_link_libraries( bloom_test fc )

add_executable( hmac_test tests/hmac_test.cpp )
target_link_libraries( hmac_test fc )

add_executable( blinding_test tests/blinding_test.cpp )
target_link_libraries( blinding_test fc )

add_executable( udt_server tests/udts.cpp )
target_link_libraries( udt_server fc udt )

add_executable( udt_client tests/udtc.cpp )
target_link_libraries( udt_client fc udt )

add_executable( ecc_test tests/crypto/ecc_test.cpp )
target_link_libraries( ecc_test fc )

#add_executable( test_aes tests/aes_test.cpp )
#target_link_libraries( test_aes fc )
#add_executable( test_sleep tests/sleep.cpp )
#target_link_libraries( test_sleep fc )
#add_executable( test_rate_limiting tests/rate_limiting.cpp )
#target_link_libraries( test_rate_limiting fc )

add_executable( all_tests tests/all_tests.cpp
                          tests/compress/compress.cpp
                          tests/crypto/aes_test.cpp
                          tests/crypto/base_n_tests.cpp
                          tests/crypto/bigint_test.cpp
                          tests/crypto/blind.cpp
                          tests/crypto/blowfish_test.cpp
                          tests/crypto/dh_test.cpp
                          tests/crypto/rand_test.cpp
                          tests/crypto/sha_tests.cpp
                          tests/network/ntp_test.cpp
                          tests/network/http/websocket_test.cpp
                          tests/thread/task_cancel.cpp
                          tests/bloom_test.cpp
                          tests/utf8_test.cpp
                          )
target_link_libraries( all_tests fc )
