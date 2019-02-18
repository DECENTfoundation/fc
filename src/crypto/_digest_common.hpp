#pragma once

/* Common stuff for cryptographic hashes
 */
namespace fc { namespace detail {
    void shift_l( const char* in, char* out, std::size_t n, std::size_t i);
    void shift_r( const char* in, char* out, std::size_t n, std::size_t i);
}}
