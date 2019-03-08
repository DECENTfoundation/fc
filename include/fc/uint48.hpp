#pragma once
#include <cstdint>
#include <fc/exception/exception.hpp>
#include <fc/reflect/reflect.hpp>

struct uint48_t
{
   uint48_t(uint64_t v = 0) : value(v)
   {
      FC_ASSERT( (value >> 48) == 0 );
   }

   bool operator ==(const uint48_t& v) const { return value == v.value; }
   bool operator !=(const uint48_t& v) const { return value != v.value; }

   bool operator <(const uint48_t& v) const { return value < v.value; }
   bool operator <=(const uint48_t& v) const { return value <= v.value; }
   bool operator >(const uint48_t& v) const { return value > v.value; }
   bool operator >=(const uint48_t& v) const { return value >= v.value; }

   uint64_t value;
};

FC_REFLECT( uint48_t, (value) )
