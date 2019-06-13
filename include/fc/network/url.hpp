#pragma once
#include <fc/string.hpp>
#include <fc/optional.hpp>
#include <stdint.h>
#include <boost/filesystem/path.hpp>
#include <fc/variant_object.hpp>
#include <memory>

namespace fc {

  typedef fc::optional<std::string>          ostring;
  typedef fc::optional<boost::filesystem::path> opath;
  typedef fc::optional<fc::variant_object>   ovariant_object;

  namespace detail { class url_impl; }

  /**
   *  Used to pass an immutable URL and
   *  query its parts.
   */
  class url 
  {
    public:
      url();
      explicit url( const std::string& u );
      url( const url& c );
      url( url&& c );
      ~url();
      
      url& operator=( const url& c );
      url& operator=( url&& c );

      bool operator==( const url& cmp )const;
      
      operator std::string()const;
      
      //// file, ssh, tcp, http, ssl, etc...
      std::string               proto()const; 
      ostring                   host()const;
      ostring                   user()const;
      ostring                   pass()const;
      opath                     path()const;
      ovariant_object           args()const;
      fc::optional<uint16_t>    port()const;

    private:
      std::shared_ptr<detail::url_impl> my;
  };

  void to_variant( const url& u, fc::variant& v );
  void from_variant( const fc::variant& v, url& u );

} // namespace fc
