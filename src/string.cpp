#include <fc/string.hpp>
#include <fc/exception.hpp>
#include <boost/lexical_cast.hpp>

#include <sstream>
#include <iomanip>
#include <limits>

/**
 *  Implemented with std::string for now.
 */

namespace fc  {

  int64_t    to_int64( const std::string& i )
  {
    try
    {
      return boost::lexical_cast<int64_t>(i.c_str());
    }
    catch( const boost::bad_lexical_cast& )
    {
      FC_THROW_EXCEPTION( parse_error_exception, "Couldn't parse int64_t" );
    }
    FC_RETHROW_EXCEPTIONS( warn, "${i} => int64_t", ("i",i) )
  }

  uint64_t   to_uint64( const std::string& i )
  { try {
    try
    {
      return boost::lexical_cast<uint64_t>(i.c_str());
    }
    catch( const boost::bad_lexical_cast& )
    {
      FC_THROW_EXCEPTION( parse_error_exception, "Couldn't parse uint64_t" );
    }
    FC_RETHROW_EXCEPTIONS( warn, "${i} => uint64_t", ("i",i) )
  } FC_CAPTURE_AND_RETHROW( (i) ) }

  double     to_double( const std::string& i)
  {
    try
    {
      return boost::lexical_cast<double>(i.c_str());
    }
    catch( const boost::bad_lexical_cast& )
    {
      FC_THROW_EXCEPTION( parse_error_exception, "Couldn't parse double" );
    }
    FC_RETHROW_EXCEPTIONS( warn, "${i} => double", ("i",i) )
  }

  std::string to_string(double d)
  {
    // +2 is required to ensure that the double is rounded correctly when read back in.  http://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html
    std::stringstream ss;
    ss << std::setprecision(std::numeric_limits<double>::digits10 + 2) << std::fixed << d;
    return ss.str();
  }

  std::string to_string( uint64_t d)
  {
    return boost::lexical_cast<std::string>(d);
  }

  std::string to_string( int64_t d)
  {
    return boost::lexical_cast<std::string>(d);
  }

  std::string to_string( uint16_t d)
  {
    return boost::lexical_cast<std::string>(d);
  }

} // namespace fc
