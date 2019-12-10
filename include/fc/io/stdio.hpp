#pragma once
#include <fc/io/iostream.hpp>

namespace fc
{
  class cout_t : virtual public ostream {
     public:
      virtual size_t writesome( const char* buf, size_t len ) override;
      virtual void   close() override;
      virtual void   flush() override;
  };

  class cerr_t : virtual public ostream {
     public:
      virtual size_t writesome( const char* buf, size_t len ) override;
      virtual void   close() override;
      virtual void   flush() override;
  };

  class cin_t : virtual public istream {
     public:
      ~cin_t();
      virtual size_t readsome( char* buf, size_t len ) override;
      virtual istream& read( char* buf, size_t len );
      virtual bool eof()const;
  };

  extern cout_t& cout;
  extern cerr_t& cerr;
  extern cin_t&  cin;

  extern std::shared_ptr<cin_t>  cin_ptr;
  extern std::shared_ptr<cout_t> cout_ptr;
  extern std::shared_ptr<cerr_t> cerr_ptr;
}
