#pragma once
#include <fc/io/iostream.hpp>
#include <fc/fwd.hpp>

namespace fc {

  class stringstream : virtual public iostream {
    public:
      stringstream();
      stringstream( std::string& s);
      stringstream( const std::string& s);
      ~stringstream();

      std::string str();
      void str(const std::string& s);

      void clear();

      virtual bool     eof()const;
      virtual size_t   writesome( const char* buf, size_t len ) override;
      virtual size_t   readsome( char* buf, size_t len ) override;
      virtual void     close() override;
      virtual void     flush() override;
              char     peek();

    private:
      class impl;
      fwd<impl, 392> my;
  };

}
