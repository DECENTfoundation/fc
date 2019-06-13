#pragma once
#include <fc/shared_ptr.hpp>
#include <fc/filesystem.hpp>
#include <fc/io/iostream.hpp>
#include <ios>

namespace boost {
  namespace filesystem {
    class path;
  }
}

namespace fc {
  class ofstream : virtual public ostream {
    public:
      ofstream();
      ofstream(const boost::filesystem::path& file, std::ios_base::openmode mode = std::ios::binary);
      ~ofstream();

      void open(const boost::filesystem::path& file, std::ios_base::openmode mode = std::ios::binary);
      size_t writesome( const char* buf, size_t len );
      size_t writesome(const std::shared_ptr<const char>& buffer, size_t len, size_t offset);
      void   put( char c );
      void   close();
      void   flush();

    private:
      class impl;
      fc::shared_ptr<impl> my;
  };

  class ifstream : virtual public istream {
    public:
      enum seekdir { beg, cur, end };

      ifstream();
      ifstream(const boost::filesystem::path& file, std::ios_base::openmode mode = std::ios::binary);
      ~ifstream();

      void      open(const boost::filesystem::path& file, std::ios_base::openmode mode = std::ios::binary);
      size_t    readsome( char* buf, size_t len );
      size_t    readsome(const std::shared_ptr<char>& buffer, size_t max, size_t offset);
      ifstream& read( char* buf, size_t len );
      ifstream& seekg( size_t p, seekdir d = beg );
      using istream::get;
      void      get( char& c ) { read( &c, 1 ); }
      void      close();
      bool      eof()const;
    private:
      class impl;
      fc::shared_ptr<impl> my;
  };

  /**
   * Grab the full contents of a file into a string object.
   * NB reading a full file into memory is a poor choice
   * if the file may be very large.
   */
  void read_file_contents( const boost::filesystem::path& filename, std::string& result );

} // namespace fc
