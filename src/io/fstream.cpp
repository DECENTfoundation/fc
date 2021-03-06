#include <fstream>
#include <sstream>

#include <fc/filesystem.hpp>
#include <fc/exception.hpp>
#include <fc/io/fstream.hpp>
#include <fc/log/logger.hpp>

#include <boost/filesystem/path.hpp>
#include <boost/filesystem/fstream.hpp>

namespace fc {
   class ofstream::impl {
      public:
         boost::filesystem::ofstream ofs;
   };
   class ifstream::impl {
      public:
         boost::filesystem::ifstream ifs;
   };

   ofstream::ofstream()
   :my( new impl() ){}

   ofstream::ofstream( const boost::filesystem::path& file, std::ios_base::openmode mode )
   :my( new impl() ) { this->open( file, mode ); }
   ofstream::~ofstream(){}

   void ofstream::open( const boost::filesystem::path& file, std::ios_base::openmode mode ) {
     const boost::filesystem::path& bfp = file;
     my->ofs.open( bfp, mode | std::ios::binary );
   }
   size_t ofstream::writesome( const char* buf, size_t len ) {
        my->ofs.write(buf,len);
        return len;
   }

   void   ofstream::put( char c ) {
        my->ofs.put(c);
   }
   void   ofstream::close() {
        my->ofs.close();
   }
   void   ofstream::flush() {
        my->ofs.flush();
   }

   ifstream::ifstream()
   :my(new impl()){}
   ifstream::ifstream( const boost::filesystem::path& file, std::ios_base::openmode mode )
   :my(new impl())
   {
      this->open( file, mode );
   }
   ifstream::~ifstream(){}

   void ifstream::open( const boost::filesystem::path& file, std::ios_base::openmode mode ) {
     const boost::filesystem::path& bfp = file;
      my->ifs.open( bfp, mode | std::ios::binary );
   }
   size_t ifstream::readsome( char* buf, size_t len ) {
      auto s = size_t(my->ifs.readsome( buf, len ));
      if( s <= 0 ) {
         read( buf, 1 );
         s = 1;
      }
      return s;
   }

   ifstream& ifstream::read( char* buf, size_t len ) {
      if (eof())
        FC_THROW_EXCEPTION( eof_exception , "");
      my->ifs.read(buf,len);
      if (my->ifs.gcount() < int64_t(len))
        FC_THROW_EXCEPTION( eof_exception , "");
      return *this;
   }
   ifstream& ifstream::seekg( size_t p, seekdir d ) {
      switch( d ) {
        case beg: my->ifs.seekg( p, std::ios_base::beg ); return *this;
        case cur: my->ifs.seekg( p, std::ios_base::cur ); return *this;
        case end: my->ifs.seekg( p, std::ios_base::end ); return *this;
      }
      return *this;
   }
   void   ifstream::close() { return my->ifs.close(); }

   bool   ifstream::eof()const { return !my->ifs.good(); }

   void read_file_contents( const boost::filesystem::path& filename, std::string& result )
   {
      const boost::filesystem::path& bfp = filename;
      boost::filesystem::ifstream f( bfp, std::ios::in | std::ios::binary );
      // don't use fc::stringstream here as we need something with override for << rdbuf()
      std::stringstream ss;
      ss << f.rdbuf();
      result = ss.str();
   }

} // namespace fc
