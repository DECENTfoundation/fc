#include <fc/interprocess/mmap_struct.hpp>
#include <boost/filesystem.hpp>
#include <fc/io/fstream.hpp>
#include <fc/filesystem.hpp>

namespace fc
{
   size_t mmap_struct_base::size()const
   {
      return _mapped_region->get_size();
   }

   void mmap_struct_base::flush()
   {
      _mapped_region->flush();
   }

   void mmap_struct_base::open( const boost::filesystem::path& file, size_t s, bool create )
   {
      if( !exists( file ) || file_size(file) != s )
      {
         fc::ofstream out( file );
         char buffer[1024];
         memset( buffer, 0, sizeof(buffer) );

         size_t bytes_left = s;
         while( bytes_left > 0 )
         {
            size_t to_write = std::min<size_t>(bytes_left, sizeof(buffer) );
            out.write( buffer, to_write );
            bytes_left -= to_write;
         }
      }

      std::string filePath = to_native_ansi_path(file); 

      _file_mapping.reset( new boost::interprocess::file_mapping( filePath.c_str(), boost::interprocess::read_write ) );
      _mapped_region.reset( new boost::interprocess::mapped_region( *_file_mapping, boost::interprocess::read_write, 0, s ) );
   }

} // namespace fc
