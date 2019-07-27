//#define BOOST_NO_SCOPED_ENUMS
#include <fc/filesystem.hpp>
#include <fc/exception/exception.hpp>
#include <fc/fwd_impl.hpp>
#include <fc/io/fstream.hpp>

#include <fc/utf8.hpp>
#include <fc/variant.hpp>

#include <boost/config.hpp>
#include <boost/filesystem.hpp>

#ifdef WIN32
# include <Windows.h>
# include <UserEnv.h>
# include <ShlObj.h>
#else
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <pwd.h>
  #include <sys/file.h>
  #include <fcntl.h>
#endif

namespace fc {
  std::string path_to_utf8(const boost::filesystem::path& p)
  {
    std::wstring wide_string = p.generic_wstring();
    std::string utf8_string;
    fc::encodeUtf8(wide_string, &utf8_string);
    return utf8_string;
  }

  boost::filesystem::path path_from_utf8(const std::string& p)
  {
    std::wstring wide_string;
    fc::decodeUtf8(p, &wide_string);
    return boost::filesystem::path(wide_string);
  }

  // when converting to and from a variant, store utf-8 in the variant
  void to_variant( const boost::filesystem::path& p, variant& v ) 
  {
    v = path_to_utf8(p);
  }

  void from_variant( const fc::variant& v, boost::filesystem::path& p ) 
  {
    p = path_from_utf8(v.as_string());
  }

  std::string to_native_ansi_path( const boost::filesystem::path &p )
    {
    std::wstring path = p.generic_wstring();

#ifdef WIN32
    const size_t maxPath = 32*1024;
    std::vector<wchar_t> short_path;
    short_path.resize(maxPath + 1);
          
    wchar_t* buffer = short_path.data();
    DWORD res = GetShortPathNameW(path.c_str(), buffer, maxPath);
    if(res != 0)
      path = buffer;
#endif
    std::string filePath;
    fc::encodeUtf8(path, &filePath);
    return filePath;
    }

   temp_file::temp_file(const boost::filesystem::path& p, bool create)
   : temp_file_base(p / boost::filesystem::unique_path())
   {
      if (exists(*_path))
      {
         FC_THROW( "Name collision: ${path}", ("path", _path->string()) );
      }
      if (create)
      {
         fc::ofstream ofs(*_path);
         ofs.close();
      }
   }

   temp_file::temp_file(temp_file&& other)
      : temp_file_base(std::move(other._path))
   {
   }

   temp_file& temp_file::operator=(temp_file&& other)
   {
      if (this != &other)
      {
         remove();
         _path = std::move(other._path);
      }
      return *this;
   }

   temp_directory::temp_directory(const boost::filesystem::path& p)
   : temp_file_base(p / boost::filesystem::unique_path())
   {
      if (exists(*_path))
      {
         FC_THROW( "Name collision: ${path}", ("path", _path->string()) );
      }
      create_directories(*_path);
   }

   temp_directory::temp_directory(temp_directory&& other)
      : temp_file_base(std::move(other._path))
   {
   }

   temp_directory& temp_directory::operator=(temp_directory&& other)
   {
      if (this != &other)
      {
         remove();
         _path = std::move(other._path);
      }
      return *this;
   }

   const boost::filesystem::path& temp_file_base::path() const
   {
      if (!_path)
      {
         FC_THROW( "Temporary directory has been released." );
      }
      return *_path;
   }

   void temp_file_base::remove()
   {
      if (_path.valid())
      {
         try
         {
            remove_all(*_path);
         }
         catch (...)
         {
            // eat errors on cleanup
         }
         release();
      }
   }

   void temp_file_base::release()
   {
      _path = fc::optional<boost::filesystem::path>();
   }

   const boost::filesystem::path& home_path()
   {
      static boost::filesystem::path p = []()
      {
#ifdef WIN32
          HANDLE access_token;
          if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &access_token))
            FC_ASSERT(false, "Unable to open an access token for the current process");
          wchar_t user_profile_dir[MAX_PATH];
          DWORD user_profile_dir_len = sizeof(user_profile_dir);
          BOOL success = GetUserProfileDirectoryW(access_token, user_profile_dir, &user_profile_dir_len);
          CloseHandle(access_token);
          if (!success)
            FC_ASSERT(false, "Unable to get the user profile directory");
          return boost::filesystem::path(std::wstring(user_profile_dir));
#else
          char* home = getenv( "HOME" );
          if( nullptr == home )
          {
             struct passwd* pwd = getpwuid(getuid());
             if( pwd )
             {
                 return boost::filesystem::path( std::string( pwd->pw_dir ) );
             }
             FC_ASSERT( home != nullptr, "The HOME environment variable is not set" );
          }
          return boost::filesystem::path( std::string(home) );
#endif
      }();
      return p;
   }

   const boost::filesystem::path& app_path()
   {
#ifdef __APPLE__
         static boost::filesystem::path appdir = [](){  return home_path() / "Library" / "Application Support"; }();  
#elif defined( WIN32 )
         static boost::filesystem::path appdir = [](){
           wchar_t app_data_dir[MAX_PATH];

           if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, app_data_dir)))
             FC_ASSERT(false, "Unable to get the current AppData directory");
           return boost::filesystem::path(std::wstring(app_data_dir));
         }();
#else
        static boost::filesystem::path appdir = home_path();
#endif
      return appdir;
   }

  class simple_lock_file::impl
  {
  public:
#ifdef _WIN32
    HANDLE file_handle;
#else
    int file_handle;
#endif
    bool is_locked;
    boost::filesystem::path lock_file_path;

    impl(const boost::filesystem::path& lock_file_path);
    ~impl();

    bool try_lock();
    void unlock();
  };
  
  simple_lock_file::impl::impl(const boost::filesystem::path& lock_file_path) :
#ifdef _WIN32
    file_handle(INVALID_HANDLE_VALUE),
#else
    file_handle(-1),
#endif
    is_locked(false),
    lock_file_path(lock_file_path)
  {}
   
  simple_lock_file::impl::~impl()
  {
    unlock();
  }

  bool simple_lock_file::impl::try_lock()
  {
#ifdef _WIN32
    HANDLE fh = CreateFileW(lock_file_path.wstring().c_str(),
                            GENERIC_READ | GENERIC_WRITE,
                            0, 0,
                            OPEN_ALWAYS, 0, NULL);
    if (fh == INVALID_HANDLE_VALUE)
      return false;
    is_locked = true;
    file_handle = fh;
    return true;
#else
    int fd = open(lock_file_path.string().c_str(), O_RDWR|O_CREAT, 0644);
    if (fd < 0)
      return false;
    if (flock(fd, LOCK_EX|LOCK_NB) == -1)
    {
      close(fd);
      return false;
    }
    is_locked = true;
    file_handle = fd;
    return true;
#endif
  }

  void simple_lock_file::impl::unlock()
  {
#ifdef WIN32
    CloseHandle(file_handle);
    file_handle = INVALID_HANDLE_VALUE;
    is_locked = false;
#else
    flock(file_handle, LOCK_UN);
    close(file_handle);
    file_handle = -1;
    is_locked = false;
#endif
  }


  simple_lock_file::simple_lock_file(const boost::filesystem::path& lock_file_path) :
    my(new impl(lock_file_path))
  {
  }

  simple_lock_file::~simple_lock_file()
  {
  }

  bool simple_lock_file::try_lock()
  {
    return my->try_lock();
  }

  void simple_lock_file::unlock()
  {
    my->unlock();
  }
}
