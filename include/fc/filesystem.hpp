#pragma once
#include <memory>
#include <boost/filesystem/path.hpp>
#include <fc/reflect/typename.hpp>
#include <fc/optional.hpp>

namespace fc {

  /** Retrieves native string path representation and next converts it into
      ANSI UTF-8 representation.
  */
  std::string  to_native_ansi_path( const boost::filesystem::path& p );

  /** @return the home directory on Linux and OS X and the Profile directory on Windows */
  const boost::filesystem::path& home_path();

  /** @return the home_path() on Linux, home_path()/Library/Application Support/ on OS X, 
   *  and APPDATA on windows
   */
  const boost::filesystem::path& app_path();

  std::string path_to_utf8(const boost::filesystem::path& p);
  boost::filesystem::path path_from_utf8(const std::string& p);

  class variant;
  void to_variant( const boost::filesystem::path& p, variant& v );
  void from_variant( const variant& v, boost::filesystem::path& p );

  template<> struct get_typename<boost::filesystem::path> { static const char* name()   { return "path";   } };

  /**
   * Class which creates a temporary directory inside an existing temporary directory.
   */
  class temp_file_base
  {
  public:
     inline ~temp_file_base() { remove(); }
     inline operator bool() const { return _path.valid(); }
     inline bool operator!() const { return !_path; }
     const boost::filesystem::path& path() const;
     void remove();
     void release();
  protected:
     typedef fc::optional<boost::filesystem::path> path_t;
     inline temp_file_base(const path_t& path) : _path(path) {}
     inline temp_file_base(path_t&& path) : _path(std::move(path)) {}
     path_t _path;
  };

  /**
   * Class which creates a temporary directory inside an existing temporary directory.
   */
  class temp_file : public temp_file_base
  {
  public:
     temp_file(temp_file&& other);
     temp_file& operator=(temp_file&& other);
     temp_file(const boost::filesystem::path& tempFolder, bool create = false);
  };

  /**
   * Class which creates a temporary directory inside an existing temporary directory.
   */
  class temp_directory : public temp_file_base
  {
  public:
     temp_directory(temp_directory&& other);
     temp_directory& operator=(temp_directory&& other);
     temp_directory(const boost::filesystem::path& tempFolder);
  };

  /** simple class which only allows one process to open any given file. 
   * approximate usage:
   * int main() {
   *   fc::simple_file_lock instance_lock("~/.my_app/.lock");
   *   if (!instance_lock.try_lock()) {
   *     elog("my_app is already running");
   *     return 1;
   *   }
   *   // do stuff here, file will be unlocked when instance_lock goes out of scope
   * }
  */
  class simple_lock_file
  {
  public:
    simple_lock_file(const boost::filesystem::path& lock_file_path);
    ~simple_lock_file();
    bool try_lock();
    void unlock();
  private:
    class impl;
    std::unique_ptr<impl> my;
  };
}
