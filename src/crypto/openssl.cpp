#include <fc/crypto/openssl.hpp>

#include <fc/filesystem.hpp>

#include <cstdlib>
#include <string>
#include <stdlib.h>

namespace  fc 
{
    struct openssl_scope
    {
       static boost::filesystem::path _configurationFilePath;
       openssl_scope()
       {
          ERR_load_crypto_strings(); 
          OpenSSL_add_all_algorithms();

          const boost::filesystem::path& boostPath = _configurationFilePath;
          if(boostPath.empty() == false)
          {
            std::string varSetting("OPENSSL_CONF=");
            varSetting += to_native_ansi_path(_configurationFilePath);
#if defined(WIN32)
            _putenv((char*)varSetting.c_str());
#else
            putenv((char*)varSetting.c_str());
#endif
          }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
          if (CONF_modules_load(NULL, NULL, CONF_MFLAGS_IGNORE_ERRORS| CONF_MFLAGS_IGNORE_MISSING_FILE) < 0) {
             ERR_print_errors_fp(stderr);
             exit(1);
          }
#else
          OPENSSL_config(nullptr);
#endif
       }

       ~openssl_scope()
       {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
          CONF_modules_free();
#endif

          EVP_cleanup();
          ERR_free_strings();
       }
    };

    boost::filesystem::path openssl_scope::_configurationFilePath;

    void store_configuration_path(const boost::filesystem::path& filePath)
    {
      openssl_scope::_configurationFilePath = filePath;
    }
   
    int init_openssl()
    {
      static openssl_scope ossl;
      return 0;
    }
}
