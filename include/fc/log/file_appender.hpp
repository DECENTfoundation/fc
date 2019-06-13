#pragma once

#include <boost/filesystem/path.hpp>
#include <fc/log/appender.hpp>
#include <fc/log/logger.hpp>
#include <fc/time.hpp>

namespace fc {

class file_appender : public appender {
    public:
         struct config {
            config( const boost::filesystem::path& p = "log.txt" );

            std::string                        format;
            boost::filesystem::path            filename;
            bool                               flush = true;
            bool                               rotate = false;
            microseconds                       rotation_interval;
            microseconds                       rotation_limit;
         };
         file_appender( const variant& args );
         ~file_appender();
         virtual void log( const log_message& m )override;

      private:
         class impl;
         fc::shared_ptr<impl> my;
   };
} // namespace fc

#include <fc/reflect/reflect.hpp>
FC_REFLECT( fc::file_appender::config,
            (format)(filename)(flush)(rotate)(rotation_interval)(rotation_limit) )
