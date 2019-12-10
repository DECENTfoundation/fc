#pragma once
#include <fc/io/stdio.hpp>
#include <fc/io/json.hpp>
#include <fc/io/sstream.hpp>
#include <fc/rpc/api_connection.hpp>
#include <fc/thread/thread.hpp>

#include <iostream>

namespace fc { namespace rpc {

   /**
    *  Provides a simple wrapper for RPC calls to a given interface.
    */
   class cli : public api_connection
   {
      public:
         ~cli();

         virtual variant send_call( api_id_type api_id, std::string method_name, variants args = variants() );
         virtual variant send_callback( uint64_t callback_id, variants args = variants() );
         virtual void    send_notice( uint64_t callback_id, variants args = variants() );

         // sets the CLI to non-interactive mode: commands will be loaded from command_file
         void set_command_file( const std::string& command_file );

         void start();
         void stop();
         void wait();
         void format_result( const std::string& method, std::function<std::string(variant,const variants&)> formatter);

         void get_line( const std::string& prompt, std::string& line, bool allow_history ) const;

         void set_prompt( const std::string& prompt );

      private:
         void run();

         std::string _prompt = ">>>";
         std::map<std::string,std::function<std::string(variant,const variants&)> > _result_formatters;
         fc::future<void> _run_complete;

         std::string command_file;
         bool non_interactive = false;
   };
} }
