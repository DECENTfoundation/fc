#include <fc/rpc/cli.hpp>
#include <fc/thread/thread.hpp>
#include <fc/io/console.hpp>
#include <fc/io/iostream.hpp>

#include <iostream>
#include <fstream>

#include <boost/algorithm/string/trim.hpp>

#ifdef HAVE_READLINE
# include <readline/readline.h>
# include <readline/history.h>
// I don't know exactly what version of readline we need.  I know the 4.2 version that ships on some macs is
// missing some functions we require.  We're developing against 6.3, but probably anything in the 6.x
// series is fine
# if RL_VERSION_MAJOR < 6
#  ifdef _MSC_VER
#   pragma message("You have an old version of readline installed that might not support some of the features we need")
#   pragma message("Readline support will not be compiled in")
#  else
#   warning "You have an old version of readline installed that might not support some of the features we need"
#   warning "Readline support will not be compiled in"
#  endif
#  undef HAVE_READLINE
# endif
# ifdef WIN32
#  include <io.h>
# endif
#endif

namespace fc { namespace rpc {

static std::vector<std::string>& cli_commands()
{
   static std::vector<std::string>* cmds = new std::vector<std::string>();
   return *cmds;
}

cli::~cli()
{
   if( _run_complete.valid() )
   {
      stop();
   }
}

variant cli::send_call( api_id_type api_id, std::string method_name, variants args /* = variants() */ )
{
   FC_ASSERT(false);
}

variant cli::send_callback( uint64_t callback_id, variants args /* = variants() */ )
{
   FC_ASSERT(false);
}

void cli::send_notice( uint64_t callback_id, variants args /* = variants() */ )
{
   FC_ASSERT(false);
}

void cli::start()
{
   cli_commands() = get_method_names(0);
   _run_complete = fc::async( [&](){ run(); } );
}

void cli::stop()
{
   _run_complete.cancel();
   _run_complete.wait();
}

void cli::wait()
{
   _run_complete.wait();
}

void cli::format_result( const std::string& method, std::function<std::string(variant,const variants&)> formatter)
{
   _result_formatters[method] = formatter;
}

void cli::set_prompt( const std::string& prompt )
{
   _prompt = prompt;
}

void cli::set_command_file( const std::string& command_file )
{
    non_interactive = true;
    this->command_file = command_file;
}

void cli::run()
{
   if (non_interactive)
   {
       fc::variants args = fc::json::variants_from_string("from_command_file " + command_file + char(EOF));

       const std::string& method = args[0].get_string();

       auto result = receive_call( 0, method, variants( args.begin()+1,args.end() ) );
       auto itr = _result_formatters.find( method );
       if( itr == _result_formatters.end() )
       {
          std::cout << fc::json::to_pretty_string( result ) << "\n";
       }
       else
          std::cout << itr->second( result, args ) << "\n";

       return;
   }

   while( !_run_complete.canceled() )
   {
      try
      {
         std::string line;
         std::string trimmed_line;

         try
         {
             get_line( _prompt.c_str(), line, true );
         }
         catch ( const fc::eof_exception& )
         {
            break;
         }

         trimmed_line = boost::algorithm::trim_right_copy(line);
         if (trimmed_line == "quit" || trimmed_line == "exit")
            break;

         if (trimmed_line == "unlock" || trimmed_line == "set_password")
         {
             line = fc::get_password_hidden(trimmed_line);
         }

         fc::variants args = fc::json::variants_from_string(line + char(EOF));
         if( args.size() == 0 )
            continue;

         const std::string& method = args[0].get_string();

         auto result = receive_call( 0, method, variants( args.begin()+1,args.end() ) );
         auto itr = _result_formatters.find( method );
         if( itr == _result_formatters.end() )
         {
            std::cout << fc::json::to_pretty_string( result ) << "\n";
         }
         else
            std::cout << itr->second( result, args ) << "\n";
      }
      catch ( const fc::exception& e )
      {
         std::cout << e.to_detail_string() << "\n";
      }
   }
}


char * dupstr (const char* s) {
   char *r;

   r = (char*) malloc ((strlen (s) + 1));
   strcpy (r, s);
   return (r);
}

char* my_generator(const char* text, int state)
{
   static size_t list_index, len;
   const char *name;

   if (!state) {
      list_index = 0;
      len = strlen (text);
   }

   auto& cmd = cli_commands();

   while( list_index < cmd.size() )
   {
      name = cmd[list_index].c_str();
      list_index++;

      if (strncmp (name, text, len) == 0)
         return (dupstr(name));
   }

   /* If no names matched, then return NULL. */
   return ((char *)NULL);
}


static char** cli_completion( const char * text , int start, int end)
{
   char **matches;
   matches = (char **)NULL;

#ifdef HAVE_READLINE
   if (start == 0)
      matches = rl_completion_matches ((char*)text, &my_generator);
   else
      rl_bind_key('\t',rl_abort);
#endif

   return (matches);
}


void cli::get_line( const std::string& prompt, std::string& line, bool allow_history) const
{
   // getting file descriptor for C++ streams is near impossible
   // so we just assume it's the same as the C stream...
#ifdef HAVE_READLINE
#ifndef WIN32
   if( isatty( fileno( stdin ) ) )
#else
   // it's implied by
   // https://msdn.microsoft.com/en-us/library/f4s0ddew.aspx
   // that this is the proper way to do this on Windows, but I have
   // no access to a Windows compiler and thus,
   // no idea if this actually works
   if( _isatty( _fileno( stdin ) ) )
#endif
   {
      rl_attempted_completion_function = cli_completion;

      static fc::thread getline_thread("getline");
      getline_thread.async( [&](){
         char* line_read = nullptr;
         std::cout.flush(); //readline doesn't use cin, so we must manually flush _out
         line_read = readline(prompt.c_str());
         if( line_read == nullptr )
            FC_THROW_EXCEPTION( fc::eof_exception, "" );
         rl_bind_key( '\t', rl_complete );
         if( allow_history && *line_read )
            add_history(line_read);
         line = line_read;
         free(line_read);
      }).wait();
   }
   else
#endif
   {
      std::cout << prompt;
      // sync_call( cin_thread, [&](){ std::getline( *input_stream, line ); }, "getline");
      fc::getline(line);
   }
}

} } // namespace fc::rpc
