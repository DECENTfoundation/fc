#include <fc/io/console.hpp>
#include <fc/io/iostream.hpp>
#include <fc/thread/thread.hpp>

#ifndef _WIN32
#include <unistd.h>
#include <termios.h>
#else
#include <Windows.h>
#endif

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

namespace fc {

void get_line_password( const std::string& prompt, std::string& line, bool allow_history)
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

std::string get_password_hidden(const std::string& current_line)
{
   std::string line = current_line;
#ifndef _WIN32
   struct termios _old, _new;
   int input_file_desc = fileno(
#ifdef HAVE_READLINE
       rl_instream != NULL ? rl_instream :
#endif
       stdin);
   /* Turn echoing off and fail if we can’t. */
   if (tcgetattr(input_file_desc, &_old) != 0)
       FC_THROW("Can't get terminal attributes");
   _new = _old;
   _new.c_lflag &= ~ECHO;
   if (tcsetattr(input_file_desc, TCSAFLUSH, &_new) != 0)
       FC_THROW("Can't set terminal attributes");
#else
   DWORD mode = 0;
   GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
   mode &= ~ENABLE_ECHO_INPUT;

   DWORD bytesWritten = 0;
   INPUT_RECORD ir[4];
   memset(&ir, 0, sizeof(ir));

   ir[0].EventType = KEY_EVENT;
   ir[0].Event.KeyEvent.bKeyDown = TRUE;
   ir[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
   ir[0].Event.KeyEvent.uChar.AsciiChar = 13;
   ir[0].Event.KeyEvent.wRepeatCount = 1;

   ir[1].EventType = KEY_EVENT;
   ir[1].Event.KeyEvent.bKeyDown = FALSE;
   ir[1].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
   ir[1].Event.KeyEvent.uChar.AsciiChar = 13;
   ir[1].Event.KeyEvent.wRepeatCount = 1;

   BOOL res = SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
   res = WriteConsoleInput(GetStdHandle(STD_INPUT_HANDLE), ir, 2, &bytesWritten);
   bytesWritten = 0;

   std::string redudant_line;
   fc::getline(redudant_line);
#endif

   try
   {
       std::string passwd;
       get_line_password( "Password: ", passwd, false );
       std::cout << "\n";
       if (!passwd.empty())
           line.append(1, ' ').append(passwd);
   }
   catch ( const fc::eof_exception& )
   {
       return "";
   }

#ifndef _WIN32
   /* Restore terminal. */
   if (tcsetattr(input_file_desc, TCSAFLUSH, &_old) != 0)
       FC_THROW("Can't revert terminal attributes");
#else
   GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
   mode |= ENABLE_ECHO_INPUT;
   res = SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);

   bytesWritten = 0;
   memset(&ir, 0, sizeof(ir));

   ir[0].EventType = KEY_EVENT;
   ir[0].Event.KeyEvent.bKeyDown = TRUE;
   ir[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
   ir[0].Event.KeyEvent.uChar.AsciiChar = 13;
   ir[0].Event.KeyEvent.wRepeatCount = 1;

   ir[1].EventType = KEY_EVENT;
   ir[1].Event.KeyEvent.bKeyDown = FALSE;
   ir[1].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
   ir[1].Event.KeyEvent.uChar.AsciiChar = 13;
   ir[1].Event.KeyEvent.wRepeatCount = 1;

   res = WriteConsoleInput(GetStdHandle(STD_INPUT_HANDLE), ir, 2, &bytesWritten);
   fc::getline(redudant_line);
#endif
   return line;
}

} // namespace fc
