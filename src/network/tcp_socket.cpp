#include <fc/network/tcp_socket.hpp>
#include <fc/network/ip.hpp>
#include <fc/network/tcp_socket_io_hooks.hpp>
#include <fc/asio.hpp>
#include <fc/log/logger.hpp>
#include <fc/io/stdio.hpp>

#if defined _WIN32 || defined WIN32 || defined OS_WIN64 || defined _WIN64 || defined WIN64 || defined WINNT
# include <MSTcpIP.h>
#endif

namespace fc {

  namespace detail
  {
    bool have_so_reuseport = true;

    boost::asio::ssl::context get_client_context(const std::string& cert_file)
    {
        boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_client);
        if (!cert_file.empty())
        {
          ctx.set_options(boost::asio::ssl::context::default_workarounds |
                          boost::asio::ssl::context::no_sslv2 |
                          boost::asio::ssl::context::no_sslv3 |
                          boost::asio::ssl::context::no_tlsv1 |
                          boost::asio::ssl::context::no_tlsv1_1 |
                          boost::asio::ssl::context::single_dh_use);
          ctx.load_verify_file(cert_file);
        }

        return ctx;
    }

    boost::asio::ssl::context get_server_context(const std::string& cert_file, const std::string& key_file, const std::string& key_password)
    {
        boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_server);
        FC_ASSERT(cert_file.empty() == key_file.empty());

        if (!cert_file.empty())
        {
          ctx.set_options(boost::asio::ssl::context::default_workarounds |
                          boost::asio::ssl::context::no_sslv2 |
                          boost::asio::ssl::context::no_sslv3 |
                          boost::asio::ssl::context::no_tlsv1 |
                          boost::asio::ssl::context::no_tlsv1_1 |
                          boost::asio::ssl::context::single_dh_use);
          ctx.set_password_callback([=](std::size_t, boost::asio::ssl::context::password_purpose) { return key_password; });
          ctx.use_certificate_file(cert_file, boost::asio::ssl::context::pem);
          ctx.use_private_key_file(key_file, boost::asio::ssl::context::pem);
        }

        return ctx;
    }
  }

  class tcp_socket::impl : public tcp_socket_io_hooks {
    public:
      impl(const std::string& cert_file)
        : _ctx(detail::get_client_context(cert_file)),
          _sock(fc::asio::default_io_service(), _ctx),
          _uses_ssl(!cert_file.empty()),
          _io_hooks(this)
      {
        if (_uses_ssl)
          _sock.set_verify_mode(boost::asio::ssl::verify_peer);
      }

      impl(const std::string& cert_file, const std::string& key_file, const std::string& key_password)
        : _ctx(detail::get_server_context(cert_file, key_file, key_password)),
          _sock(fc::asio::default_io_service(), _ctx),
          _uses_ssl(!cert_file.empty()),
          _io_hooks(this)
      {
      }

      ~impl()
      {
        if( _sock.next_layer().is_open() )
          try
          {
            _sock.next_layer().close();
          }
          catch( ... )
          {}
        if( _read_in_progress.valid() )
          try
          {
            _read_in_progress.wait();
          }
          catch ( ... )
          {
          }
        if( _write_in_progress.valid() )
          try
          {
            _write_in_progress.wait();
          }
          catch ( ... )
          {
          }
      }

      virtual size_t readsome(boost::asio::ip::tcp::socket& socket, char* buffer, size_t length) override
      {
        return (_read_in_progress = fc::asio::read_some(socket, buffer, length)).wait();
      }

      virtual size_t writesome(boost::asio::ip::tcp::socket& socket, const char* buffer, size_t length) override
      {
        return (_write_in_progress = fc::asio::write_some(socket, buffer, length)).wait();
      }

      virtual size_t readsome(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket, char* buffer, size_t length) override
      {
        return (_read_in_progress = fc::asio::read_some(socket, buffer, length)).wait();
      }

      virtual size_t writesome(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket, const char* buffer, size_t length) override
      {
        return (_write_in_progress = fc::asio::write_some(socket, buffer, length)).wait();
      }

      fc::future<size_t> _write_in_progress;
      fc::future<size_t> _read_in_progress;
      boost::asio::ssl::context _ctx;
      boost::asio::ssl::stream<boost::asio::ip::tcp::socket> _sock;
      bool _uses_ssl;
      tcp_socket_io_hooks* _io_hooks;
  };

  tcp_socket::tcp_socket(const std::string& cert_file)
    : my(new impl(cert_file))
  {
  }

  tcp_socket::tcp_socket(const std::string& cert_file, const std::string& key_file, const std::string& key_password)
    : my(new impl(cert_file, key_file, key_password))
  {
  }

  tcp_socket::~tcp_socket()
  {
  }

  void tcp_socket::open()
  {
    my->_sock.next_layer().open(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0).protocol());
  }

  bool tcp_socket::is_open() const
  {
    return my->_sock.next_layer().is_open();
  }

  bool tcp_socket::uses_ssl() const
  {
    return my->_uses_ssl;
  }

  void tcp_socket::flush()
  {
  }

  void tcp_socket::close()
  {
    try {
      if( is_open() )
        my->_sock.next_layer().close();
    } FC_RETHROW_EXCEPTIONS( warn, "error closing tcp socket" );
  }

  bool tcp_socket::eof()const
  {
    return !my->_sock.next_layer().is_open();
  }

  size_t tcp_socket::readsome( char* buf, size_t len )
  {
    return my->_uses_ssl ? my->_io_hooks->readsome(my->_sock, buf, len) : my->_io_hooks->readsome(my->_sock.next_layer(), buf, len);
  }

  size_t tcp_socket::writesome(const char* buf, size_t len)
  {
    return my->_uses_ssl ? my->_io_hooks->writesome(my->_sock, buf, len) : my->_io_hooks->writesome(my->_sock.next_layer(), buf, len);
  }

  fc::ip::endpoint tcp_socket::remote_endpoint()const
  {
    try
    {
      auto rep = my->_sock.next_layer().remote_endpoint();
      return  fc::ip::endpoint(rep.address().to_v4().to_ulong(), rep.port() );
    }
    FC_RETHROW_EXCEPTIONS( warn, "error getting socket's remote endpoint" );
  }

  fc::ip::endpoint tcp_socket::local_endpoint() const
  {
    try
    {
      auto boost_local_endpoint = my->_sock.next_layer().local_endpoint();
      return fc::ip::endpoint(boost_local_endpoint.address().to_v4().to_ulong(), boost_local_endpoint.port() );
    }
    FC_RETHROW_EXCEPTIONS( warn, "error getting socket's local endpoint" );
  }

  void tcp_socket::connect_to( const fc::ip::endpoint& remote_endpoint )
  {
    fc::asio::tcp::connect(my->_sock.next_layer(), boost::asio::ip::tcp::endpoint( boost::asio::ip::address_v4(remote_endpoint.get_address()), remote_endpoint.port() ) );
    if (my->_uses_ssl)
    {
      //my->_sock.set_verify_callback(boost::asio::ssl::rfc2818_verification(remote_endpoint.get_address()));
      fc::asio::ssl::handshake(my->_sock, boost::asio::ssl::stream_base::client);
    }
  }

  void tcp_socket::bind(const fc::ip::endpoint& local_endpoint)
  {
    try
    {
      my->_sock.next_layer().bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4(local_endpoint.get_address()), local_endpoint.port()));
    }
    catch (const std::exception& except)
    {
      elog("Exception binding outgoing connection to desired local endpoint: ${what}", ("what", except.what()));
      FC_THROW("error binding to ${endpoint}: ${what}", ("endpoint", local_endpoint)("what", except.what()));
    }
  }

  void tcp_socket::enable_keep_alives(const fc::microseconds& interval)
  {
    if (interval.count())
    {
      boost::asio::socket_base::keep_alive option(true);
      my->_sock.next_layer().set_option(option);
#if defined _WIN32 || defined WIN32 || defined OS_WIN64 || defined _WIN64 || defined WIN64 || defined WINNT
      struct tcp_keepalive keepalive_settings;
      keepalive_settings.onoff = 1;
      keepalive_settings.keepalivetime = (ULONG)(interval.count() / fc::milliseconds(1).count());
      keepalive_settings.keepaliveinterval = (ULONG)(interval.count() / fc::milliseconds(1).count());

      DWORD dwBytesRet = 0;
      if (WSAIoctl(my->_sock.next_layer().native_handle(), SIO_KEEPALIVE_VALS, &keepalive_settings, sizeof(keepalive_settings),
                   NULL, 0, &dwBytesRet, NULL, NULL) == SOCKET_ERROR)
        wlog("Error setting TCP keepalive values");
#elif !defined(__clang__) || (__clang_major__ >= 6)
      // This should work for modern Linuxes and for OSX >= Mountain Lion
      int timeout_sec = interval.count() / fc::seconds(1).count();
      if (setsockopt(my->_sock.next_layer().native_handle(), IPPROTO_TCP,
      #if defined( __APPLE__ )
                     TCP_KEEPALIVE,
       #else
                     TCP_KEEPIDLE,
       #endif
                     (char*)&timeout_sec, sizeof(timeout_sec)) < 0)
        wlog("Error setting TCP keepalive idle time");
# if !defined(__APPLE__) || defined(TCP_KEEPINTVL) // TCP_KEEPINTVL not defined before 10.9
      if (setsockopt(my->_sock.next_layer().native_handle(), IPPROTO_TCP, TCP_KEEPINTVL,
                     (char*)&timeout_sec, sizeof(timeout_sec)) < 0)
        wlog("Error setting TCP keepalive interval");
# endif // !__APPLE__ || TCP_KEEPINTVL
#endif // !WIN32
    }
    else
    {
      boost::asio::socket_base::keep_alive option(false);
      my->_sock.next_layer().set_option(option);
    }
  }

  void tcp_socket::set_io_hooks(tcp_socket_io_hooks* new_hooks)
  {
    my->_io_hooks = new_hooks ? new_hooks : &*my;
  }

  void tcp_socket::set_reuse_address(bool enable /* = true */)
  {
    FC_ASSERT(my->_sock.next_layer().is_open());
    boost::asio::socket_base::reuse_address option(enable);
    my->_sock.next_layer().set_option(option);
#if defined(__APPLE__) || defined(__linux__)
# ifndef SO_REUSEPORT
#  define SO_REUSEPORT 15
# endif
    // OSX needs SO_REUSEPORT in addition to SO_REUSEADDR.
    // This probably needs to be set for any BSD
    if (detail::have_so_reuseport)
    {
      int reuseport_value = 1;
      if (setsockopt(my->_sock.next_layer().native_handle(), SOL_SOCKET, SO_REUSEPORT,
                     (char*)&reuseport_value, sizeof(reuseport_value)) < 0)
      {
        if (errno == ENOPROTOOPT)
          detail::have_so_reuseport = false;
        else
          wlog("Error setting SO_REUSEPORT");
      }
    }
#endif // __APPLE__
  }

  class tcp_server::impl {
    public:
      impl() : _accept(fc::asio::default_io_service())
      {
        _accept.open(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0).protocol());
      }

      ~impl()
      {
        try
        {
          _accept.close();
        }
        catch ( boost::system::system_error& )
        {
           wlog( "unexpected exception ${e}", ("e", fc::except_str()) );
        }
      }

      boost::asio::ip::tcp::acceptor _accept;
  };

  tcp_server::tcp_server()
  {
  }

  tcp_server::~tcp_server()
  {
  }

  void tcp_server::close()
  {
    if( my && my->_accept.is_open() )
      my->_accept.close();
    my.reset();
  }

  void tcp_server::accept( tcp_socket& s )
  {
    FC_ASSERT( my );
    try
    {
      fc::asio::tcp::accept(my->_accept, s.my->_sock.next_layer());
      if( s.my->_uses_ssl )
        fc::asio::ssl::handshake(s.my->_sock, boost::asio::ssl::stream_base::server);
    } FC_RETHROW_EXCEPTIONS( warn, "Unable to accept connection on socket." );
  }

  void tcp_server::set_reuse_address(bool enable /* = true */)
  {
    if( !my )
      my.reset(new impl);
    boost::asio::ip::tcp::acceptor::reuse_address option(enable);
    my->_accept.set_option(option);
#if defined(__APPLE__) || (defined(__linux__) && defined(SO_REUSEPORT))
    // OSX needs SO_REUSEPORT in addition to SO_REUSEADDR.
    // This probably needs to be set for any BSD
    if (detail::have_so_reuseport)
    {
      int reuseport_value = 1;
      if (setsockopt(my->_accept.native_handle(), SOL_SOCKET, SO_REUSEPORT,
                     (char*)&reuseport_value, sizeof(reuseport_value)) < 0)
      {
        if (errno == ENOPROTOOPT)
          detail::have_so_reuseport = false;
        else
          wlog("Error setting SO_REUSEPORT");
      }
    }
#endif // __APPLE__
  }

  void tcp_server::listen( uint16_t port )
  {
    if( !my )
      my.reset(new impl);
    try
    {
      my->_accept.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4(), port));
      my->_accept.listen();
    }
    FC_RETHROW_EXCEPTIONS(warn, "error listening on socket");
  }

  void tcp_server::listen( const fc::ip::endpoint& ep )
  {
    if( !my )
      my.reset(new impl);
    try
    {
      my->_accept.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::from_string((std::string)ep.get_address()), ep.port()));
      my->_accept.listen();
    }
    FC_RETHROW_EXCEPTIONS(warn, "error listening on socket");
  }

  fc::ip::endpoint tcp_server::get_local_endpoint() const
  {
    FC_ASSERT( my );
    return fc::ip::endpoint(my->_accept.local_endpoint().address().to_v4().to_ulong(), my->_accept.local_endpoint().port() );
  }

  uint16_t tcp_server::get_port()const
  {
    FC_ASSERT( my );
    return my->_accept.local_endpoint().port();
  }

} // namespace fc
