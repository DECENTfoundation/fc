#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace fc
{
  struct tcp_socket_io_hooks
  {
    virtual ~tcp_socket_io_hooks() = default;

    virtual size_t readsome(boost::asio::ip::tcp::socket& socket, char* buffer, size_t length) = 0;
    virtual size_t writesome(boost::asio::ip::tcp::socket& socket, const char* buffer, size_t length) = 0;

    virtual size_t readsome(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket, char* buffer, size_t length) = 0;
    virtual size_t writesome(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket, const char* buffer, size_t length) = 0;
  };

} // namesapce fc
