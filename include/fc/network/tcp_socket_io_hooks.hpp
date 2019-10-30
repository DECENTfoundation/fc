#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>

namespace fc
{
  struct tcp_socket_io_hooks
  {
    virtual ~tcp_socket_io_hooks() {}

    virtual size_t readsome(boost::asio::ip::tcp::socket& socket, char* buffer, size_t length) = 0;
    virtual size_t readsome(boost::asio::ip::tcp::socket& socket, const std::shared_ptr<char>& buffer, size_t length, size_t offset) = 0;
    virtual size_t writesome(boost::asio::ip::tcp::socket& socket, const char* buffer, size_t length) = 0;
    virtual size_t writesome(boost::asio::ip::tcp::socket& socket, const std::shared_ptr<const char>& buffer, size_t length, size_t offset) = 0;

    virtual size_t readsome(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket, char* buffer, size_t length) = 0;
    virtual size_t readsome(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket, const std::shared_ptr<char>& buffer, size_t length, size_t offset) = 0;
    virtual size_t writesome(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket, const char* buffer, size_t length) = 0;
    virtual size_t writesome(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket, const std::shared_ptr<const char>& buffer, size_t length, size_t offset) = 0;
  };

} // namesapce fc
