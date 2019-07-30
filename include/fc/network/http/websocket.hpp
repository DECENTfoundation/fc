#pragma once
#include <functional>
#include <memory>
#include <string>

#include <boost/any.hpp>
#include <fc/network/ip.hpp>
#include <boost/signals2/signal.hpp>

namespace fc { namespace http {
   namespace detail {
      class abstract_websocket_server;
      class websocket_client_impl;
      class websocket_tls_client_impl;
   } // namespace detail;

   class websocket_connection
   {
      public:
         virtual ~websocket_connection(){}
         virtual void send_message( const std::string& message ) = 0;
         virtual void close( int64_t code, const std::string& reason  ){};
         void on_message( const std::string& message ) { _on_message(message); }
         std::string on_http( const std::string& message ) { return _on_http(message); }

         void on_message_handler( const std::function<void(const std::string&)>& h ) { _on_message = h; }
         void on_http_handler( const std::function<std::string(const std::string&)>& h ) { _on_http = h; }

         void     set_session_data( boost::any d ){ _session_data = std::move(d); }
         boost::any& get_session_data() { return _session_data; }

         boost::signals2::signal<void()> closed;
         bool is_tls;
      private:
         boost::any                                _session_data;
         std::function<void(const std::string&)>   _on_message;
         std::function<std::string(const std::string&)> _on_http;
   };
   typedef std::shared_ptr<websocket_connection> websocket_connection_ptr;

   typedef std::function<void(const websocket_connection_ptr&, bool& is_tls)> on_connection_handler;

   class websocket_server
   {
      public:
         websocket_server(bool enable_permessage_deflate = true);
         ~websocket_server();

         void on_connection( const on_connection_handler& handler);
         void listen( uint16_t port );
         void listen( const fc::ip::endpoint& ep );
         void start_accept();

         void add_headers(const std::string& name, const std::string& value);

      private:
         std::unique_ptr<detail::abstract_websocket_server> my;
   };


   class websocket_tls_server
   {
      public:
         websocket_tls_server(const std::string& server_cert_file = std::string(),
                              const std::string& server_cert_key_file = std::string(),
                              const std::string& server_cert_chain_file = std::string(),
                              const std::string& ssl_password = std::string(),
                              bool enable_permessage_deflate = false);
         ~websocket_tls_server();

         void on_connection( const on_connection_handler& handler);
         void listen( uint16_t port );
         void listen( const fc::ip::endpoint& ep );
         void start_accept();

         void add_headers(const std::string& name, const std::string& value);

      private:
         std::unique_ptr<detail::abstract_websocket_server> my;
   };

   class websocket_client
   {
      public:
         websocket_client();
         ~websocket_client();

         websocket_connection_ptr connect( const std::string& uri );
         websocket_connection_ptr secure_connect( const std::string& uri );
      private:
         std::unique_ptr<detail::websocket_client_impl> my;
         std::unique_ptr<detail::websocket_tls_client_impl> smy;
   };
   class websocket_tls_client
   {
      public:
         websocket_tls_client();
         ~websocket_tls_client();

         websocket_connection_ptr connect( const std::string& uri );
      private:
         std::unique_ptr<detail::websocket_tls_client_impl> my;
   };

} }
