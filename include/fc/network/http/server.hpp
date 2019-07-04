#pragma once 
#include <fc/network/http/connection.hpp>
#include <functional>
#include <memory>

namespace fc { namespace http {

  /**
   *  Listens on a given port for incomming http
   *  connections and then calls a user provided callback
   *  function for every http request.
   *
   */
  class server 
  {
    public:
      server();
      server( uint16_t port );
      server( server&& s );
      ~server();

      server& operator=(server&& s);

      class response 
      {
        public:
          class impl;

          response();
          response( const std::shared_ptr<impl>& my);
          response( const response& r);
          response( response&& r );
          ~response();
          response& operator=(const response& );
          response& operator=( response&& );

          void add_header( const std::string& key, const std::string& val )const;
          void set_status( const http::reply::status_code& s )const;
          void set_length( uint64_t s )const;

          void write( const char* data, uint64_t len )const;

        private:
          std::shared_ptr<impl> my;
      };

      void listen( const fc::ip::endpoint& p );
      fc::ip::endpoint get_local_endpoint() const;

      void set_cors_domains(const std::string& cors);

      /**
       *  Set the callback to be called for every http request made.
       */
      void on_request( const std::function<void(const http::request&, const server::response& s )>& cb );

    private:
      class impl;
      std::unique_ptr<impl> my;
  };
  typedef std::shared_ptr<server> server_ptr;

} }
