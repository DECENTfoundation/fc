#pragma once
#include <functional>
#include <fc/exception.hpp>
#include <boost/type_index.hpp>
#include <boost/any.hpp>

namespace fc {

   template<typename Api>
   struct api_base {
      static std::string get_api_name()
      {
         const std::string str = boost::typeindex::type_id<Api>().pretty_name();
         // remove namespaces
         size_t pos = str.find_last_of(":");
         return pos == std::string::npos ? str : str.substr( pos + 1 );
      }
   };

  struct identity_member {
      template<typename R, typename C, typename... Args>
      static std::function<R(Args...)> functor( R (C::*mem_func)(Args...) );
      template<typename R, typename C, typename... Args>
      static std::function<R(Args...)> functor( R (C::*mem_func)(Args...)const );
  };

  template<typename Interface, typename Transform = identity_member>
  struct vtable : public std::enable_shared_from_this<vtable<Interface,Transform>>
  { private: vtable(); };

  template<typename Adaptor>
  struct vtable_copy_visitor {
      typedef Adaptor other_type;
      vtable_copy_visitor( Adaptor& s):_source( s ){}

      template<typename R, typename MemberPtr, typename... Args>
      void operator()( const char* name, std::function<R(Args...)>& memb, MemberPtr m )const
      {
        memb = [=, src = &_source]( Args... args ){ return (src->*m)(args...); };
      }
      Adaptor& _source;
  };

  template<typename Interface>
  class api {
    public:
      typedef vtable<Interface> vtable_type;

      api():_vtable( std::make_shared<vtable_type>() ) {}

      template<typename Adaptor>
      api( const Adaptor& p ) :_vtable( std::make_shared<vtable_type>() )
      {
         _instance = std::make_shared<boost::any>(p);
         Adaptor& ptr = boost::any_cast<Adaptor&>(*_instance);
         _vtable->visit_other( vtable_copy_visitor<std::remove_reference_t<decltype(*ptr)>>(*ptr) );
      }

      api( const api& cpy ):_vtable(cpy._vtable),_instance(cpy._instance) {}

      friend bool operator == ( const api& a, const api& b ) { return a._instance == b._instance && a._vtable == b._vtable; }
      friend bool operator != ( const api& a, const api& b ) { return !(a._instance == b._instance && a._vtable == b._vtable); }
      uint64_t handle() const { return uint64_t(_instance.get()); }

      vtable_type& operator*()const  { FC_ASSERT( _vtable ); return *_vtable; }
      vtable_type* operator->()const {  FC_ASSERT( _vtable ); return _vtable.get(); }

      std::string get_api_name()const { return Interface::get_api_name(); }

    private:
      std::shared_ptr<vtable_type>    _vtable;
      std::shared_ptr<boost::any>     _instance;
  };

} // namespace fc

#include <boost/preprocessor/repeat.hpp>
#include <boost/preprocessor/repetition/enum_binary_params.hpp>
#include <boost/preprocessor/repetition/enum_params.hpp>
#include <boost/preprocessor/repetition/enum_trailing_params.hpp>
#include <boost/preprocessor/facilities/empty.hpp>
#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/stringize.hpp>

#define FC_API_VTABLE_DEFINE_MEMBER( r, data, elem ) \
      decltype(Transform::functor(&data::elem)) elem;
#define FC_API_VTABLE_DEFINE_VISIT_OTHER( r, data, elem ) \
        { typedef typename Visitor::other_type OtherType; \
        v( BOOST_PP_STRINGIZE(elem), elem, &OtherType::elem ); }
#define FC_API_VTABLE_DEFINE_VISIT( r, data, elem ) \
        v( BOOST_PP_STRINGIZE(elem), elem );

#define FC_API( CLASS, METHODS ) \
namespace fc { \
  template<typename Transform> \
  struct vtable<CLASS,Transform> : public std::enable_shared_from_this<vtable<CLASS,Transform>> { \
      BOOST_PP_SEQ_FOR_EACH( FC_API_VTABLE_DEFINE_MEMBER, CLASS, METHODS ) \
      template<typename Visitor> \
      void visit_other( Visitor&& v ){ \
        BOOST_PP_SEQ_FOR_EACH( FC_API_VTABLE_DEFINE_VISIT_OTHER, CLASS, METHODS ) \
      } \
      template<typename Visitor> \
      void visit( Visitor&& v ){ \
        BOOST_PP_SEQ_FOR_EACH( FC_API_VTABLE_DEFINE_VISIT, CLASS, METHODS ) \
      } \
  }; \
}
