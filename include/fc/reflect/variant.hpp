#pragma once
#include <fc/reflect/reflect.hpp>
#include <fc/variant_object.hpp>

namespace fc
{
   template<typename T>
   void to_variant( const T& o, variant& v );
   template<typename T>
   void from_variant( const variant& v, T& o );

   template<typename T>
   struct to_variant_visitor
   {
         to_variant_visitor( mutable_variant_object& mvo, const T& v )
         :vo(mvo),val(v){}

         template<typename Member, class Class, Member (Class::*member)>
         void operator()( const char* name )const
         {
            this->add(vo,name,(val.*member));
         }

         template<typename M>
         void add( mutable_variant_object& vo, const char* name, const optional<M>& v )const
         {
            if( v.valid() )
               vo(name,*v);
         }

         template<typename M>
         void add( mutable_variant_object& vo, const char* name, const M& v )const
         { vo(name,v); }

         mutable_variant_object& vo;
         const T& val;
   };

   template<typename T>
   struct from_variant_visitor
   {
         from_variant_visitor( const variant_object& _vo, T& v )
         :vo(_vo),val(v){}

         template<typename Member, class Class, Member (Class::*member)>
         void operator()( const char* name )const
         {
            auto itr = vo.find(name);
            if( itr != vo.end() )
               from_variant( itr->value(), val.*member );
         }

         const variant_object& vo;
         T& val;
   };

   template<typename IsEnum=std::false_type>
   struct if_enum
   {
     template<typename T>
     static inline void to_variant( const T& v, fc::variant& vo )
     {
         mutable_variant_object mvo;
         fc::reflector<T>::visit( to_variant_visitor<T>( mvo, v ) );
         vo = std::move(mvo);
     }
     template<typename T>
     static inline void from_variant( const fc::variant& v, T& o )
     {
         const variant_object& vo = v.get_object();
         fc::reflector<T>::visit( from_variant_visitor<T>( vo, o ) );
     }
   };

    template<>
    struct if_enum<std::true_type>
    {
       template<typename T>
       static inline void to_variant( const T& o, fc::variant& v )
       {
           v = fc::reflector<T>::to_fc_string(o);
       }
       template<typename T>
       static inline void from_variant( const fc::variant& v, T& o )
       {
           if( v.is_string() )
              o = fc::reflector<T>::from_string( v.get_string().c_str() );
           else
              o = static_cast<T>(v.as_int64());
       }
    };

   template<typename T>
   void to_variant( const T& o, variant& v )
   {
      if_enum<typename fc::reflector<T>::is_enum>::to_variant( o, v );
   }

   template<typename T>
   void from_variant( const variant& v, T& o )
   {
      if_enum<typename fc::reflector<T>::is_enum>::from_variant( v, o );
   }

   template<typename T, T value, uint32_t magic>
   void to_variant(const reflect_default_value<T, value, magic>& o, variant& v)
   {
      if(o.instance != value)
         v = o.instance;
   }

   template<typename T, T value, uint32_t magic>
   void from_variant(const variant& v, reflect_default_value<T, value, magic>& o)
   {
      o.instance = v.is_null() ? value : v.as<T>();
   }

}
