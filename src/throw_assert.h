

#define use_throwing_assert

#ifndef throw_asssert

#ifdef use_throwing_assert
#define throw_assert(a) { if(!(a)) throw std::invalid_argument(#a); } 
#else
#include <assert.h>
#define throw_assert(a) { assert(a); } 
#endif
#endif
