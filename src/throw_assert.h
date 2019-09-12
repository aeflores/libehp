

#ifndef throw_asssert
#define throw_assert(a) { if(!(a)) throw std::invalid_argument(#a); } 
#endif
