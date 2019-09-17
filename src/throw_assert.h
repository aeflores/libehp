// @HEADER_COMPONENT libehp
// @HEADER_LANG C++
// @HEADER_BEGIN

/*
   Copyright 2017-2019 University of Virginia

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// @HEADER_END

#define use_throwing_assert

#ifndef throw_asssert

#ifdef use_throwing_assert
#define throw_assert(a) { if(!(a)) throw std::invalid_argument(#a); } 
#else
#include <assert.h>
#define throw_assert(a) { assert(a); } 
#endif
#endif
