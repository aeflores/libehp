/*
   Copyright 2017-2018 Zephyr Software, LLC

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
#ifndef scoop_replacement_hpp
#define scoop_replacement_hpp

#include <string>

namespace EHP
{

using namespace std;

typedef uint64_t addr_t;

class ScoopReplacement_t
{
	public:

	ScoopReplacement_t(const string& in_data, const addr_t in_start)
		:
		data(in_data),
		start(in_start),
		end(0)
	{ 
		end=in_start+data.size()-1;
	}

	string getContents()  { return data; }
	const string& getContents()  const { return data; }

	addr_t getEnd() const { return end; }
	addr_t getStart() const { return start; } 

	private:
	string data;
	addr_t start, end;
};

	
}
#endif
