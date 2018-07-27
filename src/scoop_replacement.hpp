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
