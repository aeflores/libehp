

#include <ehp.hpp>
#include <iostream>

using namespace std;
using namespace EHP;

void usage(int argc, char* argv[])
{
	cout<<"Usage: "<<argv[0]<<" <program to print eh info>"<<endl;
	exit(1);
}


int main(int argc, char* argv[])
{

	if(argc!=2)
	{
		usage(argc,argv);
	}

	auto ehp = EHFrameParser_t::factory(argv[1]);
	ehp->print();

	return 0;
}
