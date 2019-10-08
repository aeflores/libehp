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


#ifndef ehp_hpp
#define ehp_hpp

#include <limits>
#include <map>
#include <memory>
#include <set>
#include <vector>


#ifndef USE_ELFIO 
#define USE_ELFIO 1
#endif

namespace EHP
{

using namespace std;

using EHProgramInstructionByteVector_t = vector<uint8_t>;
class EHProgramInstruction_t 
{
	protected:
	EHProgramInstruction_t() {}
	EHProgramInstruction_t(const EHProgramInstruction_t&) {}
	public: 
	virtual ~EHProgramInstruction_t() {}
	virtual void print(uint64_t &pc, int64_t caf=1) const = 0;
	virtual tuple<string, int64_t, int64_t> decode() const = 0;
	virtual uint64_t getSize() const = 0;
	virtual bool isNop() const = 0;
	virtual bool isDefCFAOffset() const = 0;
	virtual bool isRestoreState() const = 0;
	virtual bool isRememberState() const = 0;
	virtual const EHProgramInstructionByteVector_t& getBytes() const = 0;
        virtual bool advance(uint64_t &cur_addr, uint64_t CAF)     const = 0;

};

using EHProgramInstructionVector_t = vector<const EHProgramInstruction_t*>;
class EHProgram_t
{
	protected:
	EHProgram_t() {}
	EHProgram_t(const EHProgram_t&) {}
	public:
	virtual ~EHProgram_t() {}
	virtual void print(const uint64_t start_addr, const int64_t caf) const =0;
	virtual const EHProgramInstructionVector_t* getInstructions()          const =0;
};

class CIEContents_t 
{
	protected:
	CIEContents_t() {} 
	CIEContents_t(const CIEContents_t&) {} 
	public:
	virtual ~CIEContents_t() {}
	virtual const EHProgram_t& getProgram() const =0;
	virtual uint64_t getPosition() const = 0;
	virtual uint64_t getLength() const = 0;
	virtual uint64_t getCAF() const =0;
	virtual int64_t getDAF() const =0;
	virtual uint64_t getPersonality() const =0;
	virtual uint8_t getPersonalityEncoding() const = 0;
	virtual uint64_t getPersonalityPointerPosition() const = 0;
	virtual uint64_t getPersonalityPointerSize() const = 0;
	virtual uint64_t getReturnRegister() const =0;
	virtual string getAugmentation() const =0;
	virtual uint8_t getLSDAEncoding() const =0;
	virtual uint8_t getFDEEncoding() const =0;
	virtual void print(const uint64_t startAddr) const =0;
};

class LSDACallSiteAction_t 
{
	protected:
	LSDACallSiteAction_t() {} 
	LSDACallSiteAction_t(const LSDACallSiteAction_t&) {} 
	public:
	virtual ~LSDACallSiteAction_t() {}
	virtual int64_t getAction() const =0;
	virtual void print() const=0;
};

class LSDATypeTableEntry_t 
{
	protected:
	LSDATypeTableEntry_t() {}
	LSDATypeTableEntry_t(const LSDATypeTableEntry_t&) {}
	public:
	virtual ~LSDATypeTableEntry_t() {} 
	virtual uint64_t getTypeInfoPointer() const =0;
	virtual uint64_t getEncoding() const =0;
	virtual uint64_t getTTEncodingSize() const =0;
	virtual void print() const=0;
	
};

using LSDACallSiteActionVector_t=vector<const LSDACallSiteAction_t*>;
class LSDACallSite_t 
{
	protected:
	LSDACallSite_t() {}
	LSDACallSite_t(const LSDACallSite_t&) {}
	public:
	virtual ~LSDACallSite_t() {}
	virtual const LSDACallSiteActionVector_t* getActionTable() const =0;
	virtual uint64_t getCallSiteAddress() const  =0;
	virtual uint64_t getCallSiteAddressPosition() const = 0;
	virtual uint64_t getCallSiteEndAddress() const  =0;
	virtual uint64_t getCallSiteEndAddressPosition() const = 0;
	virtual uint64_t getLandingPadAddress() const  =0;
	virtual uint64_t getLandingPadAddressPosition() const = 0;
	virtual uint64_t getLandingPadAddressEndPosition() const = 0;
	virtual void print() const=0;
};

using CallSiteVector_t  = vector<const LSDACallSite_t*>;
using TypeTableVector_t = vector<const LSDATypeTableEntry_t*>;

class LSDA_t 
{
	protected:
	LSDA_t() {}
	LSDA_t(const LSDA_t&) {}
	public:
	virtual ~LSDA_t() {}
	virtual uint8_t getTTEncoding() const =0;
	virtual void print() const=0;
	virtual uint64_t getLandingPadBaseAddress() const = 0;
    virtual const CallSiteVector_t* getCallSites() const =0;
	virtual uint64_t getCallSiteTableAddress() const = 0;
	virtual uint64_t getCallSiteTableAddressLocation() const = 0;
	virtual uint8_t getCallSiteTableEncoding() const = 0;
    virtual const TypeTableVector_t* getTypeTable() const =0;
	virtual uint64_t getTypeTableAddress() const = 0;
	virtual uint64_t getTypeTableAddressLocation() const = 0;
    virtual uint64_t getCallSiteTableLength() const = 0;
	virtual uint8_t getTypeTableEncoding() const = 0;
	unique_ptr<LSDA_t> factory(const string lsda_data, const uint64_t lsda_start_addr);
};


class FDEContents_t 
{
	protected:
	FDEContents_t() {}
	FDEContents_t(const FDEContents_t&) {}
	public:
	virtual ~FDEContents_t() {}

	virtual uint64_t getPosition() const =0;
	virtual uint64_t getLength() const =0;
	virtual uint64_t getStartAddress() const =0;
	virtual uint64_t getEndAddress() const =0;
	virtual const CIEContents_t& getCIE() const =0;
	virtual const EHProgram_t& getProgram() const =0;
	virtual const LSDA_t* getLSDA() const =0;
	virtual uint64_t getLSDAAddress() const =0;
	virtual uint64_t getStartAddressPosition() const = 0;
    virtual uint64_t getEndAddressPosition() const = 0;
    virtual uint64_t getEndAddressSize() const = 0;
    virtual uint64_t getLSDAAddressPosition() const = 0;
    virtual uint64_t getLSDAAddressSize() const = 0;
	virtual void print() const=0;	// move to ostream?  toString?

};


using FDEVector_t = vector<const FDEContents_t*>;
using CIEVector_t = vector<const CIEContents_t*>;
class EHFrameParser_t 
{
	protected:
	EHFrameParser_t() {}
	EHFrameParser_t(const EHFrameParser_t&) {}
	public:
	virtual ~EHFrameParser_t() {}
	virtual bool parse()=0;
	virtual void print() const=0;
	virtual const FDEVector_t* getFDEs() const =0;
	virtual const CIEVector_t* getCIEs() const =0;
	virtual const FDEContents_t* findFDE(uint64_t addr) const =0; 

#if USE_ELFIO 
	static unique_ptr<const EHFrameParser_t> factory(const string filename);
#endif
	static unique_ptr<const EHFrameParser_t> factory(
		uint8_t ptrsize,
		const string eh_frame_data, const uint64_t eh_frame_data_start_addr,
		const string eh_frame_hdr_data, const uint64_t eh_frame_hdr_data_start_addr,
		const string gcc_except_table_data, const uint64_t gcc_except_table_data_start_addr
		);
};

// e.g.
// const auto &ehparser=EHFrameParse_t::factory("a.out");
// for(const auto &fde : ehparser->getFDES()) { ... } 


}
#endif

