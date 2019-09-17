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

#ifndef ehp_priv_hpp
#define ehp_priv_hpp

#include <iostream>
#include <iomanip>
#include <fstream>
#include <limits>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <algorithm>
#include <memory>
#include <set>

#include "ehp_dwarf2.hpp"
#include "scoop_replacement.hpp"


namespace EHP
{

using namespace std;


template <int ptrsize>
class eh_frame_util_t 
{
	public: 
	template <class T> 
	static bool read_type(T &value, uint32_t &position, const uint8_t* const data, const uint32_t max);
	template <class T> 
	static bool read_type_with_encoding
		(const uint8_t encoding, T &value, 
		uint32_t &position, 
		const uint8_t* const data, 
		const uint32_t max, 
		const uint64_t section_start_addr );

	static bool read_string 
		(string &s, 
		uint32_t & position, 
		const uint8_t* const data, 
		const uint32_t max);


	// see https://en.wikipedia.org/wiki/LEB128
	static bool read_uleb128 
		( uint64_t &result, 
		uint32_t& position, 
		const uint8_t* const data, 
		const uint32_t max);

	// see https://en.wikipedia.org/wiki/LEB128
	static bool read_sleb128 ( 
		int64_t &result, 
		uint32_t & position, 
		const uint8_t* const data, 
		const uint32_t max);
	
	static bool read_length(
		uint64_t &act_length, 
		uint32_t &position, 
		const uint8_t* const data, 
		const uint32_t max);
};

template <int ptrsize>
class eh_program_insn_t  : public EHProgramInstruction_t
{
	public: 
	
	eh_program_insn_t() ;
	eh_program_insn_t(const string &s) ;

	void print(uint64_t &pc, int64_t caf) const;
	tuple<string, int64_t, int64_t> decode() const;
	uint64_t getSize() const { return program_bytes.size(); }
	void push_byte(uint8_t c) ;

	static void print_uleb_operand(
		uint32_t pos, 
		const uint8_t* const data, 
		const uint32_t max) ;

	static void print_sleb_operand(
		uint32_t pos, 
		const uint8_t* const data, 
		const uint32_t max) ;

	bool parse_insn(
		uint8_t opcode, 
		uint32_t& pos, 
		const uint8_t* const data, 
		const uint32_t &max);

	bool isNop() const ;
	bool isDefCFAOffset() const ;
	bool isRestoreState() const ;
	bool isRememberState() const ;

	bool advance(uint64_t &cur_addr, uint64_t CAF) const ;

	const vector<uint8_t>& getBytes() const ;
	vector<uint8_t>& getBytes() ;

	private:

	vector<uint8_t> program_bytes;
};

template <int ptrsize>
bool operator<(const eh_program_insn_t<ptrsize>& a, const eh_program_insn_t<ptrsize>& b);

template <int ptrsize>
class eh_program_t : public EHProgram_t
{
	public:
	void push_insn(const eh_program_insn_t<ptrsize> &i); 

	void print(const uint64_t start_addr, const int64_t caf) const;

	bool parse_program(
		const uint32_t& program_start_position, 
		const uint8_t* const data, 
		const uint32_t &max_program_pos);
        virtual const EHProgramInstructionVector_t* getInstructions() const ;
	vector<eh_program_insn_t <ptrsize> >& getInstructionsInternal() ;
	const vector<eh_program_insn_t <ptrsize> >& getInstructionsInternal() const ;

	private:
	vector<eh_program_insn_t <ptrsize> > instructions;
	mutable EHProgramInstructionVector_t instructions_cache;
};

template <int ptrsize>
bool operator<(const eh_program_t<ptrsize>& a, const eh_program_t<ptrsize>& b);

template <int ptrsize>
class cie_contents_t : public CIEContents_t, private eh_frame_util_t<ptrsize>
{
	private:
	uint64_t cie_position;
	uint64_t length;
	uint8_t cie_id;
	uint8_t cie_version;
	string augmentation;
	uint64_t code_alignment_factor;
	int64_t data_alignment_factor;
	uint64_t return_address_register_column;
	uint64_t augmentation_data_length;
	uint8_t personality_encoding;
	uint64_t personality;
	uint64_t personality_pointer_position;
	uint64_t personality_pointer_size;
	uint8_t lsda_encoding;
	uint8_t fde_encoding;
	eh_program_t<ptrsize> eh_pgm;

	public:

	cie_contents_t() ;
	
	const eh_program_t<ptrsize>& getProgram() const ;
	uint64_t getPosition() const { return cie_position; }
	uint64_t getLength() const { return length; }
	uint64_t getCAF() const ;
	int64_t getDAF() const ;
	uint8_t getPersonalityEncoding() const { return personality_encoding; }
	uint64_t getPersonality() const ;
	uint64_t getPersonalityPointerPosition() const { return personality_pointer_position; };
	uint64_t getPersonalityPointerSize() const { return personality_pointer_size; };
	uint64_t getReturnRegister() const ;

	string getAugmentation() const ;
	uint8_t getLSDAEncoding() const ;
	uint8_t getFDEEncoding() const ;

	bool parse_cie(
		const uint32_t &cie_position, 
		const uint8_t* const data, 
		const uint32_t max, 
		const uint64_t eh_addr);
	void print(const uint64_t startAddr) const ;
};

template <int ptrsize>
class lsda_call_site_action_t : public LSDACallSiteAction_t, private eh_frame_util_t<ptrsize>
{
	private:
	int64_t action;

	public:
	lsda_call_site_action_t() ;
	int64_t getAction() const ;

	bool parse_lcsa(uint32_t& pos, const uint8_t* const data, const uint64_t max, bool &end);
	void print() const;
};

template <int ptrsize>
bool operator< (const lsda_call_site_action_t <ptrsize> &lhs, const lsda_call_site_action_t <ptrsize> &rhs);

template <int ptrsize>
class lsda_type_table_entry_t: public LSDATypeTableEntry_t, private eh_frame_util_t<ptrsize>
{
	private:
	uint64_t pointer_to_typeinfo;
	uint64_t tt_encoding;
	uint64_t tt_encoding_size;

	public:
	lsda_type_table_entry_t() ; 

	uint64_t getTypeInfoPointer() const ;
	uint64_t getEncoding() const ;
	uint64_t getTTEncodingSize() const ;

	bool parse(
		const uint64_t p_tt_encoding, 	
		const uint64_t tt_pos, 	
		const uint64_t index,
		const uint8_t* const data, 
		const uint64_t max,  
		const uint64_t data_addr
		);

	void print() const;
	
};

template <int ptrsize>
class lsda_call_site_t : public LSDACallSite_t, private eh_frame_util_t<ptrsize>
{
	private:
	uint64_t call_site_offset;
	uint64_t call_site_addr;
	uint64_t call_site_addr_position;
	uint64_t call_site_length;
	uint64_t call_site_end_addr;
	uint64_t call_site_end_addr_position;
	uint64_t landing_pad_offset;
	uint64_t landing_pad_addr;
	uint64_t landing_pad_addr_position;
	uint64_t landing_pad_addr_end_position;
	uint64_t action;
	uint64_t action_table_offset;
	uint64_t action_table_addr;

	vector<lsda_call_site_action_t <ptrsize> > action_table;
	mutable LSDACallSiteActionVector_t action_table_cache;

	public:
	lsda_call_site_t() ;

	const LSDACallSiteActionVector_t* getActionTable() const;
	const vector<lsda_call_site_action_t <ptrsize> >& getActionTableInternal() const { return action_table; }
	      vector<lsda_call_site_action_t <ptrsize> >& getActionTableInternal()       { return action_table; }

	uint64_t getCallSiteAddress() const  { return call_site_addr ; } 
	uint64_t getCallSiteAddressPosition() const { return call_site_addr_position; }
	uint64_t getCallSiteEndAddress() const  { return call_site_end_addr ; }
	uint64_t getCallSiteEndAddressPosition() const { return call_site_end_addr_position; }
	uint64_t getLandingPadAddress() const  { return landing_pad_addr ; }
	uint64_t getLandingPadAddressPosition() const { return landing_pad_addr_position; }
	uint64_t getLandingPadAddressEndPosition() const { return landing_pad_addr_end_position; }

	bool parse_lcs(	
		const uint64_t action_table_start_addr, 	
		const uint64_t cs_table_start_addr, 	
		const uint8_t cs_table_encoding, 
		uint32_t &pos, 
		const uint8_t* const data, 
		const uint64_t max,  /* call site table max */
		const uint64_t data_addr, 
		const uint64_t landing_pad_base_addr,
		const uint64_t gcc_except_table_max);

	void print() const;


};


// short hand for a vector of call sites
template <int ptrsize>  using call_site_table_t = vector<lsda_call_site_t <ptrsize> > ;
template <int ptrsize>  using lsda_type_table_t = vector<lsda_type_table_entry_t <ptrsize> > ;

template <int ptrsize>
class lsda_t : public LSDA_t, private eh_frame_util_t<ptrsize>
{
	private:
	uint8_t landing_pad_base_encoding;
	uint64_t landing_pad_base_addr; // often ommitted. when ommitted, filled in from FDE region start.
	uint8_t type_table_encoding;
	uint64_t type_table_offset;
	uint64_t type_table_addr;
	uint64_t type_table_addr_location;
	uint8_t cs_table_encoding;
	uint64_t cs_table_start_offset;
	uint64_t cs_table_start_addr;
	uint64_t cs_table_start_addr_location;
	uint64_t cs_table_length;
	uint64_t cs_table_end_addr;
	uint64_t action_table_start_addr;

	call_site_table_t<ptrsize>  call_site_table;
	// this is a vector of pointers into the call site table.
	// and is the thing we return when getCallSites is called.
	// this is marked as mutable so we can cache it between calls.
	mutable CallSiteVector_t call_site_table_cache ;

	lsda_type_table_t<ptrsize> type_table;

	// this is a vector of pointers into the type_table
	// and is the thing we return when getTypeTable is called.
	// this is marked as mutable so we can cache it between calls.
	mutable TypeTableVector_t type_table_cache ;

	public:

	lsda_t();

	uint8_t getTTEncoding() const ;
	bool parse_lsda(const uint64_t lsda_addr, 
			const ScoopReplacement_t* gcc_except_scoop_data,
	                const uint64_t fde_region_start
	                );
	void print() const;
	uint64_t getLandingPadBaseAddress() const {  return landing_pad_base_addr; }
	const CallSiteVector_t* getCallSites() const ;
	uint64_t getCallSiteTableAddress() const { return cs_table_start_addr; }
	uint64_t getCallSiteTableAddressLocation() const { return cs_table_start_addr_location; }
	uint64_t getCallSiteTableLength() const { return cs_table_length; }
	uint8_t getCallSiteTableEncoding() const { return cs_table_encoding; }
	const call_site_table_t<ptrsize> getCallSitesInternal() const { return call_site_table;}
	const TypeTableVector_t* getTypeTable() const ;
	uint64_t getTypeTableAddress() const { return type_table_addr; }
	uint64_t getTypeTableAddressLocation() const { return type_table_addr_location; }
	uint8_t getTypeTableEncoding() const { return type_table_encoding; }

};



template <int ptrsize>
class fde_contents_t : public FDEContents_t, eh_frame_util_t<ptrsize> 
{
	uint32_t fde_position;
	uint32_t cie_position;
	uint64_t length;
	uint8_t id;
	uint64_t fde_start_addr;
	uint64_t fde_end_addr;
	uint64_t fde_range_len;
	uint64_t lsda_addr;
    uint64_t fde_start_addr_position;
    uint64_t fde_end_addr_position;
    uint64_t fde_end_addr_size;
    uint64_t fde_lsda_addr_position;
    uint64_t fde_lsda_addr_size;

	lsda_t<ptrsize> lsda;
	eh_program_t<ptrsize> eh_pgm;
	cie_contents_t<ptrsize> cie_info;

	public:
	fde_contents_t() ;
	fde_contents_t(const uint64_t start_addr, const uint64_t end_addr)
		: 
		fde_start_addr(start_addr),
		fde_end_addr(end_addr)
	{} 
	uint64_t getPosition() const { return fde_position; }
	uint64_t getLength() const { return length; }
	uint64_t getStartAddress() const { return fde_start_addr; } 
	uint64_t getEndAddress() const {return fde_end_addr; }

	uint64_t getFDEStartAddress() const { return fde_start_addr; } 
	uint64_t getFDEEndAddress() const {return fde_end_addr; }

	const cie_contents_t<ptrsize>& getCIE() const ;
	cie_contents_t<ptrsize>& getCIE() ;

	const eh_program_t<ptrsize>& getProgram() const ;
	eh_program_t<ptrsize>& getProgram() ;

	const LSDA_t* getLSDA() const { return &lsda; } // shared_ptr<LSDA_t>(new lsda_t<ptrsize>(lsda)) ;  }
	const lsda_t<ptrsize>& getLSDAInternal() const { return lsda; }

    uint64_t getLSDAAddress() const { return lsda_addr; }
    uint64_t getStartAddressPosition() const { return fde_start_addr_position; }
    uint64_t getEndAddressPosition() const { return fde_end_addr_position; }
    uint64_t getEndAddressSize() const { return fde_end_addr_size; }
	uint64_t getLSDAAddressPosition() const { return fde_lsda_addr_position; }
	uint64_t getLSDAAddressSize() const { return fde_lsda_addr_size; }

	bool parse_fde(
		const uint32_t &fde_position, 
		const uint32_t &cie_position, 
		const uint8_t* const data, 
		const uint64_t max, 
		const uint64_t eh_addr,
		const ScoopReplacement_t *gcc_except_scoop);

	void print() const;


};

template <int ptrsize>
bool operator<(const fde_contents_t<ptrsize>& a, const fde_contents_t<ptrsize>& b) { return a.getFDEEndAddress()-1 < b.getFDEStartAddress(); }


template <int ptrsize>
class split_eh_frame_impl_t : public EHFrameParser_t
{
	private: 

	unique_ptr<ScoopReplacement_t> eh_frame_scoop;
	unique_ptr<ScoopReplacement_t> eh_frame_hdr_scoop;
	unique_ptr<ScoopReplacement_t> gcc_except_table_scoop;

	vector<cie_contents_t <ptrsize> > cies;
	mutable CIEVector_t cies_cache;

	set<fde_contents_t <ptrsize> > fdes;
	mutable FDEVector_t fdes_cache;


	bool iterate_fdes();

	public:

	split_eh_frame_impl_t
		(
		const ScoopReplacement_t &eh_frame,
		const ScoopReplacement_t &eh_frame_hdr,
		const ScoopReplacement_t &gcc_except_table 
		)
		:
			eh_frame_scoop(new ScoopReplacement_t(eh_frame)),
			eh_frame_hdr_scoop(new ScoopReplacement_t(eh_frame_hdr)),
			gcc_except_table_scoop(new ScoopReplacement_t(gcc_except_table))
	{
	}

	bool parse();
	void print() const;

        virtual const FDEVector_t* getFDEs() const;
        virtual const CIEVector_t* getCIEs() const;
        virtual const FDEContents_t* findFDE(uint64_t addr) const; 



};

}
#endif

