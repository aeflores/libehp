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

#include <iostream>
#include <iomanip>
#include <fstream>
#include <limits>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <algorithm>
#include <memory>

#include <ehp.hpp>
#include "throw_assert.h"
#include "ehp_priv.hpp"
#include "scoop_replacement.hpp"

#ifndef USE_ELFIO
#define USE_ELFIO 1
#endif

#if USE_ELFIO 
#include <elfio/elfio.hpp>
#endif

using namespace std;
using namespace EHP;

#if USE_ELFIO
using namespace ELFIO;
#endif

#define ALLOF(s) begin(s), end(s)

template <int ptrsize>
template <class T> 
bool eh_frame_util_t<ptrsize>::read_type(T &value, uint64_t &position, const uint8_t* const data, const uint64_t max)
{
	if(position + sizeof(T) > max) return true;

	
	// typecast to the right type
	auto ptr=(const T*)&data[position];

	// set output parameters
	position+=sizeof(T);
	value=*ptr;

	return false;
	
}
template <int ptrsize>
template <class T> 
bool eh_frame_util_t<ptrsize>::read_type_with_encoding
	(const uint8_t encoding, T &value, 
	uint64_t &position,
	const uint8_t* const data, 
	const uint64_t max,
	const uint64_t section_start_addr )
{
	auto orig_position=position;
	auto encoding_lower8=encoding&0xf;
	auto encoding_upper8=encoding&0xf0;
	value=0;
	if(encoding == DW_EH_PE_omit)
		return true;
	switch(encoding_lower8)
	{
		case DW_EH_PE_uleb128:
		{
			auto newval=uint64_t(0);
			if(eh_frame_util_t<ptrsize>::read_uleb128(newval,position,data,max))
				return true;
			value=newval;
			break;
		}
		case DW_EH_PE_sleb128:
		{
			auto newval=int64_t(0);
			if(eh_frame_util_t<ptrsize>::read_sleb128(newval,position,data,max))
				return true;
			value=newval;
			break;
		}
		case DW_EH_PE_udata2 :
		{
			auto newval=uint16_t(0);
			if(eh_frame_util_t<ptrsize>::read_type(newval,position,data,max))
				return true;
			value=newval;
			break;
		}
		case DW_EH_PE_udata4 :
		{
			auto newval=uint32_t(0);
			if(eh_frame_util_t<ptrsize>::read_type(newval,position,data,max))
				return true;
			value=newval;
			break;
		}
		case DW_EH_PE_udata8 :
		{
			auto newval=uint64_t(0);
			if(eh_frame_util_t<ptrsize>::read_type(newval,position,data,max))
				return true;
			value=newval;
			break;
		}
		case DW_EH_PE_absptr:
		{
			if(ptrsize==8)
			{
				if(eh_frame_util_t<ptrsize>::read_type_with_encoding(DW_EH_PE_udata8, value, position, data, max, section_start_addr))
					return true;
				break;
			}
			else if(ptrsize==4)
			{
				if(eh_frame_util_t<ptrsize>::read_type_with_encoding(DW_EH_PE_udata4, value, position, data, max, section_start_addr))
					return true;
				break;
			}
			throw_assert(0);
				
		}
		case DW_EH_PE_sdata2 :
		{
			auto newval=int16_t(0);
			if(eh_frame_util_t<ptrsize>::read_type(newval,position,data,max))
				return true;
			value=newval;
			break;
		}
		case DW_EH_PE_sdata4 :
		{
			auto newval=int32_t(0);
			if(eh_frame_util_t<ptrsize>::read_type(newval,position,data,max))
				return true;
			value=newval;
			break;
		}
		case DW_EH_PE_sdata8 :
		{
			auto newval=int64_t(0);
			if(read_type(newval,position,data,max))
				return true;
			value=newval;
			break;
		}

		case DW_EH_PE_signed :
		default:
			throw_assert(0);
	};

	switch(encoding_upper8)
	{
		case DW_EH_PE_absptr:
			break; 
		case DW_EH_PE_pcrel  :
			value+=section_start_addr+orig_position;
			break;
		case DW_EH_PE_textrel:
		case DW_EH_PE_datarel:
		case DW_EH_PE_funcrel:
		case DW_EH_PE_aligned:
		case DW_EH_PE_indirect:
		default:
			throw_assert(0);
			return true;
	}
	return false;
}

template <int ptrsize>
bool eh_frame_util_t<ptrsize>::read_string 
	(string &s, 
	uint64_t &position,
	const uint8_t* const data, 
	const uint64_t max)
{
	while(data[position]!='\0' && position < max)
	{
		s+=data[position];	
		position++;
	}

	position++;
	return (position>max);
}


// see https://en.wikipedia.org/wiki/LEB128
template <int ptrsize>
bool eh_frame_util_t<ptrsize>::read_uleb128 
	( uint64_t &result, 
	uint64_t &position,
	const uint8_t* const data, 
	const uint64_t max)
{
	result = 0;
	auto shift = 0;
	while( position < max )
	{
		auto byte = data[position];
		position++;
		result |= ( ( byte & 0x7f ) << shift);
		if ( ( byte & 0x80) == 0)
			break;
		shift += 7;
	}
	return ( position > max );

}
// see https://en.wikipedia.org/wiki/LEB128
template <int ptrsize>
bool eh_frame_util_t<ptrsize>::read_sleb128 ( 
	int64_t &result, 
	uint64_t &position,
	const uint8_t* const data, 
	const uint64_t max)
{
	result = 0;
	auto shift = 0;
	auto size = 64;  // number of bits in signed integer;
	auto byte=uint8_t(0);
	do
	{
		if ( position > max )
			return true;
		byte = data [position]; 
		result |= ((byte & 0x7f)<< shift);
		shift += 7;
		position++;
	} while( (byte & 0x80) != 0);

	/* sign bit of byte is second high order bit (0x40) */
	if ((shift < size) && ( (byte & 0x40) !=0 /* sign bit of byte is set */))
		/* sign extend */
		result |= - (1 << shift);
	return ( position > max );

}

template <int ptrsize>
bool eh_frame_util_t<ptrsize>::read_length(
	uint64_t &act_length, 
	uint64_t &position,
	const uint8_t* const data, 
	const uint64_t max)
{
	auto eh_frame_scoop_data=data;
	auto length=uint32_t(0);
	auto length_64bit=uint64_t(0);
	if(read_type(length,position, eh_frame_scoop_data, max))
		return true;

	if(length==0xffffffff)
	{
		if(read_type(length_64bit,position, eh_frame_scoop_data, max))
			return true;
		act_length=length_64bit;
	}
	else
		act_length=length;

	return false;
}

template <int ptrsize>
eh_program_insn_t<ptrsize>::eh_program_insn_t() { }

template <int ptrsize>
eh_program_insn_t<ptrsize>::eh_program_insn_t(const string &s) 
	: program_bytes(s.begin(), next(s.begin(), s.size()))
{ }

template <int ptrsize>
void eh_program_insn_t<ptrsize>::print(uint64_t &pc, int64_t caf) const
{
	// make sure uint8_t is an unsigned char.	
	static_assert(is_same<unsigned char, uint8_t>::value, "uint8_t is not unsigned char");

	auto &data=program_bytes;
	auto opcode=program_bytes[0];
	auto opcode_upper2=(uint8_t)(opcode >> 6);
	auto opcode_lower6=(uint8_t)(opcode & (0x3f));
	auto pos=uint64_t(1);
	auto max=program_bytes.size();

	switch(opcode_upper2)
	{
		case 1:
		{
			// case DW_CFA_advance_loc:
			pc+=(opcode_lower6*caf);
			cout<<"				cfa_advance_loc "<<dec<<+opcode_lower6<<" to "<<hex<<pc<<endl;
			break;
		}
		case 2:
		{
			uint64_t uleb=0;
			if(eh_frame_util_t<ptrsize>::read_uleb128(uleb, pos, (const uint8_t* const)data.data(), max))
				return;
			// case DW_CFA_offset:
			cout<<"				cfa_offset "<<dec<<uleb<<endl;
			break;
		}
		case 3:
		{
			// case DW_CFA_restore (register #):
			cout<<"				cfa_restore"<<endl;
			break;
		}
		case 0:
		{
			switch(opcode_lower6)
			{
			
				case DW_CFA_nop:
					cout<<"				nop" <<endl;
					break;
				case DW_CFA_remember_state:
					cout<<"				remember_state" <<endl;
					break;
				case DW_CFA_restore_state:
					cout<<"				restore_state" <<endl;
					break;

				// takes single uleb128
				case DW_CFA_undefined:
					cout<<"				undefined" ;
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max); 
					cout<<endl;
					break;
		
				case DW_CFA_same_value:
					cout<<"				same_value ";
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max); 
					cout<<endl;
					break;
				case DW_CFA_restore_extended:
					cout<<"				restore_extended ";
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max); 
					cout<<endl;
					break;
				case DW_CFA_def_cfa_register:
					cout<<"				def_cfa_register ";
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max); 
					cout<<endl;
					break;
				case DW_CFA_GNU_args_size:
					cout<<"				GNU_arg_size ";
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max); 
					cout<<endl;
					break;
				case DW_CFA_def_cfa_offset:
					cout<<"				def_cfa_offset "; 
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max); 
					cout<<endl;
					break;

				case DW_CFA_set_loc:
				{
					auto arg=uintptr_t(0xDEADBEEF);
					switch(ptrsize)
					{
						case 4:
							arg=*(uint32_t*)&data.data()[pos]; break;
						case 8:
							arg=*(uint64_t*)&data.data()[pos]; break;
					}
					cout<<"				set_loc "<<hex<<arg<<endl;
					break;
				}
				case DW_CFA_advance_loc1:
				{
					auto loc=*(uint8_t*)(&data.data()[pos]);
					pc+=(loc*caf);
					cout<<"				advance_loc1 "<<+loc<<" to " <<pc << endl;
					break;
				}

				case DW_CFA_advance_loc2:
				{
					auto loc=*(uint16_t*)(&data.data()[pos]);
					pc+=(loc*caf);
					cout<<"				advance_loc2 "<<+loc<<" to " <<pc << endl;
					break;
				}

				case DW_CFA_advance_loc4:
				{
					auto loc=*(uint32_t*)(&data.data()[pos]);
					pc+=(loc*caf);
					cout<<"				advance_loc4 "<<+loc<<" to " <<pc << endl;
					break;
				}
				case DW_CFA_offset_extended:
					cout<<"				offset_extended ";
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max);
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max);
					cout<<endl;
					break;
				case DW_CFA_register:
					cout<<"				register ";
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max);
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max);
					cout<<endl;
					break;
				case DW_CFA_def_cfa:
					cout<<"				def_cfa ";
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max);
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max);
					cout<<endl;
					break;
				case DW_CFA_def_cfa_sf:
					cout<<"				def_cfa_sf ";
					print_uleb_operand(pos,(const uint8_t* const)data.data(),max);
					print_sleb_operand(pos,(const uint8_t* const)data.data(),max);
					cout<<endl;
					break;

				case DW_CFA_def_cfa_expression:
				{
					auto uleb=uint64_t(0);
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb, pos, (const uint8_t* const)data.data(), max))
						return ;
					cout<<"				def_cfa_expression "<<dec<<uleb<<endl;
					break;
				}
				case DW_CFA_expression:
				{
					auto uleb1=uint64_t(0);
					auto uleb2=uint64_t(0);
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb1, pos, (const uint8_t* const)data.data(), max))
						return ;
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb2, pos, (const uint8_t* const)data.data(), max))
						return ;
					cout<<"                              expression "<<dec<<uleb1<<" "<<uleb2<<endl;
					break;
				}
				case DW_CFA_val_expression:
				{
					auto uleb1=uint64_t(0);
					auto uleb2=uint64_t(0);
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb1, pos, (const uint8_t* const)data.data(), max))
						return ;
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb2, pos, (const uint8_t* const)data.data(), max))
						return ;
					cout<<"                              val_expression "<<dec<<uleb1<<" "<<uleb2<<endl;
					break;
				}
				case DW_CFA_def_cfa_offset_sf:
				{
					auto leb=int64_t(0);
					if(eh_frame_util_t<ptrsize>::read_sleb128(leb, pos, (const uint8_t* const)data.data(), max))
						return ;
					cout<<"					def_cfa_offset_sf "<<dec<<leb;
					break;
				}
				case DW_CFA_offset_extended_sf:
				{
					auto uleb1=uint64_t(0);
					auto sleb2=int64_t(0);
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb1, pos, (const uint8_t* const)data.data(), max))
						return ;
					if(eh_frame_util_t<ptrsize>::read_sleb128(sleb2, pos, (const uint8_t* const)data.data(), max))
						return ;
					cout<<"                              offset_extended_sf "<<dec<<uleb1<<" "<<sleb2<<endl;
					break;
				}


				/* SGI/MIPS specific */
				case DW_CFA_MIPS_advance_loc8:

				/* GNU extensions */
				case DW_CFA_GNU_window_save:
				case DW_CFA_GNU_negative_offset_extended:
				default:
					cout<<"Unhandled opcode cannot print. opcode="<<opcode<<endl;
			}
			break;
		}
	}

}

template <int ptrsize>
tuple<string, int64_t, int64_t> eh_program_insn_t<ptrsize>::decode() const
{
    // make sure uint8_t is an unsigned char.
    static_assert(is_same<unsigned char, uint8_t>::value, "uint8_t is not unsigned char");

    auto& data = program_bytes;
    auto opcode = program_bytes[0];
    auto opcode_upper2 = (uint8_t)(opcode >> 6);
    auto opcode_lower6 = (uint8_t)(opcode & (0x3f));
    auto pos = uint64_t(1);
    auto max = program_bytes.size();
    uint64_t uleb = 0;
    uint64_t uleb2 = 0;
    int64_t sleb = 0;
    switch(opcode_upper2)
    {
        case 1:
            // case DW_CFA_advance_loc:
            return make_tuple("cf_advance_loc", +opcode_lower6, 0);
        case 2:
            if(eh_frame_util_t<ptrsize>::read_uleb128(uleb, pos, (const uint8_t* const)data.data(),
                                                      max))
                return make_tuple("unexpected_error", 0, 0);
            // case DW_CFA_offset:
            return make_tuple("offset", +opcode_lower6, uleb);
        case 3:
            // case DW_CFA_restore (register #):
            return make_tuple("restore", +opcode_lower6, 0);
        case 0:
            switch(opcode_lower6)
            {
                case DW_CFA_nop:
                    return make_tuple("nop", 0, 0);
                case DW_CFA_remember_state:
                    return make_tuple("remember_state", 0, 0);
                case DW_CFA_restore_state:
                    return make_tuple("restore_state", 0, 0);
                // takes single uleb128
                case DW_CFA_undefined:
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("undefined", uleb, 0);
                case DW_CFA_same_value:
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("same_value", uleb, 0);
                case DW_CFA_restore_extended:
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("restore_extended", uleb, 0);
                case DW_CFA_def_cfa_register:
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("def_cfa_register", uleb, 0);
                case DW_CFA_def_cfa_offset:
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("def_cfa_offset", uleb, 0);
                case DW_CFA_set_loc:
                {
                    auto arg = uintptr_t(0xDEADBEEF);
                    switch(ptrsize)
                    {
                        case 4:
                            arg = *(uint32_t*)&data.data()[pos];
                            break;
                        case 8:
                            arg = *(uint64_t*)&data.data()[pos];
                            break;
                    }
                    return make_tuple("set_loc", arg, 0);
                }
                case DW_CFA_advance_loc1:
                {
                    auto loc = *(uint8_t*)(&data.data()[pos]);
                    return make_tuple("advance_loc", loc, 0);
                }

                case DW_CFA_advance_loc2:
                {
                    auto loc = *(uint16_t*)(&data.data()[pos]);
                    return make_tuple("advance_loc", loc, 0);
                }

                case DW_CFA_advance_loc4:
                {
                    auto loc = *(uint32_t*)(&data.data()[pos]);
                    return make_tuple("advance_loc", loc, 0);
                }
                case DW_CFA_offset_extended:
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb2, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("offset_extended", uleb, uleb2);
                case DW_CFA_register:
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb2, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("register", uleb, uleb2);

                case DW_CFA_def_cfa:
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb2, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("def_cfa", uleb, uleb2);

                case DW_CFA_def_cfa_sf:
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    if(eh_frame_util_t<ptrsize>::read_sleb128(
                           sleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("def_cfa_sf", uleb, sleb);
                case DW_CFA_def_cfa_offset_sf:
                {
                    if(eh_frame_util_t<ptrsize>::read_sleb128(
                           sleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("def_cfa_offset_sf", sleb, 0);
                }
                case DW_CFA_offset_extended_sf:
                {
                    if(eh_frame_util_t<ptrsize>::read_uleb128(
                           uleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    if(eh_frame_util_t<ptrsize>::read_sleb128(
                           sleb, pos, (const uint8_t* const)data.data(), max))
                        return make_tuple("unexpected_error", 0, 0);
                    return make_tuple("offset_extended_sf", uleb, sleb);
                }

                case DW_CFA_def_cfa_expression:
                case DW_CFA_expression:
                case DW_CFA_val_expression:
                /* SGI/MIPS specific */
                case DW_CFA_MIPS_advance_loc8:
                /* GNU extensions */
				case DW_CFA_GNU_args_size:
                case DW_CFA_GNU_window_save:
                case DW_CFA_GNU_negative_offset_extended:
                default:
                    return make_tuple("unhandled_instruction", 0, 0);
            }
		default:
			return make_tuple("unhandled_instruction", 0, 0);
    }
}

template <int ptrsize>
void eh_program_insn_t<ptrsize>::push_byte(uint8_t c) { program_bytes.push_back(c); }

template <int ptrsize>
void eh_program_insn_t<ptrsize>::print_uleb_operand(
	uint64_t pos,
	const uint8_t* const data, 
	const uint64_t max)
{
	auto uleb=uint64_t(0xdeadbeef);
	eh_frame_util_t<ptrsize>::read_uleb128(uleb, pos, data, max);
	cout<<" "<<dec<<uleb;
}

template <int ptrsize>
void eh_program_insn_t<ptrsize>::print_sleb_operand(
	uint64_t pos,
	const uint8_t* const data, 
	const uint64_t max)
{
	auto leb=int64_t(0xdeadbeef);
	eh_frame_util_t<ptrsize>::read_sleb128(leb, pos, data, max);
	cout<<" "<<dec<<leb;
}

template <int ptrsize>
bool eh_program_insn_t<ptrsize>::parse_insn(
	uint8_t opcode, 
	uint64_t &pos,
	const uint8_t* const data, 
	const uint64_t &max)
{
	auto &eh_insn = *this;
	auto insn_start=pos-1;
	auto opcode_upper2=(uint8_t)(opcode >> 6);
	auto opcode_lower6=(uint8_t)(opcode & (0x3f));

	// calculate the end of the instruction, which is inherently per-opcode
	switch(opcode_upper2)
	{
		case 1:
		{
			// case DW_CFA_advance_loc:
			break;
		}
		case 2:
		{
			auto uleb=uint64_t(0);
			if(eh_frame_util_t<ptrsize>::read_uleb128(uleb, pos, data, max))
				return true;
			// case DW_CFA_offset:
			break;
		}
		case 3:
		{
			// case DW_CFA_offset:
			break;
		}
		case 0:
		{
			switch(opcode_lower6)
			{
			
				case DW_CFA_nop:
				case DW_CFA_remember_state:
				case DW_CFA_restore_state:
					break;

				// takes single uleb128
				case DW_CFA_undefined:
				case DW_CFA_same_value:
				case DW_CFA_restore_extended:
				case DW_CFA_def_cfa_register:
				case DW_CFA_GNU_args_size:
				case DW_CFA_def_cfa_offset:
				{
					auto uleb=uint64_t(0);
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb, pos, data, max))
						return true;
					break;
				}

				case DW_CFA_set_loc:
					pos+=ptrsize;
					if(pos>max)
						return true;
					break;

				case DW_CFA_advance_loc1:
					pos+=1;
					if(pos>max)
						return true;
					break;

				case DW_CFA_advance_loc2:
					pos+=2;
					if(pos>max)
						return true;
					break;

				case DW_CFA_advance_loc4:
					pos+=4;
					if(pos>max)
						return true;
					break;

				case DW_CFA_offset_extended:
				case DW_CFA_register:
				case DW_CFA_def_cfa:
				{
					auto uleb1=uint64_t(1);
					auto uleb2=uint64_t(0);
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb1, pos, data, max))
						return true;
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb2, pos, data, max))
						return true;
					break;
				}
				case DW_CFA_def_cfa_sf:
				{
					auto leb1=uint64_t(0);
					auto leb2=int64_t(0);
					if(eh_frame_util_t<ptrsize>::read_uleb128(leb1, pos, data, max))
						return true;
					if(eh_frame_util_t<ptrsize>::read_sleb128(leb2, pos, data, max))
						return true;
					break;
				}

				case DW_CFA_def_cfa_expression:
				{
					auto uleb=uint64_t(0);
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb, pos, data, max))
						return true;
					pos+=uleb;
					if(pos>max)
						return true;
					if(pos>max)
						return true;
					break;
				}
				case DW_CFA_expression:
				case DW_CFA_val_expression:
				{
					auto uleb1=uint64_t(0);
					auto uleb2=uint64_t(0);
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb1, pos, data, max))
						return true;
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb2, pos, data, max))
						return true;
					pos+=uleb2;
					if(pos>max)
						return true;
					break;
				}
				case DW_CFA_def_cfa_offset_sf:
				{
					auto leb=int64_t(0);
					if(eh_frame_util_t<ptrsize>::read_sleb128(leb, pos, data, max))
						return true;
					break;
				}
				case DW_CFA_offset_extended_sf:
				{
					auto uleb1=uint64_t(0);
					auto sleb2=int64_t(0);
					if(eh_frame_util_t<ptrsize>::read_uleb128(uleb1, pos, data, max))
						return true;
					if(eh_frame_util_t<ptrsize>::read_sleb128(sleb2, pos, data, max))
						return true;
					break;
				}
				/* Dwarf 2.1 */
				case DW_CFA_val_offset:
				case DW_CFA_val_offset_sf:


				/* SGI/MIPS specific */
				case DW_CFA_MIPS_advance_loc8:

				/* GNU extensions */
				case DW_CFA_GNU_window_save:
				case DW_CFA_GNU_negative_offset_extended:
				default:
					// Unhandled opcode cannot xform this eh-frame
					cout<<"No decoder for opcode "<<+opcode<<endl;
					return true;
			}
			break;
		}
		default:
			cout<<"No decoder for opcode "<<+opcode<<endl;
			return true;
	}

	// insert bytes into the instruction.
	auto insn_end=pos;
	for_each( &data[insn_start], &data[insn_end], [&](const uint8_t c)
	{
		eh_insn.push_byte(c);
	});
	return false;
}

template <int ptrsize>
bool eh_program_insn_t<ptrsize>::isNop() const 
{
	const auto opcode=program_bytes[0];
	const auto opcode_upper2=(uint8_t)(opcode >> 6);
	const auto opcode_lower6=(uint8_t)(opcode & (0x3f));
	return opcode_upper2==0 && opcode_lower6==DW_CFA_nop;
}

template <int ptrsize>
bool eh_program_insn_t<ptrsize>::isDefCFAOffset() const 
{
	const auto opcode=program_bytes[0];
	const auto opcode_upper2=(uint8_t)(opcode >> 6);
	const auto opcode_lower6=(uint8_t)(opcode & (0x3f));

	return opcode_upper2==0 && opcode_lower6==DW_CFA_def_cfa_offset;
}


template <int ptrsize>
bool eh_program_insn_t<ptrsize>::isRestoreState() const 
{
	const auto opcode=program_bytes[0];
	const auto opcode_upper2=(uint8_t)(opcode >> 6);
	const auto opcode_lower6=(uint8_t)(opcode & (0x3f));
	switch(opcode_upper2)
	{
		case 0:
		{
			switch(opcode_lower6)
			{
				case DW_CFA_restore_state:
					return true;	
			}
		}
	}
	return false;
}

template <int ptrsize>
bool eh_program_insn_t<ptrsize>::isRememberState() const 
{
	const auto opcode=program_bytes[0];
	const auto opcode_upper2=(uint8_t)(opcode >> 6);
	const auto opcode_lower6=(uint8_t)(opcode & (0x3f));
	switch(opcode_upper2)
	{
		case 0:
		{
			switch(opcode_lower6)
			{
				case DW_CFA_remember_state:
					return true;	
			}
		}
	}
	return false;
}

template <int ptrsize>
bool eh_program_insn_t<ptrsize>::advance(uint64_t &cur_addr, uint64_t CAF) const 
{ 
	// make sure uint8_t is an unsigned char.	
	static_assert(is_same<unsigned char, uint8_t>::value, "uint8_t is not unsigned char");

	auto &data=program_bytes;
	auto opcode=program_bytes[0];
	auto opcode_upper2=(uint8_t)(opcode >> 6);
	auto opcode_lower6=(uint8_t)(opcode & (0x3f));
	auto pos=uint64_t(1);
	//auto max=program_bytes.size();

	switch(opcode_upper2)
	{
		case 1:
		{
			// case DW_CFA_advance_loc:
			cur_addr+=(opcode_lower6*CAF);
			return true;
		}
		case 0:
		{
			switch(opcode_lower6)
			{
				case DW_CFA_set_loc:
				{
					throw_assert(0);
					return true;
				}
				case DW_CFA_advance_loc1:
				{
					auto loc=*(uint8_t*)(&data.data()[pos]);
					cur_addr+=(loc*CAF);
					return true;
				}

				case DW_CFA_advance_loc2:
				{
					auto loc=*(uint16_t*)(&data.data()[pos]);
					cur_addr+=(loc*CAF);
					return true;
				}

				case DW_CFA_advance_loc4:
				{
					auto loc=*(uint32_t*)(&data.data()[pos]);
					cur_addr+=(loc*CAF);
					return true;
				}
			}
		}
	}
	return false;
}

template <int ptrsize>
const vector<uint8_t>& eh_program_insn_t<ptrsize>::getBytes() const { return program_bytes; }

template <int ptrsize>
vector<uint8_t>& eh_program_insn_t<ptrsize>::getBytes() { return program_bytes; }






template <int ptrsize>
bool operator<(const eh_program_insn_t<ptrsize>& a, const eh_program_insn_t<ptrsize>& b)
{
	return a.getBytes() < b.getBytes(); 
}

template <int ptrsize>
void eh_program_t<ptrsize>::push_insn(const eh_program_insn_t<ptrsize> &i) { instructions.push_back(i); }

template <int ptrsize>
void eh_program_t<ptrsize>::print(const uint64_t start_addr, const int64_t caf) const
{
	auto pc=start_addr;
	cout << "			Program:                  " << endl ;
	for (const auto &i : instructions) 
	{ 
		i.print(pc,caf);
	}
}

template <int ptrsize>
bool eh_program_t<ptrsize>::parse_program(
	const uint64_t& program_start_position,
	const uint8_t* const data, 
	const uint64_t &max_program_pos)
{
	eh_program_t &eh_pgm=*this;
	auto max=max_program_pos;
	auto pos=program_start_position;
	while(pos < max_program_pos)
	{
		auto opcode=uint8_t(0);
		if(eh_frame_util_t<ptrsize>::read_type(opcode,pos,data,max))
			return true;
		eh_program_insn_t<ptrsize> eh_insn;
		if(eh_insn.parse_insn(opcode,pos,data,max))
			return true;

		eh_pgm.push_insn(eh_insn);

	
	}

	return false;
}

template <int ptrsize>
const vector<eh_program_insn_t <ptrsize> >& eh_program_t<ptrsize>::getInstructionsInternal() const { return instructions; }

template <int ptrsize>
vector<eh_program_insn_t <ptrsize> >& eh_program_t<ptrsize>::getInstructionsInternal() { return instructions; }

template <int ptrsize>
bool operator<(const eh_program_t<ptrsize>& a, const eh_program_t<ptrsize>& b)
{
	return a.getInstructionsInternal() < b.getInstructionsInternal(); 
}

template <int ptrsize>
cie_contents_t<ptrsize>::cie_contents_t() :
	cie_position(0),
	length(0),
	cie_id(0),
	cie_version(0),
	code_alignment_factor(0),
	data_alignment_factor(0),
	return_address_register_column(0),
	augmentation_data_length(0),
	personality_encoding(0),
	personality(0),
	lsda_encoding(0),
	fde_encoding(0)
{}


template <int ptrsize>
const eh_program_t<ptrsize>& cie_contents_t<ptrsize>::getProgram() const { return eh_pgm; }

template <int ptrsize>
uint64_t cie_contents_t<ptrsize>::getCAF() const { return code_alignment_factor; }

template <int ptrsize>
int64_t cie_contents_t<ptrsize>::getDAF() const { return data_alignment_factor; }

template <int ptrsize>
uint64_t cie_contents_t<ptrsize>::getPersonality() const { return personality; }

template <int ptrsize>
uint64_t cie_contents_t<ptrsize>::getReturnRegister() const { return return_address_register_column; }


template <int ptrsize>
string cie_contents_t<ptrsize>::getAugmentation() const { return augmentation; }

template <int ptrsize>
uint8_t cie_contents_t<ptrsize>::getLSDAEncoding() const { return lsda_encoding;}

template <int ptrsize>
uint8_t cie_contents_t<ptrsize>::getFDEEncoding() const { return fde_encoding;}


template <int ptrsize>
bool cie_contents_t<ptrsize>::parse_cie(
	const uint64_t &cie_position,
	const uint8_t* const data, 
	const uint64_t max,
	const uint64_t eh_addr)
{
	auto &c=*this;
	const auto eh_frame_scoop_data= data;
	auto position=cie_position;
	auto length= uint64_t(0);

	if(this->read_length(length, position, eh_frame_scoop_data, max))
		return true;

	auto end_pos=position+length;

	auto cie_id=uint32_t(0);
	if(this->read_type(cie_id, position, eh_frame_scoop_data, max))
		return true;

	auto cie_version=uint8_t(0);
	if(this->read_type(cie_version, position, eh_frame_scoop_data, max))
		return true;

	if(cie_version==1) 
	{ } // OK
	else if(cie_version==3) 
	{ } // OK
	else
	    // Err.
		return true;	

	auto augmentation=string();
	if(this->read_string(augmentation, position, eh_frame_scoop_data, max))
		return true;

	auto code_alignment_factor=uint64_t(0);
	if(this->read_uleb128(code_alignment_factor, position, eh_frame_scoop_data, max))
		return true;
	
	auto data_alignment_factor=int64_t(0);
	if(this->read_sleb128(data_alignment_factor, position, eh_frame_scoop_data, max))
		return true;

	// type depends on version info.  can always promote to 64 bits.
	auto return_address_register_column=uint64_t(0);
	if(cie_version==1)
	{
		auto return_address_register_column_8=uint8_t(0);
		if(this->read_type(return_address_register_column_8, position, eh_frame_scoop_data, max))
			return true;
		return_address_register_column=return_address_register_column_8;
	}
	else if(cie_version==3)
	{
		auto return_address_register_column_64=uint64_t(0);
		if(this->read_uleb128(return_address_register_column_64, position, eh_frame_scoop_data, max))
			return true;
		return_address_register_column=return_address_register_column_64;
	}
	else
		throw_assert(0);

	auto augmentation_data_length=uint64_t(0);
	if(augmentation.find("z") != string::npos)
	{
		if(this->read_uleb128(augmentation_data_length, position, eh_frame_scoop_data, max))
			return true;
	}
	auto personality_encoding=uint8_t(DW_EH_PE_omit);
	auto personality=uint64_t(0);
	auto personality_pointer_position=uint64_t(0);
	auto personality_pointer_size=uint64_t(0);
	if(augmentation.find("P") != string::npos)
	{
		if(this->read_type(personality_encoding, position, eh_frame_scoop_data, max))
			return true;
		personality_pointer_position=position;

		// indirect is OK as a personality encoding, but we don't need to go that far.
		// we just need to record what's in the CIE, regardless of whether it's the actual
		// personality routine or it's the pointer to the personality routine.
		auto personality_encoding_sans_indirect = personality_encoding&(~DW_EH_PE_indirect);
		if(this->read_type_with_encoding(personality_encoding_sans_indirect, personality, position, eh_frame_scoop_data, max, eh_addr))
			return true;
		personality_pointer_size=position - personality_pointer_position;
	}

	auto lsda_encoding=uint8_t(DW_EH_PE_omit);
	if(augmentation.find("L") != string::npos)
	{
		if(this->read_type(lsda_encoding, position, eh_frame_scoop_data, max))
			return true;
	}
	auto fde_encoding=uint8_t(DW_EH_PE_omit);
	if(augmentation.find("R") != string::npos)
	{
		if(this->read_type(fde_encoding, position, eh_frame_scoop_data, max))
			return true;
	}
	if(eh_pgm.parse_program(position, eh_frame_scoop_data, end_pos))
		return true;


	c.cie_position=cie_position +eh_addr;
	c.length=length;
	c.cie_id=cie_id;
	c.cie_version=cie_version;
	c.augmentation=augmentation;
	c.code_alignment_factor=code_alignment_factor;
	c.data_alignment_factor=data_alignment_factor;
	c.return_address_register_column=return_address_register_column;
	c.augmentation_data_length=augmentation_data_length;
	c.personality_encoding=personality_encoding;
	c.personality=personality;
	c.personality_pointer_position=personality_pointer_position + eh_addr;
	c.personality_pointer_size=personality_pointer_size;
	c.lsda_encoding=lsda_encoding;
	c.fde_encoding=fde_encoding;

	// all OK
	return false;
}

template <int ptrsize>
void cie_contents_t<ptrsize>::print(const uint64_t startAddr) const 
{
	cout << "["<<setw(6)<<hex<<cie_position<<"] CIE length="<<dec<<length<<endl;
	cout << "   CIE_id:                   " << +cie_id << endl;
	cout << "   version:                  " << +cie_version << endl;
	cout << "   augmentation:             \"" << augmentation << "\"" << endl;
	cout << "   code_alignment_factor:    " << code_alignment_factor << endl;
	cout << "   data_alignment_factor:    " << dec << data_alignment_factor << endl;
	cout << "   return_address_register:  " << dec << return_address_register_column << endl;
	cout << "   Augmentation data:        " << endl ;
	cout << "                             aug data len:         " << hex << +augmentation_data_length << endl;
	cout << "                             personality_encoding: " << hex << +personality_encoding << endl;
	cout << "                             personality:          " << hex << +personality << endl;
	cout << "                             lsda_encoding:        " << hex << +lsda_encoding << endl;
	cout << "                             fde_encoding:         " << hex << +fde_encoding << endl;
	cout << "   Program:        " << endl ;
	eh_pgm.print(startAddr,getCAF());
	
}


template <int ptrsize>
lsda_call_site_action_t<ptrsize>::lsda_call_site_action_t() :
	action(0)
{}


template <int ptrsize>
int64_t lsda_call_site_action_t<ptrsize>::getAction() const { return action;}


template <int ptrsize>
bool lsda_call_site_action_t<ptrsize>::parse_lcsa(uint64_t &pos, const uint8_t* const data, const uint64_t max, bool &end)
{
	end=false;
	if(this->read_sleb128(action, pos, data, max))
		return true;

	auto next_action=pos;
	auto next_pos_offset=int64_t(0);
	if(this->read_sleb128(next_pos_offset, pos, data, max))
		return true;

	if(next_pos_offset==0)
		end=true;
	else
		pos=next_action+next_pos_offset;
	return false;
}

template <int ptrsize>
void lsda_call_site_action_t<ptrsize>::print() const
{
	cout<<"					"<<action<<endl;
}

template <int ptrsize>
bool operator< (const lsda_call_site_action_t <ptrsize> &lhs, const lsda_call_site_action_t <ptrsize> &rhs)
{ 	
	return lhs.getAction() < rhs.getAction(); 
}

template <int ptrsize>
lsda_type_table_entry_t<ptrsize>::lsda_type_table_entry_t() : 
	pointer_to_typeinfo(0), tt_encoding(0)
{}


template <int ptrsize>
uint64_t lsda_type_table_entry_t<ptrsize>::getTypeInfoPointer() const { return pointer_to_typeinfo; }

template <int ptrsize>
uint64_t lsda_type_table_entry_t<ptrsize>::getEncoding() const { return tt_encoding; }

template <int ptrsize>
uint64_t lsda_type_table_entry_t<ptrsize>::getTTEncodingSize() const { return tt_encoding_size; }


template <int ptrsize>
bool lsda_type_table_entry_t<ptrsize>::parse(
	const uint64_t p_tt_encoding, 	
	const uint64_t tt_pos,
	const uint64_t index,
	const uint8_t* const data, 
	const uint64_t max,  
	const uint64_t data_addr
	)
{
	tt_encoding=p_tt_encoding;
	const auto tt_encoding_sans_indirect = tt_encoding&(~DW_EH_PE_indirect);
	const auto tt_encoding_sans_indir_sans_pcrel = static_cast<uint8_t>(tt_encoding_sans_indirect & (~DW_EH_PE_pcrel));
	const auto has_pcrel = (tt_encoding & DW_EH_PE_pcrel) == DW_EH_PE_pcrel;
	switch(tt_encoding & 0xf) // get just the size field
	{
		case DW_EH_PE_udata4:
		case DW_EH_PE_sdata4:
			tt_encoding_size=4;
			break;
		case DW_EH_PE_udata8:
		case DW_EH_PE_sdata8:
			tt_encoding_size=8;
			break;
		case DW_EH_PE_absptr:
			tt_encoding_size=ptrsize;
			break;
		default:
			throw_assert(0);
	}
	const auto orig_act_pos=uint64_t(tt_pos+(-static_cast<int64_t>(index)*tt_encoding_size));
	auto act_pos=uint64_t(tt_pos+(-static_cast<int64_t>(index)*tt_encoding_size));
	if(this->read_type_with_encoding(tt_encoding_sans_indir_sans_pcrel, pointer_to_typeinfo, act_pos, data, max, data_addr))
		return true;

	// check if there's a 0 in the field
	if(pointer_to_typeinfo != 0 && has_pcrel)
		pointer_to_typeinfo += orig_act_pos + data_addr;

	return false;
}


template <int ptrsize>
void lsda_type_table_entry_t<ptrsize>::print() const
{
	cout<<"				pointer_to_typeinfo: 0x"<<hex<<pointer_to_typeinfo<<endl;
}




template <int ptrsize>
lsda_call_site_t<ptrsize>::lsda_call_site_t() :
	call_site_offset(0),
	call_site_addr(0),
	call_site_length(0),
	call_site_end_addr(0),
	landing_pad_offset(0),
	landing_pad_addr(0),
	action(0),
	action_table_offset(0),
	action_table_addr(0)
{}

template <int ptrsize>
const LSDACallSiteActionVector_t* lsda_call_site_t<ptrsize>::getActionTable() const       
{ 
	if(action_table_cache.size() == 0)
	{
		transform(ALLOF(action_table), back_inserter(action_table_cache), [](const lsda_call_site_action_t<ptrsize> &a) { return &a;});
	}
	return &action_table_cache;
#if 0
	auto ret=shared_ptr<LSDACallSiteActionVector_t>(new LSDACallSiteActionVector_t());
	transform(ALLOF(action_table), back_inserter(*ret), 
		[](const lsda_call_site_action_t<ptrsize> &a) { return shared_ptr<LSDACallSiteAction_t>(new lsda_call_site_action_t<ptrsize>(a));});
	return shared_ptr<LSDACallSiteActionVector_t>(ret);
#endif
}




template <int ptrsize>
bool lsda_call_site_t<ptrsize>::parse_lcs(	
	const uint64_t action_table_start_addr, 	
	const uint64_t cs_table_start_addr, 	
	const uint8_t cs_table_encoding, 
	uint64_t &pos,
	const uint8_t* const data, 
	const uint64_t cs_max,  /* call site table max */
	const uint64_t data_addr, 
	const uint64_t landing_pad_base_addr,
	const uint64_t gcc_except_table_max)
{
	const auto smallest_max = min(cs_max,gcc_except_table_max);
	call_site_addr_position = pos + data_addr;
	if(this->read_type_with_encoding(cs_table_encoding, call_site_offset, pos, data, smallest_max, data_addr))
		return true;
	call_site_addr=landing_pad_base_addr+call_site_offset;
	call_site_end_addr_position = pos + data_addr;

	if(this->read_type_with_encoding(cs_table_encoding, call_site_length, pos, data, smallest_max, data_addr))
		return true;
	call_site_end_addr=call_site_addr+call_site_length;
	landing_pad_addr_position = pos + data_addr;

	if(this->read_type_with_encoding(cs_table_encoding, landing_pad_offset, pos, data, smallest_max, data_addr))
		return true;
	landing_pad_addr_end_position = pos + data_addr;

	// calc the actual addr.
	if(landing_pad_offset == 0)
		landing_pad_addr=0;
	else
		landing_pad_addr=landing_pad_base_addr+landing_pad_offset;

	if(this->read_uleb128(action, pos, data, smallest_max))
		return true;

	if(action == 0)
	{ /* no action table -- means no cleanup is needed, just unwinding. */ }
	else if( action > 0 )
	{
		action_table_offset=action-1;
		action_table_addr=action_table_start_addr+action-1;

		// parse action tables
		bool end=false;
		auto act_table_pos=uint64_t(action_table_addr-data_addr);
		while(!end)
		{
			lsda_call_site_action_t<ptrsize> lcsa;
			if(lcsa.parse_lcsa(act_table_pos, data, gcc_except_table_max, end))	 /* expect action table after cs_max */
				return true;
			action_table.push_back(lcsa);
			
		}
	}
	else if( action < 0 )
	{
		throw_assert(0); // how can the index into the action table be negative?
	}
	else
	{
		throw_assert(0); // how is this possible?
	}

	return false;
}


template <int ptrsize>
void lsda_call_site_t<ptrsize>::print() const
{
	cout<<"				CS Offset        : 0x"<<hex<<call_site_offset<<endl;
	cout<<"				CS len           : 0x"<<hex<<call_site_length<<endl;
	cout<<"				landing pad off. : 0x"<<hex<<landing_pad_offset<<endl;
	cout<<"				action (1+addr)  : 0x"<<hex<<action<<endl;
	cout<<"				---interpreted---"<<endl;
	cout<<"				CS Addr          : 0x"<<hex<<call_site_addr<<endl;
	cout<<"				CS End Addr      : 0x"<<hex<<call_site_end_addr<<endl;
	cout<<"				landing pad addr : 0x"<<hex<<landing_pad_addr<<endl;
	cout<<"				act-tab off      : 0x"<<hex<<action_table_offset<<endl;
	cout<<"				act-tab addr     : 0x"<<hex<<action_table_addr<<endl;
	cout<<"				act-tab 	 : "<<endl;
	for_each(action_table.begin(), action_table.end(), [&](const lsda_call_site_action_t<ptrsize>& p)
	{
		p.print();
	});
}


template <int ptrsize>
uint8_t lsda_t<ptrsize>::getTTEncoding() const { return type_table_encoding; }

template <int ptrsize>
lsda_t<ptrsize>::lsda_t() :
	landing_pad_base_encoding(0),
	landing_pad_base_addr(0),
	type_table_encoding(0),
	type_table_offset(0),
	type_table_addr(0),
	cs_table_encoding(0),
	cs_table_start_offset(0),
	cs_table_start_addr(0),
	cs_table_length(0),
	cs_table_end_addr(0),
	action_table_start_addr(0)
{}
	
template <int ptrsize>
bool lsda_t<ptrsize>::parse_lsda(
                                 const uint64_t lsda_addr, 
                                 //const DataScoop_t* gcc_except_scoop, 
                                 const ScoopReplacement_t *gcc_except_scoop, 
                                 const uint64_t fde_region_start
                                )
{
	// make sure there's a scoop and that we're in the range.
	if(!gcc_except_scoop)
		return true;
	if(lsda_addr<gcc_except_scoop->getStart())
		return true;
	if(lsda_addr>=gcc_except_scoop->getEnd())
		return true;

	const auto &data=gcc_except_scoop->getContents();
	const auto data_addr=gcc_except_scoop->getStart();
	const auto max=gcc_except_scoop->getContents().size();
	auto pos=uint64_t(lsda_addr-data_addr);
	auto start_pos=pos;

	if(this->read_type(landing_pad_base_encoding, pos, (const uint8_t* const)data.data(), max))
		return true;
	if(landing_pad_base_encoding!=DW_EH_PE_omit)
	{
		if(this->read_type_with_encoding(landing_pad_base_encoding,landing_pad_base_addr, pos, (const uint8_t* const)data.data(), max, data_addr))
			return true;
	}
	else
		landing_pad_base_addr=fde_region_start;

	if(this->read_type(type_table_encoding, pos, (const uint8_t* const)data.data(), max))
		return true;

	auto type_table_pos=uint64_t(0);
	if(type_table_encoding!=DW_EH_PE_omit)
	{
		type_table_addr_location = pos + data_addr;
		if(this->read_uleb128(type_table_offset, pos, (const uint8_t* const)data.data(), max))
			return true;
		type_table_addr=lsda_addr+type_table_offset+(pos-start_pos);
		type_table_pos=pos+type_table_offset;
	}
	else
	{
		type_table_addr=0;
		type_table_addr_location=0;
	}

	if(this->read_type(cs_table_encoding, pos, (const uint8_t* const)data.data(), max))
		return true;

	cs_table_start_addr_location = pos + data_addr;
	if(this->read_uleb128(cs_table_length, pos, (const uint8_t* const)data.data(), max))
		return true;

	auto cs_table_end=pos+cs_table_length;
	//auto cs_table_start_pos=pos;
	cs_table_start_offset=pos;
	cs_table_start_addr=lsda_addr+pos-start_pos;
	cs_table_end_addr=cs_table_start_addr+cs_table_length;

	// action table comes immediately after the call site table.
	action_table_start_addr=cs_table_start_addr+cs_table_length;
	while(1)
	{
		lsda_call_site_t<ptrsize> lcs;
		if(lcs.parse_lcs(action_table_start_addr,
			cs_table_start_addr,cs_table_encoding, pos, (const uint8_t* const)data.data(), cs_table_end, data_addr, landing_pad_base_addr, max))
		{
			return true;
		}

		call_site_table.push_back(lcs);
		
		if(pos>=cs_table_end)
			break;	
	}

	if(type_table_encoding!=DW_EH_PE_omit)
	{
		for(const auto cs_tab_entry : call_site_table)
		{
			for(const auto act_tab_entry : cs_tab_entry.getActionTableInternal())
			{
				const auto type_filter=act_tab_entry.getAction();
				const auto parse_and_insert_tt_entry = [&] (const uint64_t index) -> bool
				{
					// cout<<"Parsing TypeTable at -"<<index<<endl;
					// 1-based indexing because of odd backwards indexing of type table.
					lsda_type_table_entry_t <ptrsize> ltte;
					if(ltte.parse(type_table_encoding, type_table_pos, index, (const uint8_t* const)data.data(), max, data_addr ))
						return true;
					type_table.resize(std::max((size_t)index,(size_t)type_table.size()));
					type_table.at(index-1)=ltte;
					return false;
				};
		
				if(type_filter==0)
				{	
					// type-filter==0 means no TT entry in the action table.
				}
				else if(type_filter>0)
				{
					// type_filter > 0 indicates singleton type table entry
					if(parse_and_insert_tt_entry(type_filter))
						return true;
				}
				else if(type_filter<0)
				{
					// a type filter < 0 indicates a dynamic exception specification (DES) is in play.
					// a DES is where the runtime enforces whether exceptions can be thrown or not, 
					// and if an unexpected exception is thrown, a separate handler is invoked.
					// these are not common and even less likely to be needed for correct execution.
					// we ignore for now.  A warning is printed if they are found in build_ir. 
				}
				else 
					throw_assert(0);

			};
		
		};

	}

	return false;
}

template <int ptrsize>
void lsda_t<ptrsize>::print() const
{
	cout<<"		LSDA:"<<endl;
	cout<<"			LP base encoding   : 0x"<<hex<<+landing_pad_base_encoding<<endl;
	cout<<"			LP base addr	   : 0x"<<hex<<+landing_pad_base_addr<<endl;
	cout<<"			TypeTable encoding : 0x"<<hex<<+type_table_encoding<<endl;
	cout<<"			TypeTable offset   : 0x"<<hex<<type_table_offset<<endl;
	cout<<"			TypeTable addr     : 0x"<<hex<<+type_table_addr<<endl;
	cout<<"			CS tab encoding    : 0x"<<hex<<+cs_table_encoding<<endl;
	cout<<"			CS tab addr        : 0x"<<hex<<+cs_table_start_addr<<endl;
	cout<<"			CS tab offset      : 0x"<<hex<<+cs_table_start_offset<<endl;
	cout<<"			CS tab length      : 0x"<<hex<<+cs_table_length<<endl;
	cout<<"			CS tab end addr    : 0x"<<hex<<+cs_table_end_addr<<endl;
	cout<<"			Act tab start_addr : 0x"<<hex<<+action_table_start_addr<<endl;
	cout<<"			CS tab :"<<endl;
	int i=0;
	for_each(call_site_table.begin(), call_site_table.end(), [&](const lsda_call_site_t<ptrsize>& p)
	{
		cout<<"			[ "<<hex<<i++<<"] call site table entry "<<endl;
		p.print();
	});
	i=0;
	for_each(type_table.begin(), type_table.end(), [&](const lsda_type_table_entry_t<ptrsize>& p)
	{
		cout<<"			[ -"<<dec<<++i<<"] Type table entry "<<endl;
		p.print();
	});
}

template <int ptrsize>
fde_contents_t<ptrsize>::fde_contents_t() :
	fde_position(0),
	cie_position(0),
	length(0),
	id(0),
	fde_start_addr(0),
	fde_end_addr(0),
	fde_range_len(0),
	lsda_addr(0)
{}


template <int ptrsize>
const cie_contents_t<ptrsize>& fde_contents_t<ptrsize>::getCIE() const { return cie_info; }

template <int ptrsize>
cie_contents_t<ptrsize>& fde_contents_t<ptrsize>::getCIE() { return cie_info; }

template <int ptrsize>
const eh_program_t<ptrsize>& fde_contents_t<ptrsize>::getProgram() const { return eh_pgm; }

template <int ptrsize>
eh_program_t<ptrsize>& fde_contents_t<ptrsize>::getProgram() { return eh_pgm; }

template <int ptrsize>
bool fde_contents_t<ptrsize>::parse_fde(
	const uint64_t &fde_position,
	const uint64_t &cie_position,
	const uint8_t* const data, 
	const uint64_t max,
	const uint64_t eh_addr,
	const ScoopReplacement_t* gcc_except_scoop)
//	const DataScoop_t* gcc_except_scoop)
{
	auto &c=*this;
	const auto eh_frame_scoop_data=data;

	if(cie_info.parse_cie(cie_position, data, max, eh_addr))
		return true;

	auto pos=fde_position;
	auto length=uint64_t(0);
	if(this->read_length(length, pos, eh_frame_scoop_data, max))
		return true;


	auto end_pos=pos+length;
	//auto end_length_position=pos;

	auto cie_id=uint32_t(0);
	if(this->read_type(cie_id, pos, eh_frame_scoop_data, max))
		return true;

	auto fde_start_addr=uint64_t(0);
	auto fde_start_addr_position = pos;
	if(this->read_type_with_encoding(c.getCIE().getFDEEncoding(),fde_start_addr, pos, eh_frame_scoop_data, max, eh_addr))
		return true;

	auto fde_range_len=uint64_t(0);
	auto fde_end_addr_position = pos;
	if(this->read_type_with_encoding(c.getCIE().getFDEEncoding() & 0xf /* drop pc-rel bits */,fde_range_len, pos, eh_frame_scoop_data, max, eh_addr))
		return true;

	auto fde_end_addr=fde_start_addr+fde_range_len;
	auto fde_end_addr_size = pos - fde_end_addr_position;
	auto augmentation_data_length=uint64_t(0);
	if(c.getCIE().getAugmentation().find("z") != string::npos)
	{
		if(this->read_uleb128(augmentation_data_length, pos, eh_frame_scoop_data, max))
			return true;
	}
	auto lsda_addr=uint64_t(0);
	auto fde_lsda_addr_position = pos;
	auto fde_lsda_addr_size = uint64_t(0);
	if(c.getCIE().getLSDAEncoding()!= DW_EH_PE_omit)
	{
		if(this->read_type_with_encoding(c.getCIE().getLSDAEncoding(), lsda_addr, pos, eh_frame_scoop_data, max, eh_addr))
			return true;
		fde_lsda_addr_size = pos - fde_lsda_addr_position;
		if(lsda_addr!=0)
			if(c.lsda.parse_lsda(lsda_addr,gcc_except_scoop, fde_start_addr))
				return true;
	}

	if(c.eh_pgm.parse_program(pos, eh_frame_scoop_data, end_pos))
		return true;

	c.fde_position = fde_position + eh_addr;
	c.cie_position=cie_position;
	c.length=length;
	c.id=id;
	c.fde_start_addr=fde_start_addr;
	c.fde_end_addr=fde_end_addr;
	c.fde_range_len=fde_range_len;
	c.lsda_addr=lsda_addr;
	c.fde_start_addr_position = fde_start_addr_position + eh_addr;
	c.fde_end_addr_position = fde_end_addr_position + eh_addr;
	c.fde_lsda_addr_position = fde_lsda_addr_position + eh_addr;
	c.fde_end_addr_size = fde_end_addr_size;
	c.fde_lsda_addr_size = fde_lsda_addr_size;

	return false;
}

template <int ptrsize>
void fde_contents_t<ptrsize>::print() const
{
	const auto caf=cie_info.getCAF();

	cout << "["<<setw(6)<<hex<<fde_position<<"] FDE length="<<dec<<length;
	cout <<" cie=["<<setw(6)<<hex<<cie_position<<"]"<<endl;
	cout<<"		FDE len addr:		"<<dec<<length<<endl;
	cout<<"		FDE Start addr:		"<<hex<<fde_start_addr<<endl;
	cout<<"		FDE End addr:		"<<hex<<fde_end_addr<<endl;
	cout<<"		FDE len:		"<<dec<<fde_range_len<<endl;
	cout<<"		FDE LSDA:		"<<hex<<lsda_addr<<endl;
	eh_pgm.print(fde_start_addr, caf);
	if(getCIE().getLSDAEncoding()!= DW_EH_PE_omit && lsda_addr!=0 /* indicator of nullptr for lsda */)
		lsda.print();
	else
		cout<<"		No LSDA for this FDE."<<endl;
}






template <int ptrsize>
bool split_eh_frame_impl_t<ptrsize>::iterate_fdes()
{
	auto eh_frame_scoop_str=eh_frame_scoop->getContents();
	auto eh_frame_scoop_data=(const uint8_t* const)eh_frame_scoop_str.c_str();
	auto data=eh_frame_scoop_data;
	auto eh_addr= eh_frame_scoop->getStart();
	auto max=eh_frame_scoop->getContents().size();
	auto position=uint64_t(0);

	//cout << "----------------------------------------"<<endl;
	while(1)
	{
		auto old_position=position;
		auto act_length=uint64_t(0);

		if(eh_frame_util_t<ptrsize>::read_length(act_length, position, eh_frame_scoop_data, max))
			break;

		// length field has to be meaningful, 0 or -1 indicates end of segment
		// the exact end-of-segment marker varies platform to platform.
		if(act_length==0 || act_length==0xffffffff || act_length == decltype(act_length)(-1))
			break;

		auto next_position=position + act_length;
		auto cie_offset=uint32_t(0);
		auto cie_offset_position=position;

		if(eh_frame_util_t<ptrsize>::read_type(cie_offset,position, eh_frame_scoop_data, max))
			break;

		//cout << " [ " << setw(6) << hex << old_position << "] " ;
		if(act_length==0)
		{
			//cout << "Zero terminator " << endl;
			break;
		}
		else if(cie_offset==0)
		{
			//cout << "CIE length="<< dec << act_length << endl;
			cie_contents_t<ptrsize> c;
			if(c.parse_cie(old_position, data, max, eh_addr))
				return true;
			cies.push_back(c);
		}
		else
		{
			fde_contents_t<ptrsize> f;
			auto cie_position = cie_offset_position - cie_offset;
			//cout << "FDE length="<< dec << act_length << " cie=[" << setw(6) << hex << cie_position << "]" << endl;
			if(f.parse_fde(old_position, cie_position, data, max, eh_addr, gcc_except_table_scoop.get()))
				return true;
			//const auto old_fde_size=fdes.size();
			fdes.insert(f);
		}
		//cout << "----------------------------------------"<<endl;
		

		// next CIE/FDE
		throw_assert(position<=next_position); 	// so we don't accidentally over-read a CIE/FDE
		position=next_position;
	}
	return false;
}


template <int ptrsize>
bool split_eh_frame_impl_t<ptrsize>::parse()
{
	if(eh_frame_scoop==NULL)
		return true; // no frame info in this binary


	if(iterate_fdes())
		return true;

	return false;
}


template <int ptrsize>
void split_eh_frame_impl_t<ptrsize>::print() const
{
	for_each(cies.begin(), cies.end(), [&](const cie_contents_t<ptrsize>  &p)
	{
		p.print(0 /* cie has no start address on its own */);
	});
	for_each(fdes.begin(), fdes.end(), [&](const fde_contents_t<ptrsize>  &p)
	{
		p.print();
	});
}


template <int ptrsize>
const EHProgramInstructionVector_t* eh_program_t<ptrsize>::getInstructions() const 
{
	if(instructions_cache.size()==0)
	{
		transform(ALLOF(instructions), back_inserter(instructions_cache), [](const eh_program_insn_t<ptrsize> &a) { return &a;});
	}
	return &instructions_cache;
#if 0
	auto ret=shared_ptr<EHProgramInstructionVector_t>(new EHProgramInstructionVector_t());
	transform(ALLOF(getInstructionsInternal()), back_inserter(*ret), 
		[](const eh_program_insn_t<ptrsize> &a) { return shared_ptr<EHProgramInstruction_t>(new eh_program_insn_t<ptrsize>(a));});
	return shared_ptr<EHProgramInstructionVector_t>(ret);
#endif
	
}

template <int ptrsize>
const TypeTableVector_t* lsda_t<ptrsize>::getTypeTable() const 
{
	if(type_table_cache.size()==0)
	{
		transform(ALLOF(type_table), back_inserter(type_table_cache), [](const lsda_type_table_entry_t<ptrsize> &a) { return &a; });
	}
	return &type_table_cache;
#if 0
	auto ret=shared_ptr<TypeTableVector_t>(new TypeTableVector_t());
	transform(ALLOF(type_table), back_inserter(*ret), 
		[](const lsda_type_table_entry_t<ptrsize> &a) { return shared_ptr<LSDATypeTableEntry_t>(new lsda_type_table_entry_t<ptrsize>(a));});
	return shared_ptr<TypeTableVector_t>(ret);
#endif
}


template <int ptrsize>
const CallSiteVector_t* lsda_t<ptrsize>::getCallSites() const 
{
	if(call_site_table_cache.size()==0)
	{
		transform(ALLOF(call_site_table), back_inserter(call_site_table_cache), [](const lsda_call_site_t<ptrsize> &a) { return &a;});
	}
	return &call_site_table_cache;
#if 0
	auto ret=shared_ptr<CallSiteVector_t>(new CallSiteVector_t());
	transform(ALLOF(call_site_table), back_inserter(*ret), 
		[](const lsda_call_site_t<ptrsize> &a) { return shared_ptr<LSDACallSite_t>(new lsda_call_site_t<ptrsize>(a));});
	return shared_ptr<CallSiteVector_t>(ret);
#endif
}


template <int ptrsize>
const FDEVector_t*  split_eh_frame_impl_t<ptrsize>::getFDEs() const
{
	if(fdes_cache.size()==0)
	{
		transform(ALLOF(fdes), back_inserter(fdes_cache), [](const fde_contents_t<ptrsize> &a) { return &a; });
	}
	return &fdes_cache;
#if 0
	auto ret=shared_ptr<FDEVector_t>(new FDEVector_t());
	transform(ALLOF(fdes), back_inserter(*ret), 
		[](const fde_contents_t<ptrsize> &a) { return shared_ptr<FDEContents_t>(new fde_contents_t<ptrsize>(a));});
	return shared_ptr<FDEVector_t>(ret);
#endif
}

template <int ptrsize>
const CIEVector_t*  split_eh_frame_impl_t<ptrsize>::getCIEs() const
{
	if(cies_cache.size()==0)
	{
		transform(ALLOF(cies), back_inserter(cies_cache), [](const cie_contents_t<ptrsize> &a) { return &a; });
	}
	return &cies_cache;
#if 0
	auto ret=shared_ptr<CIEVector_t>(new CIEVector_t());
	transform(ALLOF(cies), back_inserter(*ret), 
		[](const cie_contents_t<ptrsize> &a){ return shared_ptr<CIEContents_t>(new cie_contents_t<ptrsize>(a));});
	return ret;
#endif
}

template <int ptrsize>
const FDEContents_t* split_eh_frame_impl_t<ptrsize>::findFDE(uint64_t addr) const
{

        const auto tofind=fde_contents_t<ptrsize>( addr, addr+1);
        const auto fde_it=fdes.find(tofind);
	const auto raw_ret_ptr = (fde_it==fdes.end()) ?  nullptr : &*fde_it;
	return raw_ret_ptr;
}

#if USE_ELFIO
unique_ptr<const EHFrameParser_t> EHFrameParser_t::factory(const string filename)
{
	auto elfiop=unique_ptr<elfio>(new elfio);
	if(!elfiop->load(filename))
	{
		throw invalid_argument(string() + "Cannot open file: " + filename);
	}

	auto get_info=[&](const string name) -> pair<string,uint64_t>
		{
			const auto &sec=elfiop->sections[name.c_str()];
			if(sec==nullptr)
				return {"",0};

			auto contents=string(sec->get_data(), sec->get_size());
			auto addr=sec->get_address();
			return {contents,addr};	

		};

	const auto eh_frame_section=get_info(".eh_frame");
	const auto eh_frame_hdr_section=get_info(".eh_frame_hdr");
	const auto gcc_except_table_section=get_info(".gcc_except_table");

	const auto ptrsize = elfiop->get_class()==ELFCLASS64 ? 8 :
	                     elfiop->get_class()==ELFCLASS32 ? 4 : 
	                     0; 
	if(ptrsize==0)
		throw invalid_argument(string() + "Invalid ELF class in : " + filename);

	return EHFrameParser_t::factory(ptrsize,
			eh_frame_section.first, eh_frame_section.second,
			eh_frame_hdr_section.first, eh_frame_hdr_section.second,
			gcc_except_table_section.first, gcc_except_table_section.second);

}
#endif

unique_ptr<const EHFrameParser_t> EHFrameParser_t::factory(
	uint8_t ptrsize,
	const string eh_frame_data, const uint64_t eh_frame_data_start_addr,
	const string eh_frame_hdr_data, const uint64_t eh_frame_hdr_data_start_addr,
	const string gcc_except_table_data, const uint64_t gcc_except_table_data_start_addr
	)
{
	const auto eh_frame_sr=ScoopReplacement_t(eh_frame_data,eh_frame_data_start_addr);
	const auto eh_frame_hdr_sr=ScoopReplacement_t(eh_frame_hdr_data,eh_frame_hdr_data_start_addr);
	const auto gcc_except_table_sr=ScoopReplacement_t(gcc_except_table_data,gcc_except_table_data_start_addr);
	auto ret_val=(EHFrameParser_t*)nullptr;
	if(ptrsize==4)
		ret_val=new split_eh_frame_impl_t<4>(eh_frame_sr,eh_frame_hdr_sr,gcc_except_table_sr);
	else if(ptrsize==8)
		ret_val=new split_eh_frame_impl_t<8>(eh_frame_sr,eh_frame_hdr_sr,gcc_except_table_sr);
	else
		throw out_of_range("ptrsize must be 4 or 8");

	ret_val->parse();

	return unique_ptr<const EHFrameParser_t>(ret_val);
}

	



