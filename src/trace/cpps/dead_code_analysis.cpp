#include <iostream>
#include "../headers/dead_code_analysis.h"
#include<unordered_map>
#include<string>
#include <vector>
#include<utility>
#include <algorithm>
#include<bitset>
extern "C" {
#include "xed-interface.h"
}
using namespace std;


analysis_tool_t *
dead_code_analysis_create()
{
    return new dead_code_analysis_t();
}

dead_code_analysis_t::dead_code_analysis_t()
{
}

dead_code_analysis_t::~dead_code_analysis_t()
{
}

void dead_code_analysis_t::addDeadCode(int index,const memref_t obj,int reg = -1) {
    deadCode dead_code = deadCode(); // 死指令初始化
    dead_code.index = index;
    dead_code.obj = obj;
    dead_code.reg = reg;
    sorted_deadCode.push_back(dead_code);
}

void dead_code_analysis_t::initAddrReadWrite_thread(memref_t memref){
    // 1.构造tid-addr的pair
    std::pair<memref_tid_t,addr_t> pair_tid_addr(memref.data.tid, memref.data.addr);
    // 2.初始化构建map的key
    addr_read_write[pair_tid_addr] = new read_write();
    if (memref.data.type == TRACE_TYPE_READ) {
        addr_read_write[pair_tid_addr]->read = true;
    } else if (memref.data.type == TRACE_TYPE_WRITE) {
        addr_read_write[pair_tid_addr]->write = true;
        addr_read_write[pair_tid_addr]->index_write = number.allCodeNumber;
    }
    // 3.记录本次操作的类型
    addr_read_write[pair_tid_addr]->obj = memref; // read
}


void print_operands(xed_decoded_inst_t* xedd) {
    unsigned int i, noperands;
#define TBUFSZ 90
    char tbuf[TBUFSZ];
    const xed_inst_t* xi = xed_decoded_inst_inst(xedd);
    xed_operand_action_enum_t rw;
    xed_uint_t bits;

    printf("Operands\n");
    noperands = xed_inst_noperands(xi);
    printf("#   TYPE               DETAILS        VIS  RW       OC2 BITS BYTES NELEM ELEMSZ   ELEMTYPE   REGCLASS\n");
    printf("#   ====               =======        ===  ==       === ==== ===== ===== ======   ========   ========\n");
    tbuf[0]=0;
    for( i=0; i < noperands ; i++) {
        const xed_operand_t* op = xed_inst_operand(xi,i);
        xed_operand_enum_t op_name = xed_operand_name(op);
        printf("%u %6s ",
               i,xed_operand_enum_t2str(op_name));
        switch(op_name) {
        case XED_OPERAND_AGEN:
        case XED_OPERAND_MEM0:
        case XED_OPERAND_MEM1:
            // we print memops in a different function
            xed_strcpy(tbuf, "(see below)");
            break;
        case XED_OPERAND_PTR:  // pointer (always in conjunction with a IMM0)
        case XED_OPERAND_RELBR: { // branch displacements
            xed_uint_t disp_bits =
                xed_decoded_inst_get_branch_displacement_width(xedd);
            if (disp_bits) {
                xed_int32_t disp =
                    xed_decoded_inst_get_branch_displacement(xedd);
#if defined (_WIN32) && !defined(PIN_CRT)
                _snprintf_s(tbuf, TBUFSZ, TBUFSZ,
                            "BRANCH_DISPLACEMENT_BYTES= %d %08x",
                            disp_bits,disp);
#else
                snprintf(tbuf, TBUFSZ,
                         "BRANCH_DISPLACEMENT_BYTES= %d %08x",
                         disp_bits,disp);
#endif
            }
        }
        break;
        case XED_OPERAND_IMM0: { // immediates
            char buf[64];
            const unsigned int no_leading_zeros=0;
            xed_uint_t ibits;
            const xed_bool_t lowercase = 1;
            ibits = xed_decoded_inst_get_immediate_width_bits(xedd);
            if (xed_decoded_inst_get_immediate_is_signed(xedd)) {
                xed_uint_t rbits = ibits?ibits:8;
                xed_int32_t x = xed_decoded_inst_get_signed_immediate(xedd);
                xed_uint64_t y = XED_STATIC_CAST(xed_uint64_t,
                                                 xed_sign_extend_arbitrary_to_64(
                                                     (xed_uint64_t)x,
                                                     ibits));
                xed_itoa_hex_ul(buf, y, rbits, no_leading_zeros, 64, lowercase);
            }
            else {
                xed_uint64_t x =xed_decoded_inst_get_unsigned_immediate(xedd);
                xed_uint_t rbits = ibits?ibits:16;
                xed_itoa_hex_ul(buf, x, rbits, no_leading_zeros, 64, lowercase);
            }
#if defined (_WIN32) && !defined(PIN_CRT)
            _snprintf_s(tbuf, TBUFSZ, TBUFSZ,
                        "0x%s(%db)",buf,ibits);
#else
            snprintf(tbuf,TBUFSZ,
                     "0x%s(%db)",buf,ibits);
#endif
            break;
        }
        case XED_OPERAND_IMM1: { // 2nd immediate is always 1 byte.
            xed_uint8_t x = xed_decoded_inst_get_second_immediate(xedd);
#if defined (_WIN32) && !defined(PIN_CRT)
            _snprintf_s(tbuf, TBUFSZ, TBUFSZ,
                        "0x%02x",(int)x);
#else
            snprintf(tbuf,TBUFSZ,
                     "0x%02x",(int)x);
#endif
            break;
        }
        case XED_OPERAND_REG0:
        case XED_OPERAND_REG1:
        case XED_OPERAND_REG2:
        case XED_OPERAND_REG3:
        case XED_OPERAND_REG4:
        case XED_OPERAND_REG5:
        case XED_OPERAND_REG6:
        case XED_OPERAND_REG7:
        case XED_OPERAND_REG8:
        case XED_OPERAND_BASE0:
        case XED_OPERAND_BASE1:
        {
            xed_reg_enum_t r = xed_decoded_inst_get_reg(xedd, op_name);
#if defined (_WIN32)  && !defined(PIN_CRT)
            _snprintf_s(tbuf, TBUFSZ, TBUFSZ,
                        "%s=%s",
                        xed_operand_enum_t2str(op_name),
                        xed_reg_enum_t2str(r));
#else
            snprintf(tbuf,TBUFSZ,
                     "%s=%s",
                     xed_operand_enum_t2str(op_name),
                     xed_reg_enum_t2str(r));
#endif
            break;
        }
        default:
            printf("need to add support for printing operand: %s",
                   xed_operand_enum_t2str(op_name));
        }
        printf("%21s", tbuf);

        rw = xed_decoded_inst_operand_action(xedd,i);

        printf(" %10s %3s %9s",
               xed_operand_visibility_enum_t2str(
                   xed_operand_operand_visibility(op)),
               xed_operand_action_enum_t2str(rw),
               xed_operand_width_enum_t2str(xed_operand_width(op)));
        bits =  xed_decoded_inst_operand_length_bits(xedd,i);
        printf( "  %3u", bits);
        /* rounding, bits might not be a multiple of 8 */
        printf("  %4u", (bits +7) >> 3);
        printf("    %2u", xed_decoded_inst_operand_elements(xedd,i));
        printf("    %3u", xed_decoded_inst_operand_element_size_bits(xedd,i));

        printf(" %10s",
               xed_operand_element_type_enum_t2str(
                   xed_decoded_inst_operand_element_type(xedd,i)));
        printf(" %10s\n",
               xed_reg_class_enum_t2str(
                   xed_reg_class(
                       xed_decoded_inst_get_reg(xedd, op_name))));
    }
}

void get_register(int& reg,trace_type_t type,xed_decoded_inst_t* xedd) {

    unsigned int noperands;
    //char tbuf[90];
    const xed_inst_t* xi = xed_decoded_inst_inst(xedd);
    //xed_operand_action_enum_t rw;
    //xed_uint_t bits;
    noperands = xed_inst_noperands(xi);
    //tbuf[0]=0;
    //cout << "noperands: " << noperands << endl;
    if (type == TRACE_TYPE_READ) {
        // get one operand pointer
        const xed_operand_t *op = xed_inst_operand(xi, 0);
        // get the general operand name
        xed_operand_enum_t op_name = xed_operand_name(op);
        if (XED_OPERAND_REG <= op_name && op_name <= XED_OPERAND_REG9) {
            reg = op_name;
        } else {
            reg = -1;
        }
        // return the specified register operand name
        //xed_reg_enum_t reg_name = xed_decoded_inst_get_reg(xedd,op_name);
    }
    if (type == TRACE_TYPE_WRITE) {
        // get one operand pointer
        const xed_operand_t *op = xed_inst_operand(xi, noperands-1);
        // get the general operand name
        xed_operand_enum_t op_name = xed_operand_name(op);
        if (XED_OPERAND_REG <= op_name && op_name <= XED_OPERAND_REG9) {
            reg = op_name;
        } else {
            reg = -1;
        }
        // return the specified register operand name
        //xed_reg_enum_t reg_name = xed_decoded_inst_get_reg(xedd,op_name);
    }
//    for(int i=0; i < noperands ; i++) {
//        // get one operand pointer
//        const xed_operand_t *op = xed_inst_operand(xi, i);
//        // get the general operand name
//        xed_operand_enum_t op_name = xed_operand_name(op);
//        // return the specified register operand name
//        xed_reg_enum_t reg_name = xed_decoded_inst_get_reg(xedd,op_name);
//        if (XED_OPERAND_REG <= op_name && op_name <= XED_OPERAND_REG9) {
//            cout << "reg [" << i << "]: " << reg_name << " " << xed_reg_enum_t2str(reg_name) << endl;
//        } else {
//            cout << "no reg" <<endl;
//        }
//    }
}

bool isDecodingSuccess(xed_error_enum_t& xed_error) {
    if (xed_error != XED_ERROR_NONE) {

        switch(xed_error) {
        case XED_ERROR_BUFFER_TOO_SHORT:
            printf("XED_ERROR_BUFFER_TOO_SHORT: There were not enough bytes in the given buffer\n");
            break;
        case XED_ERROR_GENERAL_ERROR:
            printf("\033[31mXED_ERROR_GENERAL_ERROR: XED could not decode the given instruction\033[0m \n");
            break;
        case XED_ERROR_INVALID_FOR_CHIP:
            printf("XED_ERROR_INVALID_FOR_CHIP: The instruction is not valid for the specified chip\n");
            break;
        case XED_ERROR_BAD_REGISTER:
            printf("XED_ERROR_BAD_REGISTER: XED could not decode the given instruction because an invalid register encoding was used\n");
            break;
        case XED_ERROR_BAD_LOCK_PREFIX:
            printf("XED_ERROR_BAD_LOCK_PREFIX: A lock prefix was found where none is allowed\n");
            break;
        case XED_ERROR_BAD_REP_PREFIX:
            printf("XED_ERROR_BAD_REP_PREFIX: An F2 or F3 prefix was found where none is allowed\n");
            break;
        case XED_ERROR_BAD_LEGACY_PREFIX:
            printf("XED_ERROR_BAD_LEGACY_PREFIX: A 66, F2 or F3 prefix was found where none is allowed\n");
            break;
        case XED_ERROR_BAD_REX_PREFIX:
            printf("XED_ERROR_BAD_REX_PREFIX: A REX prefix was found where none is allowed\n");
            break;
        case XED_ERROR_BAD_EVEX_UBIT:
            printf("XED_ERROR_BAD_EVEX_UBIT: An illegal value for the EVEX.U bit was present in the instruction\n");
            break;
        case XED_ERROR_BAD_MAP:
            printf("XED_ERROR_BAD_MAP: An illegal value for the MAP field was detected in the instruction\n");
            break;
        case XED_ERROR_BAD_EVEX_V_PRIME:
            printf("XED_ERROR_BAD_EVEX_V_PRIME: EVEX.V'=0 was detected in a non-64b mode instruction\n");
            break;
        case XED_ERROR_BAD_EVEX_Z_NO_MASKING:
            printf("XED_ERROR_BAD_EVEX_Z_NO_MASKING: EVEX.Z!=0 when EVEX.aaa==0\n");
            break;
        case XED_ERROR_NO_OUTPUT_POINTER:
            printf("XED_ERROR_NO_OUTPUT_POINTER: The output pointer for xed_agen was zero\n");
            break;
        case XED_ERROR_NO_AGEN_CALL_BACK_REGISTERED:
            printf("XED_ERROR_NO_AGEN_CALL_BACK_REGISTERED: One or both of the callbacks for xed_agen were missing.\n");
            break;
        case XED_ERROR_BAD_MEMOP_INDEX:
            printf("XED_ERROR_BAD_MEMOP_INDEX: Memop indices must be 0 or 1\n");
            break;
        case XED_ERROR_CALLBACK_PROBLEM:
            printf("XED_ERROR_CALLBACK_PROBLEM: The register or segment callback for xed_agen experienced a problem\n");
            break;
        case XED_ERROR_GATHER_REGS:
            printf("XED_ERROR_GATHER_REGS: The index, dest and mask regs for AVX2 gathers must be different\n");
            break;
        case XED_ERROR_INSTR_TOO_LONG:
            printf("XED_ERROR_INSTR_TOO_LONG: Full decode of instruction would exceed 15B\n");
            break;
        case XED_ERROR_INVALID_MODE:
            printf("XED_ERROR_INVALID_MODE: The instruction was not valid for the specified mode\n");
            break;
        case XED_ERROR_BAD_EVEX_LL:
            printf("XED_ERROR_BAD_EVEX_LL: EVEX.LL must not ==3 unless using embedded rounding\n");
            break;
        case XED_ERROR_BAD_REG_MATCH:
            printf("XED_ERROR_BAD_REG_MATCH: Source registers must not match the destination register for this instruction\n");
            break;
        default:
            printf("XED_ERROR_UNKNOWN\n");
            break;
        }
        return false;
    }
    return true;
}

// 1. state initialization
xed_state_t dstate;
// 4. the main container for storing messages after instruction decoding
xed_decoded_inst_t xedd;

void get_reg(int& reg,trace_type_t type,memref_t memref){
    // 3. init storage tables
    xed_tables_init();
    // 2. init this state, pointing cpu_mode and address_width
    xed_state_init(&dstate, XED_MACHINE_MODE_LONG_64,XED_ADDRESS_WIDTH_64b,XED_ADDRESS_WIDTH_64b);

    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
    xed_error_enum_t  xed_error= xed_decode(&xedd,reinterpret_cast<const xed_uint8_t*>(memref.instr.encoding),memref.instr.size);
    if (!isDecodingSuccess(xed_error)) {
        cout << "+++++++++++++++++++++" << endl;
        exit(-1);
    }

    #define BUFLEN  1000
    char buffer[BUFLEN];
    // Print out all the information about the decoded instruction
    xed_decoded_inst_dump(&xedd,buffer, BUFLEN);
    cout << buffer << endl;
    // 6. withdrew messages from xedd
    unsigned int noperands;
    const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
    noperands = xed_inst_noperands(xi);

    if (type == TRACE_TYPE_READ) {
        // get one operand pointer
        const xed_operand_t *op = xed_inst_operand(xi, 0);
        // get the general operand name
        xed_operand_enum_t op_name = xed_operand_name(op);
        // return the specified register operand name
        xed_reg_enum_t reg_name = xed_decoded_inst_get_reg(&xedd,op_name);
        if (XED_OPERAND_REG <= op_name && op_name <= XED_OPERAND_REG9) {
            reg = reg_name;
        } else {
            reg = -1;
        }
    }
    if (type == TRACE_TYPE_WRITE) {
        // get one operand pointer
        const xed_operand_t *op = xed_inst_operand(xi, noperands-1);
        // get the general operand name
        xed_operand_enum_t op_name = xed_operand_name(op);
        // return the specified register operand name
        xed_reg_enum_t reg_name = xed_decoded_inst_get_reg(&xedd,op_name);
        if (XED_OPERAND_REG <= op_name && op_name <= XED_OPERAND_REG9) {
            reg = reg_name;
        } else {
            reg = -1;
        }
    }
    //get_register(reg,memref.data.type,&xedd);
    //return get_register(&xedd);
}

void get_info(memref_t memref){
    // 3. init storage tables
    xed_tables_init();
    // 2. init this state, pointing cpu_mode and address_width
    xed_state_init(&dstate, XED_MACHINE_MODE_LONG_64,XED_ADDRESS_WIDTH_64b,XED_ADDRESS_WIDTH_64b);

    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
    xed_error_enum_t  xed_error= xed_decode(&xedd,reinterpret_cast<const xed_uint8_t*>(memref.instr.encoding),memref.instr.size);
    if (!isDecodingSuccess(xed_error)) {
        cout << "+++++++++++++++++++++" << endl;
        exit(-1);
    }

#define BUFLEN  1000
    char buffer[BUFLEN];
    // Print out all the information about the decoded instruction
    xed_decoded_inst_dump(&xedd,buffer, BUFLEN);
    cout << buffer << endl;
}
void dead_code_analysis_t::detectDeadCode_thread(memref_t memref)
{
    number.allCodeNumber++; // 计数
    if ((memref.data.type >= TRACE_TYPE_INSTR && memref.data.type <= TRACE_TYPE_INSTR_RETURN) ||
        memref.data.type == TRACE_TYPE_INSTR_SYSENTER) {
        ins_memref = memref;
        cout << "index: " <<number.allCodeNumber<< " addr: " << memref.data.addr << endl;
        cout << "\033[33m=======BEGIN DECODING=======\033[0m" << endl;
        get_info(memref);
        cout << "\033[33m=======END DECODING=======\033[0m" << endl << endl;
    }
    else if (memref.data.type == TRACE_TYPE_READ || memref.data.type == TRACE_TYPE_WRITE){ // 数据操纵-读or写

        // 1.构造tid-addr的pair
        std::pair<memref_tid_t,addr_t> pair_tid_addr(memref.data.tid, memref.data.addr);
        if (addr_read_write.find(pair_tid_addr) == addr_read_write.end()) {
            initAddrReadWrite_thread(memref); // 初始化操作，构建map中的key-value
        } else {
            // 读取
            if (memref.data.type == TRACE_TYPE_READ) {
                if (addr_read_write[pair_tid_addr]->read) {
                    if (addr_read_write[pair_tid_addr]->obj.data.type == TRACE_TYPE_READ) {
                        int reg = -1; // current reg
                        get_reg(reg,memref.data.type,ins_memref);
                        if (reg != -1) {

                            if (reg == addr_read_write[pair_tid_addr]->reg_r) {
                                //cout << "reg : " << xed_reg_enum_t2str(
                                //            static_cast<const xed_reg_enum_t>(reg)) << endl;
                                // dead code
                                number.deadCodeNumber_read++;
                                addDeadCode(number.allCodeNumber,memref,reg);
                            } else {
                                addr_read_write[pair_tid_addr]->reg_r = reg;
                            }
                        }


                    }
                } else {
                    // 从来没有读过
                    addr_read_write[pair_tid_addr]->read = true;
                }
                addr_read_write[pair_tid_addr]->obj = memref; // read
            } else if (memref.data.type == TRACE_TYPE_WRITE) { // 写入
                int reg = -1; // current reg
                get_reg(reg, memref.data.type,ins_memref);
                if (addr_read_write[pair_tid_addr]->write) {
                    if (addr_read_write[pair_tid_addr]->obj.data.type == TRACE_TYPE_WRITE) {
//                        cout << "....DEAD WRITE...." << endl;
//                        cout << "addr: " << memref.data.addr << endl;
//                        cout << "\033[36m=======BEGIN DECODING=======\033[0m" << endl;
//                        cout << "\033[34m" << "decode: " << "\033[0m";
//                        for (int i = 0; i < ins_memref.instr.size; i++) {
//                            bitset<8> bits(ins_memref.instr.encoding[i]);
//                            printf("\033[34m%02x \033[0m",bits);
//                        }
//                        cout << endl;
//                        //string reg = get_reg(memref);
//                        get_reg(ins_memref);
//                        //cout << "\033[33m[REG]: " << reg << "\033[0m" << endl;
//                        cout << "\033[36m=======END DECODING=======\033[0m" << endl << endl;
                        if (addr_read_write[pair_tid_addr]->reg_w != -1) {
                            addDeadCode(addr_read_write[pair_tid_addr]->index_write,
                                        addr_read_write[pair_tid_addr]->obj,addr_read_write[pair_tid_addr]->reg_w);
                            number.deadCodeNumber_write++;
                        }
                    }
                } else {
                    addr_read_write[pair_tid_addr]->write = true;
                }
                addr_read_write[pair_tid_addr]->index_write = number.allCodeNumber;
                addr_read_write[pair_tid_addr]->obj = memref; // write
                addr_read_write[pair_tid_addr]->reg_w = reg;
            }
        }
    }
}



std::ostream& operator<<(std::ostream& out, const deadCode code) {
    if (code.obj.data.type == TRACE_TYPE_READ) {
        out << "[dead read] "
            << " tid: " << code.obj.data.tid
            << " reg: " << xed_reg_enum_t2str(static_cast<const xed_reg_enum_t>(code.reg))
            << " mem: " << code.obj.data.addr << endl;
    } else if (code.obj.data.type == TRACE_TYPE_WRITE) {
        out << "[dead write] "
            << " tid: " << code.obj.data.tid
            << " reg: " << xed_reg_enum_t2str(static_cast<const xed_reg_enum_t>(code.reg))
            << " mem: " << code.obj.data.addr << endl;
    }
    return out;
}

int count_ = 0;
bool
dead_code_analysis_t::process_memref(const memref_t &memref)
{
    //if (count_++ > 2000) return true;
    bool isRead = memref.data.type == TRACE_TYPE_READ;
    bool isWrite = memref.data.type == TRACE_TYPE_WRITE;
    if (isRead) {
        num_read_refs_++;
    }

    if (isWrite) {
        num_write_refs_++;
    }

    // 检测死指令
    detectDeadCode_thread(memref);
    return true;
}


bool
dead_code_analysis_t::print_results()
{
    std::cerr << "DEAD CODE ANALYSIS results:\n";
    std::cerr << "  Number of memory read references: " << num_read_refs_ << "\n";
    std::cerr << "  Number of memory write references: " << num_write_refs_ << "\n";
    std::cerr << "  Number of deadCode: " << number.deadCodeNumber_read + number.deadCodeNumber_write<< "\n";
    std::cerr << "  Number of deadCode_read: " << number.deadCodeNumber_read << "\n";
    std::cerr << "  Number of deadCode_write: " << number.deadCodeNumber_write << "\n";

    sort(sorted_deadCode.begin(),sorted_deadCode.end());
    int threshold = 0;
    for (deadCode dc : sorted_deadCode) {
        threshold++;
        if (threshold > 1000) break;
            cout << dc;
    }
    return true;
}