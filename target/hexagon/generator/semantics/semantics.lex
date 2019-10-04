%option noyywrap
%option noinput
%option nounput
%option yylineno

%{
/*
 * Hexagon emulation for qemu: semantics lexer.
 *
 * Copyright (c) 2017-2019 Comsecuris UG (haftungsbeschraenkt)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdbool.h>
#include "semantics_struct.h"
#include "semantics.tab.h"

//#define TOKEN_DEBUG

/* Global Error Counter */
int error_count = 0;
void yyerror(char *s);
int fileno(FILE *stream);

%}

/* Definitions */
DIGIT                    [0-9]
LOWER_ID                 [a-z]
UPPER_ID                 [A-Z]
HEX_DIGIT                [0-9a-fA-F]
REG_ID_32                e|s|d|t|u|v|x|y
REG_ID_64                ee|ss|dd|tt|uu|vv|xx|yy
SYS_ID_32                s|d
SYS_ID_64                ss|dd
LOWER_IMM_S              s|m|r
LOWER_PRE                d|s|t|u|v|e
UPPER_IMM_S              S|M|R
ZERO_ONE                 0|1

/* Tokens */
%option noyywrap

%%

[ \t\f\v]+               { /* Ignore whitespaces. */ }
[\n\r]+                    { /* Ignore newlines. */ }

"{"                      { return LBR; }
"}"                      { return RBR; }
"["                      { return LSQ; } 
"]"                      { return RSQ; }
"("                      { return LPAR; }
")"                      { return RPAR; }
";"                      { return SEMI; }
":"                      { return COLON; }
"+"                      { return PLUS; }
"-"                      { return MINUS; }
"[+-]"                   { return PMINUS; }
"*"                      { return MUL; }
"**"                     { return POW; }
"/"                      { return DIV; }
"%"                      { return MOD; }
"&"                      { return AND; }
"|"                      { return OR; }
"^"                      { return XOR; }
"[|&]"                   { return ANDOR; }
"[<<1]"                  { return OPTSHIFT; }
"[<<N]"                  { return NSHIFT; }
"~"                      { return NOT; }
"="                      { return ASSIGN; }
"+="                     { return INC; }
"-="                     { return DEC; }
"++"                     { return PLUSPLUS; }
"[+-]="                  { return INCDECA; }
"&="                     { return ANDA; }
"|="                     { return ORA; }
"^="                     { return XORA; }
"[|&]="                  { return ANDORA; }
"<"                      { return LT; }
">"                      { return GT; }
"<<"                     { return ASL; }
">>"                     { return ASR; }
"<<R"                    { return ROL; }
">>>"                    { return LSR; }
"=="                     { return EQ; }
"[!]="                   { return OPTEQ; }
"!="                     { return NEQ; }
"<="                     { return LTE; }
">="                     { return GTE; }
"->"                     { return LARR; }
"&&"                     { return ANDL; }
"||"                     { return ORL; }
"!"                      { return NOTL; }
","                      { return COMMA; }
"else"                   { return ELSE; }
"for"                    { return FOR; }
"i"                      { return I; }
"I"                      { return ICIRC; }
"if"                     { return IF; }
"Assembler mapped to:"   { return MAPPED; }
"apply_extension"        { return EXT; }
"dcache_inv_all"         { return DCKILL; }
"dcache_clean_addr"      { return DCLEAN; }
"dcache_cleaninv_addr"   { return DCINVA; }
"dcache_zero_addr"       { return DZEROA; }
"dcache_fetch"           { return DFETCH; }
"icache_inv_all"         { return ICKILL; }
"l2cache_inv_all"        { return L2KILL; }
"instruction_sync"       { return ISYNC; }
"frame_scramble"         { return FSCR; }
"frame_unscramble"       { return FSCR; }
"frame_check_limit"      { return FCHK; }
"Constant_extended"      { return CONSTEXT; }
"Enter debug mode"       { return BRKPT; }
"count_leading_ones"     { return LOCNT; }
"reverse_bits"           { return BREV; }
"memory_synch"           { return SYNCHT; }
"(!in_debug_mode)"       { return DEBUG; }
"lock_valid"             { return LOCK; }
"modectl[TNUM]"          { return MODECTL; }
"width"                  { return WIDTH; }
"offset"                 { return OFFSET; }
"shamt"                  { return SHAMT; }
"addr"                   { return ADDR; }
"sumr"                   { return SUMR; }
"sumi"                   { return SUMI; }
"control"                { return CTRL; }
"tmpr"                   { return TMPR; }
"tmpi"                   { return TMPI; }
"tmp"                    { return TMP; }
"x0"                     { return X0; }
"x1"                     { return X1; }
"y0"                     { return Y0; }
"y1"                     { return Y1; }
"prod0"                  { return PROD0; }
"prod1"                  { return PROD1; }
"sxt"                    { return SXT; }
"zxt"                    { return ZXT; }
"min"                    { return MIN; }
"max"                    { return MAX; }
"ABS"                    { return ABS; }
"convround"              { return CROUND; }
"round"                  { return ROUND; }
"circ_add"               { return CIRCADD; }
".new"                   { return NEW; }
"[.new]"                 { return OPTNEW; }
"[!]"                    { return OPTNOTL; }
"[01]"                   { return ZEROONE; }
"sat"{DIGIT}+            { yylval.vec.width = atoi(yytext + 3);
                           yylval.vec.index = 0;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
"[sat"{DIGIT}+"]"        { yylval.vec.width = atoi(yytext + 4);
                           yylval.vec.index = 0;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
"usat"{DIGIT}+           { yylval.vec.width = atoi(yytext + 4);
                           yylval.vec.index = 0;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
"[usat"{DIGIT}+"]"       { yylval.vec.width = atoi(yytext + 5);
                           yylval.vec.index = 0;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
".u64"                   { return (U64); }
".i"                     { yylval.vec.width = 1;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I_ITER;
                           return (VEC); }
".i*2"                   { yylval.vec.width = 1;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2_ITER;
                           return (VEC); }
".i*2+1"                 { yylval.vec.width = 1;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2PLUS1_ITER;
                           return (VEC); }
".b["{DIGIT}"]"          { yylval.vec.width = 8;
                           yylval.vec.index = atoi(yytext + 3);
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
".ub["{DIGIT}"]"         { yylval.vec.width = 8;
                           yylval.vec.index = atoi(yytext + 4);
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
".h["{DIGIT}"]"          { yylval.vec.width = 16;
                           yylval.vec.index = atoi(yytext + 3);
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
".h[01]"                 { yylval.vec.width = 16;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = true;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
".uh["{DIGIT}"]"         { yylval.vec.width = 16;
                           yylval.vec.index = atoi(yytext + 4);
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
".uh[01]"                { yylval.vec.width = 16;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = true;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
".w["{DIGIT}"]"          { yylval.vec.width = 32;
                           yylval.vec.index = atoi(yytext + 3);
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
".uw["{DIGIT}"]"         { yylval.vec.width = 32;
                           yylval.vec.index = atoi(yytext + 4);
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = NO_ITER;
                           return (VEC); }
".b[i]"                  { yylval.vec.width = 8;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I_ITER;
                           return (VEC); }
".ub[i]"                 { yylval.vec.width = 8;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I_ITER;
                           return (VEC); }
".ub[#u]"                { /* XXX: #u maps to the i variable, we assume it is
                              not interleaved with the i for loop iterator */
                           yylval.vec.width = 8;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I_ITER;
                           return (VEC); }
".b[i+1]"                { yylval.vec.width = 8;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = IPLUS1_ITER;
                           return (VEC); }
".h[i]"                  { yylval.vec.width = 16;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I_ITER;
                           return (VEC); }
".uh[i]"                 { yylval.vec.width = 16;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I_ITER;
                           return (VEC); }
".w[i]"                  { yylval.vec.width = 32;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I_ITER;
                           return (VEC); }
".uw[i]"                 { yylval.vec.width = 32;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I_ITER;
                           return (VEC); }
".b[i*2]"                { yylval.vec.width = 8;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2_ITER;
                           return (VEC); }
".ub[i*2]"               { yylval.vec.width = 8;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2_ITER;
                           return (VEC); }
".h[i*2]"                { yylval.vec.width = 16;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2_ITER;
                           return (VEC); }
".uh[i*2]"               { yylval.vec.width = 16;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2_ITER;
                           return (VEC); }
".w[i*2]"                { yylval.vec.width = 32;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2_ITER;
                           return (VEC); }
".uw[i*2]"               { yylval.vec.width = 32;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2_ITER;
                           return (VEC); }
".b[i*2+1]"              { yylval.vec.width = 8;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2PLUS1_ITER;
                           return (VEC); }
".ub[i*2+1]"             { yylval.vec.width = 8;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2PLUS1_ITER;
                           return (VEC); }
".h[i*2+1]"              { yylval.vec.width = 16;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2PLUS1_ITER;
                           return (VEC); }
".uh[i*2+1]"             { yylval.vec.width = 16;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2PLUS1_ITER;
                           return (VEC); }
".w[i*2+1]"              { yylval.vec.width = 32;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2PLUS1_ITER;
                           return (VEC); }
".uw[i*2+1]"             { yylval.vec.width = 32;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = true;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = I2PLUS1_ITER;
                           return (VEC); }
".b[i+4]"                { yylval.vec.width = 8;
                           yylval.vec.index = -1;
                           yylval.vec.is_unsigned = false;
                           yylval.vec.is_zeroone = false;
                           yylval.vec.iter_type = IPLUS4_ITER;
                           return (VEC); }
"["{DIGIT}":"{DIGIT}"]"  { yylval.range.end = atoi(yytext + 1);
                           yylval.range.begin = atoi(yytext + 3);
                           return (RANGE); }
"#"                      { return HASH; }
"?"                      { return QMARK; }
"EA"                     { return EA; }
"PC"                     { return PC; }
"NPC"                    { return NPC; }
"*EA"                    { return STAREA; }
"TRAP \"0\""             { return TRAP0; }
"TRAP \"1\""             { return TRAP0; }
"USR.LPCFG"              { return LPCFG; }
"SSR.CAUSE"              { return CAUSE; }
"SSR.SSR_EX"             { return EX; }
"TLB"                    { return TLB; }
"IPEND"                  { return IPEND; }
"xv"                     { return TMP; }
"sv"                     { return TMP; }
"tv"                     { return TMP; }
"(int)"                  { return INT; }
"NOP"                    { return NOP; }

"SA"{ZERO_ONE}           { yylval.index = atoi(yytext);
                           return SA; }
"LC"{ZERO_ONE}           { yylval.index = atoi(yytext);
                           return LC; }
"R"{REG_ID_32}           { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = GENERAL_PURPOSE;
                           yylval.rvalue.reg.id = yytext[1];
                           yylval.rvalue.reg.is_const = false;
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
"C"{REG_ID_32}           { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = CONTROL;
                           yylval.rvalue.reg.id = yytext[1];
                           yylval.rvalue.reg.is_const = false;
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
"C"{REG_ID_64}           { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = CONTROL;
                           yylval.rvalue.reg.id = yytext[1];
                           yylval.rvalue.reg.is_const = false;
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.bit_width = 64;
                           return (REG); }
"R"{REG_ID_64}           { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = GENERAL_PURPOSE;
                           yylval.rvalue.reg.id = yytext[1];
                           yylval.rvalue.reg.is_const = false;
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.bit_width = 64;
                           return (REG); }
"N"{LOWER_ID}            { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = GENERAL_PURPOSE;
                           yylval.rvalue.reg.id = yytext[1];
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.reg.is_const = false;
                           return (REG); }
"S"{SYS_ID_32}           { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = SYSTEM;
                           yylval.rvalue.reg.id = yytext[1];
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.reg.is_const = false;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
"S"{SYS_ID_64}           { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = SYSTEM;
                           yylval.rvalue.reg.id = yytext[1];
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.reg.is_const = false;
                           yylval.rvalue.bit_width = 64;
                           return (REG); }
[rR]{DIGIT}+             { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = GENERAL_PURPOSE;
                           yylval.rvalue.reg.id = atoi(yytext + 1);
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.reg.is_const = true;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
"SGP"{DIGIT}             { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = SYSTEM;
                           yylval.rvalue.reg.id = atoi(yytext + 3);
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.reg.is_const = true;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
"SP"                     { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = GENERAL_PURPOSE;
                           yylval.rvalue.reg.id = 29;
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.reg.is_const = true;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
"FP"                     { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = GENERAL_PURPOSE;
                           yylval.rvalue.reg.id = 30;
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.reg.is_const = true;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
"LR"                     { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = GENERAL_PURPOSE;
                           yylval.rvalue.reg.id = 31;
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.reg.is_const = true;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
"GP"                     { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = CONTROL;
                           yylval.rvalue.reg.id = 11;
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.reg.is_const = true;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
"MuV"                    { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = CONTROL;
                           yylval.rvalue.reg.id = yytext[1];
                           yylval.rvalue.reg.offset = 6;
                           yylval.rvalue.reg.is_const = false;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
"ELR"                    { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.reg.type = SYSTEM;
                           yylval.rvalue.reg.id = 3;
                           yylval.rvalue.reg.offset = 0;
                           yylval.rvalue.reg.is_const = true;
                           yylval.rvalue.bit_width = 32;
                           return (REG); }
[pP]{DIGIT}              { yylval.rvalue.type = PREDICATE;
                           yylval.rvalue.pre.id = yytext[1];
                           yylval.rvalue.pre.is_zeroone = false;
                           yylval.rvalue.pre.is_bit_iter = false;
                           yylval.rvalue.bit_width = 8;
                           return (PRE); }
"P"{LOWER_PRE}           { yylval.rvalue.type = PREDICATE;
                           yylval.rvalue.pre.id = yytext[1];
                           yylval.rvalue.pre.is_zeroone = false;
                           yylval.rvalue.pre.is_bit_iter = false;
                           yylval.rvalue.bit_width = 8;
                           return (PRE); }
"P"                      { yylval.rvalue.type = PREDICATE;
                           yylval.rvalue.bit_width = 8;
                           return (PRE); }
"#"{LOWER_IMM_S}{DIGIT}* { yylval.rvalue.type = IMMEDIATE;
                           yylval.rvalue.is_unsigned = false;
                           yylval.rvalue.imm.type = VARIABLE;
                           yylval.rvalue.imm.id = 'j';
                           return (IMM); }
"#"{UPPER_IMM_S}{DIGIT}* { yylval.rvalue.type = IMMEDIATE;
                           yylval.rvalue.is_unsigned = false;
                           yylval.rvalue.imm.type = VARIABLE;
                           yylval.rvalue.imm.id = 'I';
                           return (IMM); }
"#u"{DIGIT}*             { yylval.rvalue.type = IMMEDIATE;
                           yylval.rvalue.is_unsigned = true;
                           yylval.rvalue.imm.type = VARIABLE;
                           yylval.rvalue.imm.id = 'j';
                           return (IMM); }
"#U"{DIGIT}*             { yylval.rvalue.type = IMMEDIATE;
                           yylval.rvalue.is_unsigned = true;
                           yylval.rvalue.imm.type = VARIABLE;
                           yylval.rvalue.imm.id = 'I';
                           return (IMM); }
"N"                      { yylval.rvalue.type = REGISTER;
                           yylval.rvalue.imm.type = VARIABLE;
                           yylval.rvalue.imm.id = 'N';
                           return (IMM); }
{DIGIT}+                 { yylval.rvalue.type = IMMEDIATE;
                           yylval.rvalue.bit_width = 32;
                           yylval.rvalue.imm.type = VALUE;
                           yylval.rvalue.imm.value = atoi(yytext);
                           return (IMM); }
"0x"{HEX_DIGIT}+         { yylval.rvalue.type = IMMEDIATE;
                           yylval.rvalue.bit_width = 32;
                           yylval.rvalue.imm.type = VALUE;
                           yylval.rvalue.imm.value = strtol(yytext, NULL, 16);
                           return (IMM); }

.                        { printf("Error: unexpected token \"%s\"\n", yytext);
                           error_count++;
                           return (-1); /* invalid token */
                         }

%%

YYSTYPE yylval;

void yyerror(char *s)               
{                                   
    printf("Error '%s' on line %d:\n", s, yylineno);      
    error_count++;                  
}                                   


#ifdef TOKEN_DEBUG
int main(void)
{
    int token;
    while ((token = yylex()) != 0)
        printf("Token: %d (%s)\n", token, yytext);
    return 0;
} 
#endif
