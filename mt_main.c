//--------------------------------------------------------------------*/
//--- Memtrace: a memory tracing tool.                   mt_main.c ---*/
//--------------------------------------------------------------------*/

/*
   This file is part of Memtrace, a Valgrind tool for tracing allocated
   memory of program. It is also based on tool, Lackey by Nicholas Nethercote

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/


#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"

/*------------------------------------------------------------*/
/*--- Command line options                                 ---*/
/*------------------------------------------------------------*/

static Bool clo_mem_trace = True;
static Bool clo_all_refs = True;

static Bool mt_process_cmd_line_option(const HChar* arg)
{
    if VG_BOOL_CLO(arg, "--mem-trace",      clo_mem_trace) {}
    else if VG_BOOL_CLO(arg, "--all-refs",  clo_all_refs) {}
    else
        return False;

    return True;
}

static void mt_print_usage(void)
{
    VG_(printf)(
"   --mem-trace=yes|no          trace all memory access [yes]\n"
"   --all-refs=yes|no           trace all memory reference [yes]\n"
    );
}

static void mt_print_debug_usage(void)
{
    VG_(printf)(
"   (none)\n"
    );
}

