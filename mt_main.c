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
#include "pub_tool_mallocfree.h"
#include "pub_tool_replacemalloc.h"
#include "pub_tool_stacktrace.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_poolalloc.h"

/*------------------------------------------------------------*/
/*--- Command line options                                 ---*/
/*------------------------------------------------------------*/

static Bool clo_mem_trace = True;
static Bool clo_trace_all = True;
static Bool clo_show_func = True;

static Bool mt_process_cmd_line_option(const HChar* arg)
{
    if VG_BOOL_CLO(arg, "--mem-trace",      clo_mem_trace) {}
    else if VG_BOOL_CLO(arg, "--trace-all", clo_trace_all) {}
    else if VG_BOOL_CLO(arg, "--show-func", clo_show_func) {}
    else
        return False;

    return True;
}

static void mt_print_usage(void)
{
    VG_(printf)(
"   --mem-trace=yes|no          trace all memory access [yes]\n"
"   --trace-all=yes|no          trace all memory reference [yes]\n"
"   --show-func=yes|no          show function name [yes]\n"
    );
}

static void mt_print_debug_usage(void)
{
    VG_(printf)(
"   (none)\n"
    );
}

/*------------------------------------------------------------*/
/*--- Stuff for --mem-trace                                ---*/
/*------------------------------------------------------------*/

typedef
    IRExpr
    IRAtom;

#define MAX_DSIZE   512

typedef
    enum {Event_Ir, Event_Dr, Event_Dw, Event_Dm}
    EventKind;

typedef
    struct
    {
        EventKind   ekind;
        IRAtom*     addr;
        Int         size;
        IRAtom*     guard;
    }
    Event;

/* Up to this many unnotified events are allowed.  Must be at least two,
   so that reads and writes to the same address can be merged into a modify.
   Beyond that, larger numbers just potentially induce more spilling due to
   extending live ranges of address temporaries. */
#define N_EVENTS 4

/* Maintain an ordered list of memory events which are outstanding, in
   the sense that no IR has yet been generated to do the relevant
   helper calls.  The SB is scanned top to bottom and memory events
   are added to the end of the list, merging with the most recent
   notified event where possible (Dw immediately following Dr and
   having the same size and EA can be merged).

   This merging is done so that for architectures which have
   load-op-store instructions (x86, amd64), the instr is treated as if
   it makes just one memory reference (a modify), rather than two (a
   read followed by a write at the same address).

   At various points the list will need to be flushed, that is, IR
   generated from it.  That must happen before any possible exit from
   the block (the end, or an IRStmt_Exit).  Flushing also takes place
   when there is no space to add a new event, and before entering a
   RMW (read-modify-write) section on processors supporting LL/SC.

   If we require the simulation statistics to be up to date with
   respect to possible memory exceptions, then the list would have to
   be flushed before each memory reference.  That's a pain so we don't
   bother.

   Flushing the list consists of walking it start to end and emitting
   instrumentation IR for each event, in the order in which they
   appear. */

static Event events[N_EVENTS];
static Int   events_used = 0;

/*------------------------------------------------------------*/
/*--- Stuff for --trace-all=no                             ---*/
/*------------------------------------------------------------*/

typedef
    struct
    {
        ULong           offset;
        ULong           start;
        ULong           size;
        struct Address* next;
    }
    Address;

/* Use a link table to collect all the address allocated by the program. */

static Address* addresses = NULL;
static ULong watermark = 0;

/*------------------------------------------------------------*/
/*--- Stuff for --show-func=yes                            ---*/
/*------------------------------------------------------------*/
HChar   lastFnname[255];

/*------------------------------------------------------------*/
/*--- Global Tool Functions                                ---*/
/*------------------------------------------------------------*/
static void pp_StackTrace_wrapper(HChar* trace_info, ThreadId tid)
{
    static Addr ips[10];

    Int n_ips = VG_(get_StackTrace)(tid, ips, 10, NULL, NULL, 0);
    VG_(message)(Vg_UserMsg, " Detected %s, stack trace:\n", trace_info);
    VG_(pp_StackTrace)(VG_(current_DiEpoch)(), ips, n_ips);
}

static void print_allocation_info(HChar* trace_info, ThreadId tid,
                                  void* p, SizeT req_szB)
{
    pp_StackTrace_wrapper(trace_info, tid);
    VG_(message)(Vg_UserMsg, " Detailed information of allocation:\n");
    VG_(message)(Vg_UserMsg, "   Address: 0x%08lx,", (ULong)p);
    VG_(message)(Vg_UserMsg, " Size: %lu\n\n", (ULong)req_szB);
}


/*------------------------------------------------------------*/
/*--- Functions for --trace-all=no                         ---*/
/*------------------------------------------------------------*/

typedef
    struct _HP_Chunk {
        struct _HP_Chunk* next;
        Addr              data;
        SizeT             req_szB;
        SizeT             slop_szB;
    }
    HP_Chunk;

static PoolAlloc *HP_Chunk_alloc_pool = NULL;

static VgHashTable *allocaiton_list = NULL;

static __inline__ void* add_address(ThreadId tid, void* p, SizeT req_szB, SizeT slop_szB)
{
    HP_Chunk* hc = VG_(allocEltPA)(HP_Chunk_alloc_pool);
    hc->req_szB  = req_szB;
    hc->slop_szB = slop_szB;
    hc->data     = (Addr)p;
    VG_(HT_add_node)(allocaiton_list, hc);

    return p;
}

static __inline__ void* alloc_and_add_wrapper(ThreadId tid, SizeT req_szB, 
                                              SizeT req_alignB, Bool is_zeroed)
{
    SizeT actual_szB, slop_szB;
    void* p;

    if((SizeT)req_szB < 0) {
        return NULL;
    }

    p = VG_(cli_malloc)(req_alignB, req_szB);
    if(!p) {
        return NULL;
    }

    if(is_zeroed) {
        VG_(memset)(p, 0, req_szB);
    }
    actual_szB = VG_(cli_malloc_usable_size)(p);
    tl_assert(actual_szB >= req_szB);
    slop_szB = actual_szB - req_szB;

    add_address(tid, p, req_szB, slop_szB);

    print_allocation_info("allocation function", tid, p, req_szB);

    return p;
}

static __inline__ void remove_address(void* p)
{
    HP_Chunk* hc = VG_(HT_remove)(allocaiton_list, (UWord)p);
    if(NULL == hc) {
        return;
    }

    VG_(freeEltPA)(HP_Chunk_alloc_pool, hc);
    hc = NULL;
}

static __inline__ void free_and_remove_wrapper(void* p)
{
    remove_address(p);
    VG_(cli_free)(p);
}

static __inline__ void* realloc_address(ThreadId tid, void* p_old, SizeT new_req_szB)
{
    HP_Chunk* hc;
    void*     p_new;
    SizeT     old_req_szB, old_slop_szB, new_slop_szB, new_actual_szB;

    hc = VG_(HT_remove)(allocaiton_list, (UWord)p_old);
    if(hc == NULL) {
        return NULL;
    }

    old_req_szB  = hc->req_szB;
    old_slop_szB = hc->slop_szB;

    if(new_req_szB <= old_req_szB + old_slop_szB) {
        p_new = p_old;
        new_slop_szB = old_slop_szB + (old_req_szB - new_req_szB);
    }
    else {
        p_new = VG_(cli_malloc)(VG_(clo_alignment), new_req_szB);
        if(!p_new) {
            return NULL;
        }
        VG_(memcpy)(p_new, p_old, old_req_szB + old_slop_szB);
        VG_(cli_free)(p_old);
        new_actual_szB = VG_(cli_malloc_usable_size)(p_new);
        tl_assert(new_actual_szB >= new_req_szB);
        new_slop_szB = new_actual_szB - new_req_szB;
    }

    if(p_new) {
        hc->data     = (Addr)p_new;
        hc->req_szB  = new_req_szB;
        hc->slop_szB = new_slop_szB;
    }
    VG_(HT_add_node)(allocaiton_list, hc);

    return p_new;
}

// static Bool is_in_allocation_list(Addr addr)
// {
//     VG_(HT_ResetIter)(allocaiton_list);
//     HP_Chunk* hc;
//     while((hc = VG_(HT_Next)(allocaiton_list))) {
//         if(hc->data <= addr && addr < hc->data + hc->req_szB) {
//             return True;
//         }
//     }
//     return False;
// }

static ULong is_in_allocation_list(Addr addr)
{
    HP_Chunk* hc;
    ULong offset;

    VG_(HT_ResetIter)(allocaiton_list);
    while((hc = VG_(HT_Next)(allocaiton_list))) {
        if(hc-> data <= addr && addr < hc->data + hc->req_szB) {
            offset = addr - hc->data;
            return offset;
        }
    }
    return -1;
}

static void* mt_malloc(ThreadId tid, SizeT szB)
{
    return alloc_and_add_wrapper(tid, szB, VG_(clo_alignment), False);
}

static void* mt___builtin_new(ThreadId tid, SizeT szB)
{
    return alloc_and_add_wrapper(tid, szB, VG_(clo_alignment), False);
}

static void* mt___builtin_vec_new(ThreadId tid, SizeT szB)
{
    return alloc_and_add_wrapper(tid, szB, VG_(clo_alignment), False);
}

static void* mt_calloc(ThreadId tid, SizeT m, SizeT szB)
{
    return alloc_and_add_wrapper(tid, m * szB, VG_(clo_alignment), True);
}

static void* mt_memalign(ThreadId tid, SizeT alignB, SizeT szB)
{
    return alloc_and_add_wrapper(tid, szB, alignB, False);
}

static void mt_free(ThreadId tid, void* p)
{
    free_and_remove_wrapper(p);
}

static void mt___builtin_delete(ThreadId tid, void* p)
{
    free_and_remove_wrapper(p);
}

static void mt___builtin_vec_delete(ThreadId tid, void* p)
{
    free_and_remove_wrapper(p);
}

static void* mt_realloc(ThreadId tid, void* p_old, SizeT new_szB)
{
    return realloc_address(tid, p_old, new_szB);
}

static SizeT mt_malloc_usable_size(ThreadId tid, void* p)
{
    HP_Chunk* hc = VG_(HT_lookup)(allocaiton_list, (UWord)p);

    return (hc ? hc->req_szB + hc->slop_szB : 0);
}

/*------------------------------------------------------------*/
/*--- Functions for memory tracing                         ---*/
/*------------------------------------------------------------*/

static VG_REGPARM(1) void showFunc(const HChar* fnname)
{
    if(clo_show_func) {
        VG_(message)(Vg_UserMsg, " %s\n", fnname);
    }
}

static VG_REGPARM(2) void trace_instr(Addr addr, SizeT size)
{
    if(clo_trace_all) {
        // VG_(message)(Vg_UserMsg, " Instr at 0x%08lx: Size: %lu\n", addr, size);
    }
    else {
        // VG_(message)(Vg_UserMsg, " Instr at 0x%08lx: Size: %lu\n", addr, size);
    }
}

static VG_REGPARM(2) void trace_load(Addr addr, SizeT size)
{
    ULong offset;
    if(clo_trace_all) {
        VG_(message)(Vg_UserMsg, " Load at 0x%08lx: Size: %lu\n", addr, size);
    }
    else {
        offset = is_in_allocation_list(addr);
        if(offset != -1) {
            VG_(message)(Vg_UserMsg, " Load at 0x%08lx: Size: %lu, Offset: %08lx\n", addr, size, offset);
        }
    }
}

static VG_REGPARM(2) void trace_store(Addr addr, SizeT size)
{
    ULong offset;
    if(clo_trace_all) {
        VG_(message)(Vg_UserMsg, " Store at 0x%08lx: Size: %lu\n", addr, size);
    }
    else {
        offset = is_in_allocation_list(addr);
        if(offset != -1) {
            VG_(message)(Vg_UserMsg, " Store at 0x%08lx: Size: %lu, Offset: %08lx\n", addr, size, offset);
        }
    }
}

static VG_REGPARM(2) void trace_modify(Addr addr, SizeT size)
{
    ULong offset;
    if(clo_trace_all) {
        VG_(message)(Vg_UserMsg, " Modify at 0x%08lx: Size: %lu\n", addr, size);
    }
    else {
        offset = is_in_allocation_list(addr);
        if(offset != -1) {
            VG_(message)(Vg_UserMsg, " Modify at 0x%08lx: Size :%lu, Offset: %08lx\n", addr, size, offset);
        }
    }
}

static void flushEvents(IRSB* sb)
{
    Int          i;
    const HChar* helperName;
    void*        helperAddr;
    IRExpr**     argv;
    IRDirty*     di;
    Event*       ev;

    for (i = 0; i < events_used; i++) {

        ev = &events[i];

        // Decide on helper fn to call and args to pass it.
        switch (ev->ekind) {
            case Event_Ir:
                helperName = "trace_instr";
                helperAddr = trace_instr;
                break;

            case Event_Dr:
                helperName = "trace_load";
                helperAddr = trace_load;
                break;

            case Event_Dw:
                helperName = "trace_store";
                helperAddr = trace_store;
                break;

            case Event_Dm:
                helperName = "trace_modify";
                helperAddr = trace_modify;
                break;

            default:
                tl_assert(0);
        }

        // Add the helper.
        argv = mkIRExprVec_2(ev->addr, mkIRExpr_HWord(ev->size));
        di   = unsafeIRDirty_0_N(/*regparms*/2,
                                 helperName, VG_(fnptr_to_fnentry)(helperAddr),
                                 argv);
        if(ev->guard) {
            di->guard = ev->guard;
        }
        addStmtToIRSB(sb, IRStmt_Dirty(di));
    }

    events_used = 0;
}

// WARNING:  If you aren't interested in instruction reads, you can omit the
// code that adds calls to trace_instr() in flushEvents().  However, you
// must still call this function, addEvent_Ir() -- it is necessary to add
// the Ir events to the events list so that merging of paired load/store
// events into modify events works correctly.
static void addEvent_Ir(IRSB* sb, IRAtom* iaddr, UInt isize)
{
    Event* evt;
    tl_assert(clo_mem_trace);
    tl_assert(( VG_MIN_INSTR_SZB <= isize && isize <= VG_MAX_INSTR_SZB)
             || VG_CLREQ_SZB == isize );
    if(events_used == N_EVENTS) {
        flushEvents(sb);
    }
    tl_assert(events_used >= 0 && events_used < N_EVENTS);
    evt = &events[events_used];
    evt->ekind = Event_Ir;
    evt->addr  = iaddr;
    evt->size  = isize;
    evt->guard = NULL;
    events_used++;
} 

static void addEvent_Dr_guarded(IRSB* sb, IRAtom* daddr, Int dsize, IRAtom* guard)
{
    Event* evt;
    tl_assert(clo_mem_trace);
    tl_assert(isIRAtom(daddr));
    tl_assert(dsize >= 1 && dsize <= MAX_DSIZE);
    if(events_used == N_EVENTS) {
        flushEvents(sb);
    }
    tl_assert(events_used >= 0 && events_used < N_EVENTS);
    evt = &events[events_used];
    evt->ekind = Event_Dr;
    evt->addr  = daddr;
    evt->size  = dsize;
    evt->guard = guard;
    events_used++;
}

static void addEvent_Dr(IRSB* sb, IRAtom* daddr, Int dsize)
{
    addEvent_Dr_guarded(sb, daddr, dsize, NULL);
}

static void addEvent_Dw_guarded(IRSB* sb, IRAtom* daddr, Int dsize, IRAtom* guard)
{
    Event* evt;
    tl_assert(clo_mem_trace);
    tl_assert(isIRAtom(daddr));
    tl_assert(dsize >= 1 && dsize <= MAX_DSIZE);
    if(events_used == N_EVENTS) {
        flushEvents(sb);
    }
    tl_assert(events_used >= 0 && events_used < N_EVENTS);
    evt = &events[events_used];
    evt->ekind = Event_Dw;
    evt->addr  = daddr;
    evt->size  = dsize;
    evt->guard = guard;
    events_used++;
}

static void addEvent_Dw(IRSB* sb, IRAtom* daddr, Int dsize)
{
    Event* lastEvt;
    Event* evt;
    tl_assert(clo_mem_trace);
    tl_assert(isIRAtom(daddr));
    tl_assert(dsize >= 1 && dsize <= MAX_DSIZE);

    // Is it possible to merge this write with the preceding read?
    lastEvt = &events[events_used - 1];
    if(events_used > 0
       && lastEvt->ekind == Event_Dr
       && lastEvt->size  == dsize
       && lastEvt->guard == NULL
       && eqIRAtom(lastEvt->addr, daddr)) {
        lastEvt->ekind = Event_Dm;
        return;    
    }

    // No.  Add as normal.
    if(events_used == N_EVENTS) {
        flushEvents(sb);
    }
    tl_assert(events_used >= 0 && events_used < N_EVENTS);
    evt = &events[events_used];
    evt->ekind = Event_Dw;
    evt->addr  = daddr;
    evt->size  = dsize;
    evt->guard = NULL;
    events_used++;
}

/*------------------------------------------------------------*/
/*--- Basic tool functions                                 ---*/
/*------------------------------------------------------------*/

static void mt_post_clo_init(void)
{
    // Nothing here
}

static IRSB* mt_instrument(VgCallbackClosure* closure,
                           IRSB* sbIn,
                           const VexGuestLayout* layout,
                           const VexGuestExtents* vge,
                           const VexArchInfo* archinfo_host,
                           IRType gWordTy, IRType hWordTy)
{
    Int   i;
    IRSB* sbOut;
    IRTypeEnv* tyenv = sbIn->tyenv;
    DiEpoch    ep = VG_(current_DiEpoch)();

    if(gWordTy != hWordTy) {
        /* We don't currently support this case. */
        VG_(tool_panic)("host/guest word size mismatch");
    }

    /* Set up SB */
    sbOut = deepCopyIRSBExceptStmts(sbIn);

    // Copy verbatim any IR preamble preceding the first IMark
    i = 0;
    while(i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
        addStmtToIRSB(sbOut, sbIn->stmts[i]);
        i++;
    }

    if(clo_mem_trace) {
        events_used = 0;
    }

    for (/*use current i*/; i < sbIn->stmts_used; i++) {
        IRStmt* st = sbIn->stmts[i];
        if (!st || st->tag == Ist_NoOp) continue;

        switch(st->tag) {
            case Ist_NoOp:
            case Ist_AbiHint:
            case Ist_Put:
            case Ist_PutI:
            case Ist_MBE:
                addStmtToIRSB(sbOut, st);
                break;

            case Ist_IMark: {
                const HChar* fnname;
                if (clo_show_func) {
                    if(VG_(get_fnname_if_entry)(ep, st->Ist.IMark.addr, &fnname)) {
                        showFunc(fnname);
                        VG_(strcpy)(lastFnname, fnname);
                    }
                    else {
                        if(VG_(get_fnname)(ep, st->Ist.IMark.addr, &fnname)) {
                            if(VG_(strcmp)(lastFnname, fnname) != 0) {
                                showFunc(fnname);
                                VG_(strcpy)(lastFnname, fnname);
                            }
                        }
                    }
                }
                if(clo_mem_trace) {
                    // WARNING: do not remove this function call, even if you
                    // aren't interested in instruction reads.  See the comment
                    // above the function itself for more detail.
                    addEvent_Ir(sbOut, mkIRExpr_HWord((HWord)st->Ist.IMark.addr),
                                st->Ist.IMark.len);
                }
                addStmtToIRSB(sbOut, st);
                break;
            }

            case Ist_WrTmp: {
                // Add a call to trace_load() if --mem-trace=yes.
                if(clo_mem_trace) {
                    IRExpr* data = st->Ist.WrTmp.data;
                    if(data->tag == Iex_Load) {
                        addEvent_Dr(sbOut, data->Iex.Load.addr,
                                    sizeofIRType(data->Iex.Load.ty));
                    }
                }
                addStmtToIRSB(sbOut, st);
                break;
            }

            case Ist_Store: {
                IRExpr*   data  = st->Ist.Store.data;
                IRType    type  = typeOfIRExpr(tyenv, data);
                tl_assert(type != Ity_INVALID);
                if(clo_mem_trace) {
                    addEvent_Dw(sbOut, st->Ist.Store.addr,
                                sizeofIRType(type));
                }
                addStmtToIRSB(sbOut, st);
                break;
            }

            case Ist_StoreG: {
                IRStoreG* sg    = st->Ist.StoreG.details;
                IRExpr*   data  = sg->data;
                IRType    type  = typeOfIRExpr(tyenv, data);
                tl_assert(type != Ity_INVALID);
                if(clo_mem_trace) {
                    addEvent_Dw_guarded(sbOut, sg->addr,
                                        sizeofIRType(type), sg->guard);
                }
                addStmtToIRSB(sbOut, st);
                break;
            }

            case Ist_LoadG: {
                IRLoadG*   lg       = st->Ist.LoadG.details;
                IRType     type     = Ity_INVALID; /* loaded type */
                IRType     typeWide = Ity_INVALID; /* after implicit widening */
                typeOfIRLoadGOp(lg->cvt, &typeWide, &type);
                tl_assert(type != Ity_INVALID);
                if(clo_mem_trace) {
                    addEvent_Dr_guarded(sbOut, lg->addr,
                                        sizeofIRType(type), lg->guard);
                }
                addStmtToIRSB(sbOut, st);
                break;
            }

            case Ist_Dirty: {
                if(clo_mem_trace) {
                    Int      dsize;
                    IRDirty* d = st->Ist.Dirty.details;
                    if(d->mFx != Ifx_None) {
                        // This dirty helper accesses memory.  Collect the details.
                        tl_assert(d->mAddr != NULL);
                        tl_assert(d->mSize != 0);
                        dsize = d->mSize;
                        if(d->mFx == Ifx_Read || d->mFx == Ifx_Modify) {
                            addEvent_Dr(sbOut, d->mAddr, dsize);
                        }
                        if(d->mFx == Ifx_Write || d->mFx == Ifx_Modify) {
                            addEvent_Dw(sbOut, d->mAddr, dsize);
                        }
                        else {
                            tl_assert(d->mAddr == NULL);
                            tl_assert(d->mSize == 0);
                        }
                    }
                }
                addStmtToIRSB(sbOut, st);
                break;
            }

            case Ist_CAS: {
                /* We treat it as a read and a write of the location.  I
                   think that is the same behaviour as it was before IRCAS
                   was introduced, since prior to that point, the Vex
                   front ends would translate a lock-prefixed instruction
                   into a (normal) read followed by a (normal) write. */
                Int     dataSize;
                IRType  dataTy;
                IRCAS*  cas = st->Ist.CAS.details;
                tl_assert(cas->addr != NULL);
                tl_assert(cas->dataLo != NULL);
                dataTy   = typeOfIRExpr(tyenv, cas->dataLo);
                dataSize = sizeofIRType(dataTy);
                if(clo_mem_trace) {
                    addEvent_Dr(sbOut, cas->addr, dataSize);
                    addEvent_Dw(sbOut, cas->addr, dataSize);
                }
                addStmtToIRSB(sbOut, st);
                break;
            }

            case Ist_LLSC: {
                IRType dataTy;
                if(st->Ist.LLSC.storedata == NULL) {
                    /* LL */
                    dataTy = typeOfIRTemp(tyenv, st->Ist.LLSC.result);
                    if(clo_mem_trace) {
                        addEvent_Dr(sbOut, st->Ist.LLSC.addr,
                                           sizeofIRType(dataTy));
                        flushEvents(sbOut);
                    }
                }
                else {
                    /* SC */
                    dataTy = typeOfIRExpr(tyenv, st->Ist.LLSC.storedata);
                    if(clo_mem_trace) {
                        addEvent_Dw(sbOut, st->Ist.LLSC.addr,
                                           sizeofIRType(dataTy));
                    }
                }
                addStmtToIRSB(sbOut, st);
                break;
            }

            case Ist_Exit: {
                if(clo_mem_trace) {
                    flushEvents(sbOut);
                }

                addStmtToIRSB(sbOut, st);
                break;
            }

            default:
                ppIRStmt(st);
                tl_assert(0);
        }
    }

    if(clo_mem_trace) {
        flushEvents(sbOut);
    }

    return sbOut;
}

static void mt_fini(Int exitcode) 
{
    // Nothing here
}

static void mt_pre_clo_init(void)
{
    VG_(details_name)            ("Memtrace");
    VG_(details_version)         (NULL);
    VG_(details_description)     ("A memory tracing tool");
    VG_(details_copyright_author)(
      "Copyright (C) 2018, and GNU GPL'd, by Kr4t0n.");
    VG_(details_bug_reports_to)  (VG_BUGS_TO);
    VG_(details_avg_translation_sizeB) (330);

    VG_(basic_tool_funcs)          (mt_post_clo_init,
                                    mt_instrument,
                                    mt_fini);
    VG_(needs_command_line_options)(mt_process_cmd_line_option,
                                    mt_print_usage,
                                    mt_print_debug_usage);
    VG_(needs_malloc_replacement)  (mt_malloc,
                                    mt___builtin_new,
                                    mt___builtin_vec_new,
                                    mt_memalign,
                                    mt_calloc,
                                    mt_free,
                                    mt___builtin_delete,
                                    mt___builtin_vec_delete,
                                    mt_realloc,
                                    mt_malloc_usable_size,
                                    0);
    VG_(needs_libc_freeres)();
    VG_(needs_cxx_freeres)();

    HP_Chunk_alloc_pool = VG_(newPA)
        (sizeof(HP_Chunk),
         1000,
         VG_(malloc),
         "memtrace allocation pool",
         VG_(free));
    allocaiton_list = VG_(HT_construct)("memtrace allocation list");
}

VG_DETERMINE_INTERFACE_VERSION(mt_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                mt_main.c ---*/
/*--------------------------------------------------------------------*/