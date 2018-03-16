/* Mode: -*- C++ -*- */
// vim: set ai ts=4 sw=4 expandtab
/* @BC
 *		                Copyright (c) 1993
 *	    by Microelectronics and Computer Technology Corporation (MCC)
 *				All Rights Reserved
 *
 *	Permission to use, copy, modify, and distribute this software and its
 *	documentation for any purpose and without fee is hereby granted,
 *	provided that this notice be retained unaltered, and that the name of
 *	MCC and its shareholders and participants shall not be used in
 *	advertising or publicity pertaining to distribution of the software
 *	without specific written prior permission.
 *
 *	THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *	IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "rosette.h"
#include "BinaryOb.h"
#include "CommandLine.h"
#include "Ctxt.h"
#include "Heap.h"
#include "ObStk.h"
#include "misc.h"

#include <memory.h>
#ifdef MIPS_SGI_SYSV
#include <sys/types.h>
#include <sys/immu.h>
#endif


/*
 * valloc doesn't appear to be declared in everyone's <stdlib.h>.
 */

#if defined(MALLOC_DEBUGGING)
extern "C" {
int malloc_verify();
}
#endif

static const int MaxFixedSize = sizeof(Ctxt);

int align(int size) { return ((size + alignmentmask) & ~alignmentmask); }


/*
 * The heap management code for RBL.  This is a two-tiered management
 * strategy for allocation and reclamation of heap-resident objects.
 *
 * The first tier is a generation-scavenging system adapted from the one
 * presented by Ungar in "Generaton Scavenging: A Non-disruptive High
 * Performance Storage Reclamation Algorithm" in the Proceedings of the
 * 1984 ACM SIGSOFT/SIGPLAN Software Engineering Symposium on Practical
 * Software Development Environments (issued as the May 1984 issue of
 * SIGPLAN Notices).  This scheme relies on the property that most
 * objects die young, and that those that don't tend to live a long time.
 * This is exploited by partitioning the heap into four spaces: an infant
 * space, two survivor spaces, and an old space.  (We refer to the
 * combination of the infant space and the two survivor spaces as the new
 * space.)  New objects are allocated out of the infant space until it is
 * exhausted, at which point a scavenge is undertaken.
 *
 * The scavenge moves all reachable objects from infant space (and one of
 * the survivor spaces) into the other survivor space (or possibly the
 * old space).  After the scavenge, there are no reachable objects in the
 * infant space or the first survivor space, so they can be reused
 * without scanning.  Thus, the cost of the scavenge is proportional only
 * to the number of objects *IN NEW SPACE* that are reachable.  It does
 * *NOT* depend on the number of objects in old space or the amount of
 * garbage in new space.
 *
 * An object is reachable if it is pointed to from the RBL runtime stack
 * or from an old space object, or if it is pointed to by a reachable
 * object (transitive closure).  The set of old objects that point to new
 * objects (objects in either infant space or survivor space) is
 * maintained in the heap's rememberedSet.  Proper maintenance of this
 * set requires that all stores into heap-resident objects be monitored:
 * whenever a pointer to a new object is written into an old object, the
 * address of that old object is added to the rememberedSet.
 *
 * Objects that survive enough scavenges are promoted (tenured) to old
 * space, so that they needn't be scavenged again after tenuring.  We
 * currently use a constant tenuring threshold; the system can be tuned
 * by using more sophisticated techniques as described by Ungar and
 * Jackson in "Tenuring Policies for Generation-Based Storage
 * Reclamation" in the 1988 OOPSLA Proceedings (issued as the November
 * 1988 issue of SIGPLAN Notices).
 *
 * We have incorporated an adaptation of one of the improvements
 * suggested by Ungar and Jackson: we provide primitive support for
 * "foreign objects", objects that are allocated out of the C++ heap
 * rather than the RBL heap.  This allows us to allocate such things as
 * large bitmaps, etc., so that they don't occupy valuable RBL heap space
 * and still have them properly garbage-collected.  The exact mechanism
 * is described later.
 *
 * The second tier of the system is based on the Quick Fit system
 * described by Weinstock and Wulf in "An Efficient Algorithm for Heap
 * Storage Allocation" in the October, 1988 issue of SIGPLAN Notices.
 * Old space is divided into two parts: that which has been allocated in
 * the past (and possibly reclaimed), and that which has never been
 * allocated (called the tail).  An array of free lists is maintained for
 * a small number of fixed chunk sizes: each free list holds chunks of a
 * specific size (the free list array is indexed by chunk size).  The
 * basic allocation scheme is:
 *
 * 1. If the request is for one of the fixed chunk sizes, and the
 * relevant free list is not empty, remove the the chunk from the free
 * list and return its address.
 *
 * 2. Otherwise, if there is enough room on the tail to satisfy the
 * request, increment the tail pointer by the requested amount and return
 * its pre-incremented value.
 *
 * 3. Otherwise, perform a traditional mark/scan garbage collection to
 * recover lost storage, and try steps 1 and 2 again.
 *
 * 4. If there is still not enough storage available, obtain a new tail
 * from the system and allocate the chunk from it.
 *
 * When objects are freed, their storage is returned to the appropriate
 * free list: the size-specific free list if the storage is one of the
 * special sizes, or the miscellaneous free list otherwise.  No attempt
 * is currently made to coalesce contiguous regions of memory when they
 * are freed.
 *
 * The mark/scan garbage collection has a couple of additional twists to
 * incorporate foreign objects and the scavenger's remembered set.  The
 * marking phase is traditional, marking all nodes reachable from the RBL
 * runtime stack.
 */



void RootSet::preScavenge() {}
void RootSet::scavenge() {}
void RootSet::postScavenge() {}
void RootSet::preGC() {}
void RootSet::mark() {}
void RootSet::postGC() {}
void RootSet::check() {}




class ForeignObTbl : public ObStk {
   public:
    void scavenge();
    void scan();
};


void ForeignObTbl::scavenge() {
    /*
     * In a scavenge, any foreign object that has been forwarded (which
     * means it is now necessarily in either survivorSpace or oldSpace)
     * is assumed to survive.  Objects that have been tenured in oldSpace
     * are removed from the table; once they move to oldSpace they can
     * only be recovered by the scan phase of a full-fledged garbage
     * collection, so there is no point in keeping a record of them in
     * this table.  Anything that has not been forwarded is assumed to be
     * garbage and is deleted and its table slot reused.
     */

    for (PtrCollectionTrav pct(this); pct; pct.advance()) {
        Ob* p = (Ob*)pct.get();
        if (FORWARDED(p)) {
            p = p->forwardingAddress();
            pct.get() = IS_OLD(p) ? NULL : p;
        } else {
            p->Ob::~Ob();
            pct.get() = NULL;
        }
    }
    compact();
}


void ForeignObTbl::scan() {
    /*
     * Any foreign object that has not been marked is assumed to be
     * garbage, and the reference to it is deleted and its table slot
     * reused.  We do not deallocate the objects that we are forgetting,
     * since that will be accomplished during the rest of the scan (doing
     * it here would lead to a double deallocation).
     */

    for (PtrCollectionTrav pct(this); pct; pct.advance()) {
        void*& p = pct.get();
        Ob* h = (Ob*)p;
        if (!MARKED(h)) {
            p = NULL;
        }
    }

    compact();
}


class GCAgenda : public ObStk {
   public:
    void scavenge();
    void scan();
};


void GCAgenda::scavenge() {
    /*
     * scavengeFixup should return TRUE if an object is to remain on the
     * gcAgenda after the fixup.  If FALSE is returned, the object will
     * be removed from the gcAgenda and will have to cause itself to be
     * re-installed later if so required.
     */
    for (PtrCollectionTrav pct(this); pct; pct.advance()) {
        void*& p = pct.get();
        Ob* h = (Ob*)p;
        if (FORWARDED(h)) {
            h = h->forwardingAddress();
            p = h->scavengeFixup() ? h : NULL;
        } else if (!IS_OLD(h) || !h->scavengeFixup()) {
            p = NULL;
        }
    }
    compact();
}


void GCAgenda::scan() {
    /*
     * Unmarked objects are unconditionally deleted from the gcAgenda.
     * Marked objects will be removed from the gcAgenda if they respond
     * FALSE to gcFixup.
     */
    for (PtrCollectionTrav pcct(this); pcct; pcct.advance()) {
        void*& p = pcct.get();
        Ob* h = (Ob*)p;
        if (!MARKED(h) || !h->gcFixup()) {
            p = NULL;
        }
    }
    compact();
}


Heap* heap;


Heap::Heap(unsigned infantSpaceSize, unsigned survivorSpaceSize,
           unsigned oldSpaceChunkSize)
    : newSpace(new NewSpace(infantSpaceSize, survivorSpaceSize)),
      oldSpace(new OldSpace(oldSpaceChunkSize)),
      foreignObs(new ForeignObTbl),
      gcAgenda(new GCAgenda),
      tenuredObs(new ObStk),
      rootSets(new PtrCollection),
      newSpaceBase(newSpace->base),
      newSpaceLimit(newSpace->limit) {
    scavengeCount = 0;
    gcCount = 0;
    totalScavenges = 0;
    totalGCs = 0;
}


Heap::~Heap() {
    delete newSpace;
    delete oldSpace;
    delete foreignObs;
    delete gcAgenda;
    delete rootSets;
    delete tenuredObs;
}


void Heap::traverseRootSets(RootSet_Fn fn) {
    for (PtrCollectionTrav pct(rootSets); pct; pct.advance()) {
        RootSet* rs = (RootSet*)pct.get();
        (rs->*fn)();
    }
}


void Heap::addRootSet(RootSet* rs) { rootSets->add(rs); }


void Heap::deleteRootSet(RootSet* rs) {
    for (PtrCollectionTrav pct(rootSets); pct; pct.advance()) {
        if (rs == pct.get()) {
            pct.get() = NULL;
            rootSets->compact();
            return;
        }
    }

    suicide("tried to delete non-existent root set");
}


int Heap::size() { return newSpace->size() + oldSpace->size(); }


/*
 * magicLoc and catchMagic can prove to be invaluable during debugging.
 * If a location is getting clobbered by a stray pointer, you can use a
 * debugger to set magicLoc to determine when it is allocated and trap on
 * entry to catchMagic.  This is tremendously faster than setting
 * debugger breakpoints.
 */

#ifdef DEBUG
static void catchMagic() {}
#endif

void* Heap::alloc(unsigned sz) {
    void* loc = newSpace->alloc(sz);
#ifdef DEBUG
    if (loc == magicLoc) {
        catchMagic();
    }
#endif
    return loc;
}


void* Heap::scavengeAndAlloc(unsigned sz) {
    scavenge();
    void* loc = alloc(sz);
    if (!loc) {
        suicide("scavengeAndAlloc -- out of space");
    }

    return loc;
}


void Heap::remember(Ob* p) {
    /*
     * Heap::remember (as well as NewSpace::remember and
     * RememberedSet::remember) assumes that the argument is in fact a
     * valid pointer (i.e., not a fixnum or some other nonsense).  This
     * must be guaranteed by the caller.
     */
    newSpace->remember(p);
}


Ob* Heap::copyAndForward(Ob* oldLoc) {
    Ob* newLoc = 0;

#ifdef DEBUG
    assert(!FORWARDED(oldLoc));
#endif

    if (AGE(oldLoc) < TenuringAge) {
        AGE(oldLoc)++;
        newLoc = (Ob*)newSpace->survivors->alloc(SIZE(oldLoc));
    }

    if (newLoc == 0) {
        newLoc = (Ob*)oldSpace->alloc(SIZE(oldLoc));
        oldLoc->forwardTo(newLoc);
        remember(newLoc);
        /*
         * The call to remember() *must* be made *after* the call to
         * forwardTo() because remember() sets a header bit that
         * forwardTo() clobbers.
         */
    } else {
        oldLoc->forwardTo(newLoc);
    }

    return newLoc;
}


void Heap::scavenge() {
    auto const starting_old_chunks = oldSpace->chunks();

    traverseRootSets(MF_ADDR(RootSet::preScavenge));

    /*
     * The order of scavenging here is important.  In particular, the
     * root sets need to be scavenged first, since they hold the roots of
     * the reachable objects, and the foreignObTbl needs to be scavenged
     * *LAST*, since it decides to deallocate foreign obs based on
     * whether or not they have been forwarded during scavenging.
     */

    traverseRootSets(MF_ADDR(RootSet::scavenge));
    ProtectedItem::scavenge();

    /*
     * There is no need to scavenge the tenured objects since they are
     * (by definition) all in old space.
     */

    newSpace->scavenge();
    gcAgenda->scavenge();
    foreignObs->scavenge();

    if (ParanoidAboutGC) {
        traverseRootSets(MF_ADDR(RootSet::check));
        ProtectedItem::check();
        tenuredObs->check();

        newSpace->check();
        // NB(leaf): I can't tell what check() is doing... :-(
        //oldSpace->check();
        foreignObs->check();
        gcAgenda->check();

#if defined(MALLOC_DEBUGGING)
        if (!malloc_verify()) {
            suicide("Heap::scavenge -- malloc_verify found a problem");
        }
#endif
    }

    scavengeCount++;

    traverseRootSets(MF_ADDR(RootSet::postScavenge));

    /*
     * If scavenging forced us to add new chunks to old space, we perform
     * a GC after the fact to look for unnecessarily tenured objects.
     */

    if (starting_old_chunks != oldSpace->chunks()) {
        gc();
    }
}


int nMarked;


void Heap::gc() {
    traverseRootSets(MF_ADDR(RootSet::preGC));

    nMarked = 0;

    traverseRootSets(MF_ADDR(RootSet::mark));
    ProtectedItem::mark();
    tenuredObs->mark();

    /*
     * The order in which we do these scans is *EXTREMELY* important:
     * since the foreignObTbl and gcAgenda eliminate those entries that
     * have not been marked, they *MUST* perform their scans before any
     * of the other scans that might reset those mark bits.  Similarly,
     * since newSpace checks its RememberedSet (whose entries all point
     * into oldSpace) and deletes those that are not marked, it must
     * perform its scan prior to the oldSpace scan.
     */

    foreignObs->scan();
    gcAgenda->scan();
    newSpace->scan();
    oldSpace->scan();

    gcCount++;

    traverseRootSets(MF_ADDR(RootSet::postGC));
}


Ob* Heap::tenure(Ob* o) {
    if (!IS_PTR(o)) {
        return o;
    }

    AGE(o) = TenuringAge;
    Ob* newLoc = copyAndForward(o);
    if (FOREIGN(o)) {
        foreignObs->scavenge();
    }

    tenuredObs->add(newLoc);

    return newLoc;
}


void Heap::tenureEverything() {
    gc();
    int tempTenuringAge = TenuringAge;
    TenuringAge = 0;
    scavenge();
    TenuringAge = tempTenuringAge;
}


bool Heap::validPtrAfterScavenge(Ob* p) {
    return newSpace->pastSurvivors->contains(p) || !newSpace->contains(p);
}


void Heap::registerForeignOb(Ob* p) {
    SET_FLAG(HDR_FLAGS(p), f_foreign);
    foreignObs->add(p);
}


void Heap::registerGCAgenda(Ob* p) { gcAgenda->add(p); }


void Heap::resetCounts() {
    totalScavenges += scavengeCount;
    scavengeCount = 0;
    totalGCs += gcCount;
    gcCount = 0;
}


void Heap::printCounts(FILE* f) {
    fprintf(f, "heap: %d/%d scavenges, %d/%d garbage collects\n", scavengeCount,
            scavengeCount + totalScavenges, gcCount, gcCount + totalGCs);
}


ProtectedItem* ProtectedItem::root = 0;


void ProtectedItem::scavenge() {
    for (ProtectedItem* pi = ProtectedItem::root; pi; pi = pi->next) {
        pOb* p = (pOb*)(pi->item);
        useIfPtr(p, MF_ADDR(Ob::relocate));
    }
}


void ProtectedItem::mark() {
    for (ProtectedItem* pi = ProtectedItem::root; pi; pi = pi->next) {
        pOb* p = (pOb*)(pi->item);
        useIfPtr(*p, MF_ADDR(Ob::mark));
    }
}


void ProtectedItem::check() {
    for (ProtectedItem* pi = ProtectedItem::root; pi; pi = pi->next) {
        pOb* p = (pOb*)(pi->item);
        useIfPtr(*p, MF_ADDR(Ob::checkOb));
    }
}


Ob* Ob::relocate() {
    if (DebugFlag) {
        fprintf(stderr, "Ob::relocate: relocating 0x%x...\n", (uintptr_t) this);
    }

    /*
     * NB: This routine depends critically upon the relative ordering of the
     * old space, the infant space and the past survivor space:
     *
     * 	past survivor addresses < infant addresses < old space addresses
     *
     * If that ordering changes, this code had better change as well.
     */

    if (FREED(this)) {
        warning("relocate called on freed %s", typestring());
        return (Ob*)INVALID;
    }

    if ((void*)this >= heap->newSpace->limit) {
        if (DebugFlag) {
            fprintf(stderr,
                    "Ob::relocate: this not in newSpace: "
                    "this(0x%x) >= newSpace->limit(0x%x)\n ",
                    (uintptr_t) this, (uintptr_t)heap->newSpace->limit);
        }

        return this;
    }

    if ((void*)this >= heap->newSpace->infants->base) {
        if (DebugFlag) {
            fprintf(stderr,
                    "Ob::relocate: "
                    "this(0x%x) >= newSpace->limit->base(0x%x)\n ",
                    (uintptr_t) this, (uintptr_t)heap->newSpace->infants->base);
        }

        return this;
    }

    if ((void*)this < heap->newSpace->pastSurvivors->base) {
        if (DebugFlag) {
            fprintf(stderr,
                    "Ob::relocate: "
                    "this(0x%x) >= newSpace->pastSurvivors->base(0x%x)\n ",
                    (uintptr_t) this,
                    (uintptr_t)heap->newSpace->pastSurvivors->base);
        }

        return this;
    }

    if ((void*)this < heap->newSpace->pastSurvivors->limit) {
        if (DebugFlag) {
            fprintf(stderr,
                    "Ob::relocate: "
                    "this(0x%x) >= newSpace->pastSurvivors->limit(0x%x)\n ",
                    (uintptr_t) this,
                    (uintptr_t)heap->newSpace->pastSurvivors->limit);
        }
        if (FORWARDED(this)) {
            return forwardingAddress();
        } else {
            return heap->copyAndForward(this);
        }
    }

    fprintf(stderr,
            "Ob::relocate: reached relocation checks without "
            "a decision. Not relocating 0x%x\n",
            (uintptr_t) this);
    return this;
}


void* palloc(unsigned sz) {
    void* loc = heap->alloc(sz);
    return loc ? loc : heap->scavengeAndAlloc(sz);
}


void* palloc1(unsigned sz, void* ob0) {
    ProtectedItem pob0(ob0);
    return palloc(sz);
}


void* palloc2(unsigned sz, void* ob0, void* ob1) {
    ProtectedItem pob1(ob1);
    return palloc1(sz, ob0);
}


void* palloc3(unsigned sz, void* ob0, void* ob1, void* ob2) {
    ProtectedItem pob2(ob2);
    return palloc2(sz, ob0, ob1);
}


void* palloc4(unsigned sz, void* ob0, void* ob1, void* ob2, void* ob3) {
    ProtectedItem pob3(ob3);
    return palloc3(sz, ob0, ob1, ob2);
}


void* palloc5(unsigned sz, void* ob0, void* ob1, void* ob2, void* ob3,
              void* ob4) {
    ProtectedItem pob4(ob4);
    return palloc4(sz, ob0, ob1, ob2, ob3);
}


void* palloc6(unsigned sz, void* ob0, void* ob1, void* ob2, void* ob3,
              void* ob4, void* ob5) {
    ProtectedItem pob5(ob5);
    return palloc5(sz, ob0, ob1, ob2, ob3, ob4);
}
