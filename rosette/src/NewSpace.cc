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
#include "PtrCollect.h"
#include "misc.h"

#include <memory.h>
#ifdef MIPS_SGI_SYSV
#include <sys/types.h>
#include <sys/immu.h>
#endif

class SpaceTrav {
    Space* sp;
    void* current;

   public:
    SpaceTrav(Space*);

    bool valid();
    Ob* get();
    void advance();

    operator void*();
};

SpaceTrav::SpaceTrav(Space* space) {
    sp = space;
    current = sp->base;
}

bool SpaceTrav::valid() {
    return current < sp->next;
}

Ob* SpaceTrav::get() {
    return (Ob*)current;
}

void SpaceTrav::advance() {
    current = (char*)current + SIZE((Ob*)current);
}

SpaceTrav::operator void*() {
    return valid() ? this : NULL;
}


Space::Space(void* b, unsigned sz) : base(b), limit((char*)b + sz) {
    if (b == 0) {
        perror("heap allocation");
        exit(1);
    }
    next = b;
}


void Space::reset() { next = base; }


int Space::size() { return ((char*)limit - (char*)base); }


void Space::free(Ob* p) {
    if (!FREED(p)) {
        SET_FLAG(HDR_FLAGS(p), f_freed);
        if (FOREIGN(p) && !FORWARDED(p)) {
            p->Ob::~Ob();
        }
    }
}


void* Space::alloc(unsigned sz) {
    register void* current = next;
    register void* temp = (char*)current + sz;

    if (temp <= limit) {
        next = temp;
        return current;
    }

    return 0;
}


bool Space::contains(Ob* p) { return (base <= (void*)p) && ((void*)p < limit); }


void Space::scan() {
    for (SpaceTrav st(this); st; st.advance()) {
        Ob* p = st.get();
        if (MARKED(p)) {
            REMOVE_FLAG(HDR_FLAGS(p), f_marked);
        } else {
            free(p);
        }
    }
}


void Space::check() {
    for (SpaceTrav st(this); st; st.advance()) {
        st.get()->check();
    }
}


/*
 * Every NewSpace has a RememberedSet that holds pointers to objects in
 * older spaces that contain references to objects in the NewSpace.  The
 * RememberedSet is updated whenever a pointer to a young (new) object is
 * stored into an older object.  It may be compacted during scavenging.
 */

void RememberedSet::scan() {
    for (PtrCollectionTrav pct(this); pct; pct.advance()) {
        void*& p = pct.get();
        if (!MARKED((Ob*)p)) {
            REMOVE_FLAG(HDR_FLAGS(((Ob*)p)), f_remembered);
            p = NULL;
        }
    }

    compact();
}


void RememberedSet::reallyRemember(Ob* p) {
    add(p);
    SET_FLAG(HDR_FLAGS(p), f_remembered);
}


void RememberedSet::remember(Ob* p) {
    if (!REMEMBERED(p)) {
        reallyRemember(p);
    }
}



NewSpace::NewSpace(unsigned isize, unsigned ssize)
    : Space((void*)valloc(isize + 2 * ssize), isize + 2 * ssize),
      infants(new Space((char*)base + 2 * ssize, isize)),
      survivors(new Space((char*)base + ssize, ssize)),
      pastSurvivors(new Space(base, ssize)),
      rememberedSet(new RememberedSet) {
    /*
     * The NewSpace is allocated as one big chunk (the call to valloc
     * above), and that chunk is divided into three regions: an infant
     * space and two survivor spaces.  The initializations above rely on
     * the fact that the base and limit member variables of the NewSpace
     * are inititialized by the implicit superclass (Space) constructor
     * call before the initializations of infants et al take place.
     */
}


NewSpace::~NewSpace() { ::free(base); }


void* NewSpace::alloc(unsigned sz) { return infants->alloc(sz); }


void NewSpace::scavenge() {
    PtrCollectionTrav rst(rememberedSet);
    SpaceTrav st(survivors);

    /*
     * Scavenging the rememberedSet can cause more Ob's to be moved (via
     * copyAndForward) to the survivor space.  Similarly, scavenging the
     * survivor space can cause more objects to be remembered.
     *
     * This loop can probably be sped up significantly by ditching the
     * Trav's.  Since this is the heart of the scavenger, it's probably
     * worthwhile to break the encapsulation here.
     */

    while (true) {
        while (rst) {
            void*& rp = rst.get();
            Ob* p = (Ob*)rp;

            if (p->traversePtrs(MF_ADDR(Ob::relocate)) == 0) {
                /*
                 * traversePtrs() returns the number of pointers within
                 * *p that still point into new space.  If there are
                 * none, there is no point in keeping this p in the
                 * remembered set.
                 */
                REMOVE_FLAG(HDR_FLAGS(p), f_remembered);
                rp = NULL;
            }
            rst.advance();
        }

        /*
         * At this point we know that everything in the remembered set
         * has been traversed.  If there is nothing new in the survivor
         * space, then there is nothing left to be scavenged and we get
         * out.
         */

        if (!st) {
            break;
        }

        do {
            Ob* p = (Ob*)st.get();
            if (!FREED(p)) {
                p->traversePtrs(MF_ADDR(Ob::relocate));
            }
            st.advance();
        } while (st);
    }

    rememberedSet->compact();

    /*
     * Swap the roles of the survivor spaces.
     */
    Space* tmp = survivors;
    survivors = pastSurvivors;
    pastSurvivors = tmp;

    infants->reset();
    survivors->reset();
}


void NewSpace::scan() {
    /*
     * It is imperative that the remembered set be scanned first, since
     * it decides whether to eliminate entries based on whether they are
     * marked or not.  It it is not scanned first, entries may be
     * incorrectly eliminated.
     */

    rememberedSet->scan();
    infants->scan();
    survivors->scan();
    pastSurvivors->scan();
}


void NewSpace::check() {
    rememberedSet->check();
    infants->check();
    survivors->check();
    pastSurvivors->check();
}


void NewSpace::remember(Ob* p) { rememberedSet->remember(p); }

