/* Mode: -*- C++ -*- */
// vim: set ai ts=4 sw=4 expandtab
/* @BC
 *		                Copyright (c) 1993
 *	    by Microelectronics and Computer Technology Corporation (MCC)
 *                                      and
 *		                Copyright (c) 1996
 *	                      by Rosette WebWorks Inc.
 *				All Rights Reserved
 *
 *	Permission to use, copy, modify, and distribute this software and its
 *	documentation for any purpose and without fee is hereby granted,
 *	provided that this notice be retained unaltered, and that the name of
 *	RWI or MCC and its shareholders and participants shall not be used in
 *	advertising or publicity pertaining to distribution of the software
 *	without specific written prior permission.
 *
 *	THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *	IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if !defined(_RBL_NewSpace_h)
#define _RBL_NewSpace_h

#include "Ob.h"
#include "ObStk.h"

class Space {
    private:
        // The address of the beginning of the space.
        void* const base;

        // The address of the end of the space.
        void* const limit;

        // The dividing line between allocated and free.
        void* next;

    public:
        Space(void*, unsigned);

        void reset();
        void* alloc(unsigned);
        void free(Ob*);
        int size();
        bool contains(Ob*);
        void scan();
        void check();
};

class RememberedSet : public ObStk {
    void reallyRemember(Ob*);

   public:
    void scan();
    void remember(Ob*);
};

class NewSpace : public Space {
    private:
        Space* const infants;
        Space* survivors;
        Space* pastSurvivors;
        RememberedSet* const rememberedSet;

    public:
        NewSpace(unsigned, unsigned);
        ~NewSpace();

        void* alloc(unsigned);
        void scavenge();
        void scan();
        void check();
        void remember(Ob*);
};

#endif
