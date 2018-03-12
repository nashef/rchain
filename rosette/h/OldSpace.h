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
#if !defined(_RBL_OldSpace_h)
#define _RBL_OldSpace_h

#include "Ob.h"
#include <map>

class OldSpace;

class OldSpace {
   private:
    Ob* currentChunk;
    std::map<Ob*, size_t> chunks_;

    void* miscAlloc(unsigned);
    void resetFreeLists();
    void checkFreeLists(char*);

    friend class Heap;

   public:
    OldSpace(unsigned) {};
    OldSpace() {};
    ~OldSpace();

    void* alloc(unsigned);
    void free(Ob*);
    bool contains(Ob*);

    size_t size();
    size_t chunks();

    void scan();
};

#endif
