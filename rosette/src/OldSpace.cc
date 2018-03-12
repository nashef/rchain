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
#include "OldSpace.h"
#include "Heap.h"

#include <utility>

using namespace std;


void OldSpace::scan() {
    for (auto it: chunks_) {
        auto p = it.first;
        if (MARKED(p)) {
            REMOVE_FLAG(HDR_FLAGS(p), f_marked);
        } else {
            free(p);
        }
    }
}

OldSpace::~OldSpace() {
    for (auto it: chunks_) {
        auto p = it.first;
        ::free(p);
    }
}

bool OldSpace::contains(Ob* p) {
    return chunks_.find(p) != chunks_.end();
}


size_t OldSpace::size() {
    size_t s = 0;
    for (auto it: chunks_) {
        s += it.second;
    }

    return s;
}

size_t OldSpace::chunks() {
    return chunks_.size();
}


void* OldSpace::alloc(unsigned sz) {
    auto p = (Ob*)calloc(1, sz);

    if (NULL == p) {
        fprintf(stderr, "OldSpace: Out of memory: malloc failed: %s\n",
                strerror(errno));
        abort();
    }

    chunks_.insert(make_pair(p, sz));
    return p;
}


void OldSpace::free(Ob* p) {
    auto it = chunks_.find(p);
    if (chunks_.end() == it) {
        return;
    }

    chunks_.erase(it);
    ::free(it->first);
    return;
}



