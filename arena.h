#include <sys/cdefs.h>

#ifndef _ARENA_H_
#define _ARENA_H_

#include <stddef.h>

__BEGIN_DECLS

struct arena {
    struct arena *next;
    void *data;
    size_t allocated, final_allocated, pos, count;
};

/*
 * difference between allocated and final_allocated is that final_allocated
 * must not change! you can decrease and increase the value of allocated to
 * add your own context data BUT it MUST NEVER be higher than final_allocated
 */

struct arena arena_init(size_t size);
void arena_reset(struct arena *arena);
void arena_deinit(struct arena *arena);

void *arena_alloc(struct arena *arena, size_t size);

__END_DECLS

#endif
