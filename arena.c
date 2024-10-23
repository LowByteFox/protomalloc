#include "arena.h"
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

#define PGSIZE 4096
#warning PGSIZE must not exist!

#define align(x, align) (((x) + (align) - 1) & ~((align) - 1))

struct arena arena_init(size_t size)
{
    struct arena a = { 0 };

    size_t aligned = align(size + sizeof(a), PGSIZE);

    a.data = mmap(NULL, aligned, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a.data == MAP_FAILED) {
        errno = ENOMEM;
        return a;
    }

    a.allocated = aligned - sizeof(a); /* just so it fits at the end */
    a.final_allocated = a.allocated;

    return a;
}

void arena_deinit(struct arena *arena)
{
    if (arena->next != NULL)
        arena_deinit(arena->next);

    munmap(arena->data, arena->final_allocated + sizeof(*arena));

    arena->allocated = 0;
    arena->final_allocated = 0;
    arena->pos = 0;
    arena->count = 0;
    arena->data = NULL;
    arena->next = NULL;
}

void arena_reset(struct arena *arena)
{
    if (arena->next != NULL)
        arena_reset(arena->next);

    arena->pos = 0;
    arena->count = 0;
}

void *arena_alloc(struct arena *arena, size_t size)
{
    if (arena->next != NULL && arena->pos + size > arena->allocated)
        arena_alloc(arena->next, size);
    else {
        if (arena->allocated == 0)
            return NULL;

        uint8_t* ptr = arena->data;
        if (arena->pos + size > arena->allocated) {
            if (arena->next != NULL)
                return arena_alloc(arena->next, size);

            arena->next = (void*) ptr + arena->final_allocated;
            *(arena->next) = arena_init(arena->final_allocated);
            if (arena->next == NULL)
                return NULL;

            return arena_alloc(arena->next, size);
        }

        void *data = ptr + arena->pos;
        arena->pos += size;
        arena->count++;
        return data;
    }

    return NULL;
}
