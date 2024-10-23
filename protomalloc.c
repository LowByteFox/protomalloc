#ifdef _PROTOLIBC
#include <arena.h>
#else
#include "arena.h"
#include "protomalloc.h"
#include "protoerrno.h"
#endif

#include <sys/cdefs.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

/* WARN: malloc needs to be thread-safe, implement after threads! */

#define JUNK_VALUE 0xAA
#define CANARY_SIZE 128

#define PGSIZE 4096
#define align(x, align) (((x) + (align) - 1) & ~((align) - 1))

#define MEDIUM_SIZE 4096
#define LARGE_SIZE  8192

struct malloc_header {
    ssize_t usable_size;
};

struct huge_alloc_list {
    struct malloc_header *prev;
    struct malloc_header *next;
};

struct alloc_pool {
    struct arena arena;
    struct arena *tail;
};

struct huge_alloc_pool {
    struct malloc_header *first;
    struct malloc_header *tail;
};

enum pools {
    MEDIUM,
    LARGE,
    HUGE
};

enum flags {
    CANARIES = 1,
    DUMP_CONTENT = 1 << 1,
    FREECHECK = 1 << 2,
    JUNKING = 1 << 3,
    VERBOSE = 1 << 4,
    XMALLOC = 1 << 5
};

/* context vars */
const char *malloc_options = NULL;

static uint8_t alloc_flags;
static bool initialized = false;
static struct arena *found_arena = NULL;

/* alloc pools */
static struct alloc_pool medium_pool;
static struct alloc_pool large_pool;
static struct huge_alloc_pool huge_pool;

/* freed blocks list functions */
static void init_free_list(struct arena *arena);
static size_t free_list_count(struct arena *arena);
static void free_list_incr(struct arena *arena);
static void free_list_push(struct arena *arena, void *block);
static void free_list_rm(struct arena *arena, void *block);
static void *free_list_get(struct arena *arena);

/* functions */
static void malloc_warn(const char *fmt, ...);
static void malloc_err(const char *fmt, ...);
static void check_canary(void *ptr);
static void fastfree(void *ptr);
static void dump_memory_info();
static void malloc_init();
static void update_tail(struct alloc_pool *pool);
static bool is_pointer_valid(void *ptr);
static void *find_free_block(size_t size, enum pools pool);

/* huge allocations helper functions */
static void *huge_alloc(size_t size);
static struct huge_alloc_list *get_list(struct malloc_header *header);
static void huge_alloc_rm(struct malloc_header *header);

/* TODO: When err and warn functions are implemented */
static void malloc_warn(const char *fmt, ...)
{
#ifdef __PROTOGEN
    fprintf(stderr, "%s: ", getprogname());
#endif

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, (char *) fmt, args);
    va_end(args);
}

static void malloc_err(const char *fmt, ...)
{
#ifdef __PROTOGEN
    fprintf(stderr, "%s: ", getprogname());
#endif

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, (char *) fmt, args);
    va_end(args);
    abort();
}

void *malloc(size_t size)
{
    if (!initialized)
        malloc_init();

    ssize_t size_check = size;
    if (size_check < 0) {
        if (alloc_flags & FREECHECK) {
            errno = EINVSIZE;
            return NULL;
        } else
            malloc_err("malloc(): invalid size");
    }

    if (size == 0)
        return NULL;

    if (size < MEDIUM_SIZE) {
        void *block = find_free_block(size, MEDIUM);

        if (block != NULL && alloc_flags & VERBOSE)
            malloc_warn("find(%ld) = %p\n", size, block);

        if (block == NULL)
            return fastmalloc(size);
        else
            return block;
    } else if (size < LARGE_SIZE) {
        void *block = find_free_block(size, LARGE);

        if (block != NULL && alloc_flags & VERBOSE)
            malloc_warn("find(%ld) = %p\n", size, block);

        if (block == NULL)
            return fastmalloc(size);
        else 
            return block;
    } else {
        return fastmalloc(size);
    }

    return NULL;
}

void *fastmalloc(size_t size)
{
    if (!initialized)
        malloc_init();

    if (size < MEDIUM_SIZE) {
        struct malloc_header head = {0};

        /* a canary is part of the allocation */
        if (alloc_flags & CANARIES)
            size += CANARY_SIZE;

        size_t to_alloc = align(size + sizeof(head), 8);
        head.usable_size = to_alloc - sizeof(head);

        /* just to be safe, lie to arena */
        medium_pool.tail->allocated -= sizeof(void*);

        void *ptr = arena_alloc(medium_pool.tail, to_alloc);

        /* don't let the user know */
        if (alloc_flags & CANARIES) {
            head.usable_size -= CANARY_SIZE;
            size -= CANARY_SIZE;
        }

        if (ptr == NULL && alloc_flags & XMALLOC)
            malloc_err("malloc(): Out Of Memory");

        if (ptr == NULL && alloc_flags & FREECHECK) {
            errno = ENOMEM;
            return NULL;
        }

        /* no need to lie */ 
        medium_pool.tail->allocated += sizeof(void*);

        /* check if next is defined */
        if (medium_pool.tail->next != NULL)
            init_free_list(medium_pool.tail->next);

        update_tail(&medium_pool);

        free_list_incr(medium_pool.tail);

        void *off = ((uint8_t *) ptr) + sizeof(head);
        *(struct malloc_header*) ptr = head;

        if (alloc_flags & JUNKING)
            memset(off, JUNK_VALUE, size);

        if (alloc_flags & CANARIES)
            memset(off + size, 0, CANARY_SIZE);

        if (alloc_flags & VERBOSE)
            malloc_warn("malloc(%ld) at arena %p = %p\n",
                head.usable_size, medium_pool.tail, ptr);

        return off;
    } else if (size < LARGE_SIZE) {
        struct malloc_header head = {0};

        if (alloc_flags & CANARIES)
            size += CANARY_SIZE;

        size_t to_alloc = align(size + sizeof(head), 8);
        head.usable_size = to_alloc - sizeof(head);

        large_pool.tail->allocated -= sizeof(void*);

        void *ptr = arena_alloc(large_pool.tail, to_alloc);

        if (alloc_flags & CANARIES) {
            head.usable_size -= CANARY_SIZE;
            size -= CANARY_SIZE;
        }

        if (ptr == NULL && alloc_flags & XMALLOC)
            malloc_err("malloc(): Out Of Memory");

        if (ptr == NULL && alloc_flags & FREECHECK) {
            errno = ENOMEM;
            return NULL;
        }

        large_pool.tail->allocated += sizeof(void*);

        if (large_pool.tail->next != NULL)
            init_free_list(large_pool.tail->next);

        update_tail(&large_pool);

        void *off = ((uint8_t *) ptr) + sizeof(head);
        *(struct malloc_header*) ptr = head;

        if (alloc_flags & JUNKING)
            memset(off, JUNK_VALUE, size);

        if (alloc_flags & CANARIES)
            memset(off + size, 0, CANARY_SIZE);

        if (alloc_flags & VERBOSE)
            malloc_warn("malloc(%ld) at arena %p = %p\n",
                head.usable_size, large_pool.tail, ptr);

        return off;
    } else {
        return huge_alloc(size);
    }

    return NULL;
}

size_t malloc_usable_size(void *ptr)
{
    if (!initialized)
        malloc_init();

    if (!is_pointer_valid(ptr)) {
        if (alloc_flags & FREECHECK)
            errno = EINVPTR;

        return 0;
    }
    
    void *base = ((uint8_t*) ptr) - sizeof(struct malloc_header);
    struct malloc_header *header = base;
    if (header->usable_size < 0)
        return 0;

    return header->usable_size;
}

void free(void *ptr)
{
    if (!initialized)
        malloc_init();

    if (ptr == NULL)
        return;

    if (!is_pointer_valid(ptr)) {
        if (alloc_flags & FREECHECK) {
            errno = EINVPTR;
            return;
        } else
            malloc_err("free(): invalid pointer");
    }

    fastfree(ptr);
}

static void fastfree(void *ptr) {
    void *base = ((uint8_t*) ptr) - sizeof(struct malloc_header);
    struct malloc_header *header = base;
    if (header->usable_size < 0) {
        if (alloc_flags & FREECHECK) {
            errno = EDBLFREE;
            return;
        } else
            malloc_err("free(): double free detected");
    }

    if (header->usable_size >= LARGE_SIZE) {
        huge_alloc_rm(header);
        munmap(header, header->usable_size + sizeof(*header) +
            sizeof(struct huge_alloc_list));
    } else {
        /* check canary */
        if (alloc_flags & CANARIES) {
            base += sizeof(struct malloc_header) + header->usable_size;
            check_canary(base);
        }

        header->usable_size = -header->usable_size;


        /*
         * while there is free list, just to quickly detect double free
         * the size can be negative
         */
        free_list_push(found_arena, header);

        if (alloc_flags & VERBOSE)
            malloc_warn("free(%p) of size %ld at arena %p\n",
                    header, -header->usable_size, found_arena);
    }
}

void *realloc(void *ptr, size_t new_size)
{
    if (!initialized)
        malloc_init();

    ssize_t size_check = new_size;
    if (size_check < 0) {
        if (alloc_flags & FREECHECK) {
            errno = EINVSIZE;
            return NULL;
        } else
            malloc_err("realloc(): invalid size");
    }

    if (new_size == 0)
        return NULL;

    if (ptr == NULL)
        return malloc(new_size);

    if (!is_pointer_valid(ptr)) {
        if (alloc_flags & FREECHECK) {
            errno = EINVPTR;
            return NULL;
        } else
            malloc_err("realloc(): invalid pointer");
    }

    void *base = ((uint8_t*) ptr) - sizeof(struct malloc_header);
    struct malloc_header *header = base;

    if (header->usable_size < MEDIUM_SIZE || header->usable_size < LARGE_SIZE) {
        size_t old_alloc_size = header->usable_size + sizeof(*header);

        uint8_t *adj = found_arena->data;
        adj += found_arena->pos - old_alloc_size;

        /* last allocation detected */
        if (adj == (void*) header) {

            if (alloc_flags & CANARIES)
                new_size += CANARY_SIZE;

            size_t to_alloc = align(new_size + sizeof(*header), 8);
            size_t space_left = found_arena->allocated - found_arena->pos;

            if (to_alloc - old_alloc_size <= space_left) {
                /* can expand */
                found_arena->pos += to_alloc - old_alloc_size;
                header->usable_size = to_alloc - sizeof(*header);

                if (alloc_flags & CANARIES) {
                    header->usable_size -= CANARY_SIZE;
                    new_size -= CANARY_SIZE;
                }

                if (alloc_flags & CANARIES) {
                    base += sizeof(struct malloc_header) + header->usable_size;
                    memset(base, 0, CANARY_SIZE);
                }

                if (alloc_flags & VERBOSE)
                    malloc_warn("realloc(%p) of size %ld to size %ld = %p\n",
                        ptr, old_alloc_size - sizeof(*header),
                        header->usable_size, ptr);
                return ptr;
            } else {
                /* cannot expand */
                void *new = fastmalloc(new_size);
                memcpy(new, ptr, header->usable_size);
                fastfree(ptr);

                return new;
            }
        } else {
            void *new = fastmalloc(new_size);
            memcpy(new, ptr, header->usable_size);
            fastfree(ptr);

            return new;
        }
    } else {
        void *new = fastmalloc(new_size);
        memcpy(new, ptr, header->usable_size);
        fastfree(ptr);

        return new;
    }

    return NULL;
}

void *fastrealloc(void *ptr, size_t new_size)
{
    ssize_t size_check = new_size;
    if (size_check < 0) {
        if (alloc_flags & FREECHECK) {
            errno = EINVSIZE;
            return NULL;
        } else
            malloc_err("realloc(): invalid size");
    }

    if (new_size == 0)
        return NULL;

    void *base = ((uint8_t*) ptr) - sizeof(struct malloc_header);
    struct malloc_header *header = base;

    void *new = fastmalloc(new_size);
    memcpy(new, ptr, header->usable_size);
    fastfree(ptr);

    return new;
}

void *calloc(size_t nmemb, size_t size)
{
    size_t total = nmemb * size;
    void *ptr = malloc(total);

    if (ptr == NULL)
        return NULL;

    memset(ptr, 0, total);
    return ptr;
}

void *fastcalloc(size_t nmemb, size_t size)
{
    size_t total = nmemb * size;
    void *ptr = fastmalloc(total);

    if (ptr == NULL)
        return NULL;

    memset(ptr, 0, total);
    return ptr;
}

void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
    return realloc(ptr, nmemb * size);
}

void *recallocarray(void *ptr, size_t oldnmemb, size_t nmemb, size_t size)
{
    if (ptr == NULL)
        return calloc(nmemb, size);

    size_t total = nmemb * size;
    void *new = realloc(ptr, total);

    if (new == NULL)
        return NULL;

    uint8_t *adj = new;
    new += oldnmemb * size;

    memset(adj, 0, total - oldnmemb * size);

    return adj;
}

void freezero(void *ptr, size_t size)
{
    if (!initialized)
        malloc_init();

    if (!is_pointer_valid(ptr)) {
        if (alloc_flags & FREECHECK) {
            errno = EINVPTR;
            return;
        } else
            malloc_err("freezero(): invalid pointer");
    }

    memset(ptr, 0, size);
    free(ptr);
}

static void malloc_init()
{
    medium_pool.arena = arena_init(MEDIUM_SIZE * 1024); // 4 MB
    medium_pool.tail = &medium_pool.arena;
    large_pool.arena = arena_init(LARGE_SIZE * 2048); // 16 MB
    large_pool.tail = &large_pool.arena;

    init_free_list(medium_pool.tail);
    init_free_list(large_pool.tail);

    huge_pool.first = 0;
    huge_pool.tail = 0;

    initialized = true;

    bool registered = false;
    char b[64] = {0};
    const char *iter = NULL;

    int fd = open("/etc/malloc.conf", O_RDONLY);
    if (fd != -1) {
        int res = read(fd, b, 63);
        if (res > 0)
            iter = b;
    }

    close(fd);

    const char *env = getenv("MALLOC_OPTIONS");
    if (env != NULL)
        iter = env;

    if (malloc_options != NULL)
        iter = malloc_options;

    if (iter == NULL)
        return;

    while (*iter) {
        switch (*iter) {
        case 'C':
            alloc_flags |= CANARIES;
            break;
        case 'D':
            if (registered)
                break;
            atexit(dump_memory_info);
            registered = true;
            break;
        case '+':
            if (iter - 1 >= malloc_options) {
                if (*(iter - 1) != 'D') {
                    malloc_warn("malloc_options: option + cannot be used on "
                        "flag '%c'\n", *(iter - 1));
                    break;
                }
                alloc_flags |= DUMP_CONTENT;
            } else
                malloc_warn("malloc_options: option + cannot be used alone\n");
            break;
        case 'F':
            alloc_flags |= FREECHECK;
            break;
        case 'J':
            alloc_flags |= JUNKING;
            break;
        case 'V':
            alloc_flags |= VERBOSE;
            break;
        case 'X':
            alloc_flags |= XMALLOC;
            break;
        /* /etc/malloc.conf may end with a new line, ignore it */
        case '\n':
            break;
        default:
            malloc_warn("malloc_options: unknown option '%c'\n", *iter);
        }
        iter++;
    }
}

static void dump_memory_info()
{
    int magic = 0;
    int fd = open("memdump", O_WRONLY | O_CREAT, 0644);

    if (fd == -1)
        malloc_err("memdump: failed to open file\n");

    if (alloc_flags & DUMP_CONTENT)
        magic = 1;

    write(fd, &magic, sizeof(int));

    /* address, size, free, content (optional) */

    struct arena *arenas[2] = {&medium_pool.arena, &large_pool.arena};
    for (int i = 0; i < 2; i++) {
        struct arena *iter = arenas[i];
        for (; iter != NULL; iter = iter->next) {
            uint8_t *adj = iter->data;
            for (int i = iter->count; i > 0; i--) {
                struct malloc_header *header = (void*) adj;
                adj += sizeof(struct malloc_header);

                uint8_t freed = 0;
                if (header->usable_size < 0)
                    freed = 1;

                write(fd, &header, sizeof(void*));
                write(fd, &header->usable_size, sizeof(ssize_t));
                write(fd, &freed, sizeof(uint8_t));

                if (magic && header->usable_size > 0)
                    write(fd, adj, header->usable_size);

                adj += header->usable_size;
            }
        }
    }

    struct malloc_header *iter = huge_pool.first;
    while (iter != NULL) {
        uint8_t *adj = (void*) iter;
        adj += iter->usable_size;

        int freed = 1; /* non free blocks won't show here */

        write(fd, &iter, sizeof(void*));
        write(fd, &iter->usable_size, sizeof(ssize_t));
        write(fd, &freed, sizeof(uint8_t));

        if (magic && iter->usable_size > 0)
            write(fd, adj, iter->usable_size);

        iter = get_list(iter)->next;
    }

    close(fd);
}

static bool is_pointer_valid(void *ptr)
{
    found_arena = NULL;
    struct arena *arenas[2] = {&medium_pool.arena, &large_pool.arena};
    for (int i = 0; i < 2; i++) {
        struct arena *iter = arenas[i];
        for (; iter != NULL; iter = iter->next) {
            uint8_t *adj = iter->data;
            adj += iter->allocated;

            if (ptr >= (void*) iter && ptr < (void*) adj) {
                found_arena = iter;
                return true;
            }
        }
    }

    struct malloc_header *iter = huge_pool.first;
    while (iter != NULL) {
        uint8_t *adj = (void*) iter;
        adj += iter->usable_size;

        if (ptr >= (void*) iter && ptr < (void*) adj)
            return true;

        iter = get_list(iter)->next;
    }

    return false;
}

static void *find_free_block(size_t size, enum pools pool)
{
    struct arena *iter = NULL;

    switch (pool) {
    case MEDIUM:
        iter = &medium_pool.arena;
    case LARGE: /* FALLTHROUGH as both medium and large pools are arenas */
        if (iter == NULL)
            iter = &large_pool.arena;

        for (; iter != NULL; iter = iter->next) {
            if (free_list_count(iter) == 0)
                continue;

            struct malloc_header *head = free_list_get(iter);

            if (head == NULL)
                return head;

            head->usable_size = -head->usable_size;

            return head;
        }
        break;
    case HUGE: /* There won't be free blocks */
        break;
    }
    return NULL;
}

static void update_tail(struct alloc_pool *pool)
{
    while (pool->tail->next != NULL)
        pool->tail = pool->tail->next;
}

static void *huge_alloc(size_t size)
{
    struct malloc_header head = {0};

    if (alloc_flags & CANARIES)
        size += CANARY_SIZE;

    size_t to_alloc = align(size + sizeof(head) +
        sizeof(struct huge_alloc_list), PGSIZE);

    head.usable_size = to_alloc - sizeof(head) -
        sizeof(struct huge_alloc_list);

    void *ptr = mmap(NULL, to_alloc, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (alloc_flags & CANARIES) {
        head.usable_size -= CANARY_SIZE;
        size -= CANARY_SIZE;
    }

    if (ptr == NULL && alloc_flags & XMALLOC)
        malloc_err("malloc(): Out Of Memory");

    if (ptr == NULL && alloc_flags & FREECHECK) {
        errno = ENOMEM;
        return NULL;
    }

    *(struct malloc_header*) ptr = head;
    uint8_t *adj = ptr;
    adj += sizeof(head);
    adj += head.usable_size;
    memset(adj, 0, sizeof(struct huge_alloc_list));

    if (huge_pool.first == NULL) {
        huge_pool.first = ptr;
        huge_pool.tail = ptr;
    } else {
        struct huge_alloc_list *list = get_list(ptr);
        struct huge_alloc_list *prev = get_list(huge_pool.tail);

        list->prev = huge_pool.tail;
        prev->next = ptr;
        huge_pool.tail = ptr;
    }

    void *off = ((uint8_t*) ptr) + sizeof(head);

    if (alloc_flags & JUNKING)
        memset(off, JUNK_VALUE, size);

    if (alloc_flags & CANARIES)
        memset(off + size, 0, CANARY_SIZE);

    if (alloc_flags & VERBOSE)
        malloc_warn("malloc(%ld) at arena %p = %p\n",
            head.usable_size, medium_pool.tail, ptr);

    return off;
}

static struct huge_alloc_list *get_list(struct malloc_header *header)
{
    uint8_t *adj = (void*) header;
    adj += sizeof(*header);
    adj += header->usable_size;
    return (struct huge_alloc_list*) adj;
}

static void huge_alloc_rm(struct malloc_header *header)
{
    struct huge_alloc_list *list = get_list(header);

    /* last one in list */
    if (list->prev == NULL && list->next == NULL) {
        huge_pool.first = 0;
        huge_pool.tail = 0;
        return;
    }

    if (alloc_flags & VERBOSE)
        malloc_warn("free(%p) of size %ld at arena %p\n",
            header, header->usable_size, found_arena);

    /* pop front */
    if (list->prev == NULL) {
        struct huge_alloc_list *next = get_list(list->next);
        huge_pool.first = list->next;
        next->prev = NULL;
        return;
    }

    /* pop back */
    if (list->next == NULL) {
        struct huge_alloc_list *prev = get_list(list->prev);
        prev->next = NULL;
        huge_pool.tail = list->prev;
        return;
    }

    struct huge_alloc_list *next = get_list(list->next);
    struct huge_alloc_list *prev = get_list(list->prev);

    prev->next = list->next;
    next->prev = list->prev;
}

static void check_canary(void *ptr)
{
    uint8_t *iter = ptr;
    for (int i = 0; i < CANARY_SIZE; i++, iter++) {
        if (*iter != 0)
            malloc_err("*** heap smashing detected ***: terminated\n");
    }
}

static void init_free_list(struct arena *arena)
{
    arena->allocated -= sizeof(size_t);
    uint8_t *adj = arena->data;
    adj += arena->allocated;
    *(size_t*) adj = 0;
}

static size_t free_list_count(struct arena *arena)
{
    uint8_t *adj = arena->data;
    adj += arena->final_allocated - sizeof(size_t);
    return *(size_t*) adj;
}

static void free_list_incr(struct arena *arena)
{
    arena->allocated -= sizeof(void*);
    uint8_t *adj = arena->data;
    adj += arena->allocated;

    *(void**) adj = NULL;

    adj = arena->data;
    adj += arena->final_allocated - sizeof(size_t);

    *(size_t*) adj = (*(size_t*) adj) + 1;
}

static void free_list_push(struct arena *arena, void *block)
{
    /* search for free block, set freed ptr */
    uint8_t *adj = arena->data;
    adj += arena->final_allocated - sizeof(size_t);
    size_t count = *(size_t*) adj;

    for (size_t i = 0; i < count; i++) {
        adj -= sizeof(void*);
        if (*(void**) adj == NULL) {
            *(void**) adj = block;
            break;
        }
    }
}

static void free_list_rm(struct arena *arena, void *block)
{
    /* search for block and set NULL */
    uint8_t *adj = arena->data;
    adj += arena->final_allocated - sizeof(size_t);
    size_t count = *(size_t*) adj;

    for (size_t i = 0; i < count; i++) {
        adj -= sizeof(void*);
        if (*(void**) adj == block) {
            *(void**) adj = NULL;
            break;
        }
    }
}

static void *free_list_get(struct arena *arena)
{
    uint8_t *adj = arena->data;
    adj += arena->final_allocated - sizeof(size_t);
    size_t count = *(size_t*) adj;

    for (size_t i = 0; i < count; i++) {
        adj -= sizeof(void*);
        if (*(void**) adj != NULL)
            return adj;
    }

    return NULL;
}
