// SPDX-License-Identifier: BSD-3-Clause
/* Copyright (C) 2021 */
// g++ -O0 -o mainf mainf.cpp -g -ljemalloc

#include <fcntl.h>
#include <sys/mman.h>
#include <iostream>
#include <vector>
#include <signal.h>
#include <cstring>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <random>
#include <jemalloc/jemalloc.h>

#define FILE_PATH "/tmp/"
#define SIZE_LIMIT 510027366U

#define N_OPERATION_LIMIT 50000000
#define CHECK_STAT_FREQ   100000

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static size_t g_current_file_size;
static int g_fd;
static unsigned g_arena_index;
static size_t g_allocated_size;
std::vector<char *> g_vec_strs;

static void *my_alloc(size_t size) {
    return je_mallocx(size, MALLOCX_ARENA(g_arena_index) | MALLOCX_TCACHE_NONE);
}

static void my_free(void *ptr){
    je_dallocx(ptr, MALLOCX_TCACHE_NONE);
}
static size_t my_usable_size(void* ptr){
    return je_malloc_usable_size(ptr);
}

static void print_stats_and_exit(void)
{
    je_malloc_stats_print(NULL, NULL, NULL);
    exit(EXIT_FAILURE);
}

static void *custom_extent_alloc(extent_hooks_t *extent_hooks,
                        void *new_addr,
                        size_t size,
                        size_t alignment,
                        bool *zero,
                        bool *commit,
                        unsigned arena_ind)
{
    void *addr = NULL;
    if (new_addr != NULL) {
        /* not supported */
        goto exit;
    }

    if (g_current_file_size + size > SIZE_LIMIT) {
        goto exit;
    }

    if ((errno = posix_fallocate(g_fd, (off_t)g_current_file_size, (off_t)size)) != 0) {
        goto exit;
    }

    if ((addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, g_fd,
                      (off_t)g_current_file_size)) != MAP_FAILED) {
        g_current_file_size += size;
    }

    if (addr != MAP_FAILED) {
        *zero = true;
        *commit = true;
        if ((uintptr_t)addr & (alignment - 1)) {
            std::cerr << "Not alligned address " << size <<" alignment " <<alignment << std::endl;
            abort();
        }
    } else {
        addr = NULL;
    }
exit:
    return addr;
}

static bool custom_extent_dalloc(extent_hooks_t *extent_hooks,
                        void *addr,
                        size_t size,
                        bool committed,
                        unsigned arena_ind)
{
    return true;
}

static bool custom_extent_commit(extent_hooks_t *extent_hooks,
                        void *addr,
                        size_t size,
                        size_t offset,
                        size_t length,
                        unsigned arena_ind)
{
    /* do nothing - report success */
    return false;
}

static bool custom_extent_decommit(extent_hooks_t *extent_hooks,
                          void *addr,
                          size_t size,
                          size_t offset,
                          size_t length,
                          unsigned arena_ind)
{
    /* do nothing - report failure (opt-out) */
    return true;
}

static bool custom_extent_purge(extent_hooks_t *extent_hooks,
                       void *addr,
                       size_t size,
                       size_t offset,
                       size_t length,
                       unsigned arena_ind)
{
    /* do nothing - report failure (opt-out) */
    return true;
}

static bool custom_extent_split(extent_hooks_t *extent_hooks,
                       void *addr,
                       size_t size,
                       size_t size_a,
                       size_t size_b,
                       bool committed,
                       unsigned arena_ind)
{
    /* do nothing - report success */
    return false;
}

static bool custom_extent_merge(extent_hooks_t *extent_hooks,
                       void *addr_a,
                       size_t size_a,
                       void *addr_b,
                       size_t size_b,
                       bool committed,
                       unsigned arena_ind)
{
    /* do nothing - report success */
    return false;
}

static void custom_extent_destroy(extent_hooks_t *extent_hooks,
                         void *addr,
                         size_t size,
                         bool committed,
                         unsigned arena_ind)
{
    if (munmap(addr, size) == -1) {
        std::cerr << "munmap failed!";
    }
}

static extent_hooks_t custom_extent_hooks = {
    .alloc = custom_extent_alloc,
    .dalloc = custom_extent_dalloc,
    .destroy = custom_extent_destroy,
    .commit = custom_extent_commit,
    .decommit = custom_extent_decommit,
    .purge_lazy = custom_extent_purge,
    .purge_forced = NULL,
    .split = custom_extent_split,
    .merge = custom_extent_merge,
};

static void create_temporary_file(const char *dir) {

    const size_t size = sysconf(_SC_PAGESIZE);
    static char template_name[] = "/test_file.XXXXXX";
    int oerrno;
    int dir_len = strlen(dir);

    if (dir_len > PATH_MAX) {
        std::cerr << "Could not create temporary file: too long path.";
        exit(1);
    }

    char fullname[dir_len + sizeof(template_name)];
    (void)strcpy(fullname, dir);
    (void)strcat(fullname, template_name);

    sigset_t set, oldset;
    sigfillset(&set);
    (void)sigprocmask(SIG_BLOCK, &set, &oldset);

    if ((g_fd = mkstemp(fullname)) < 0) {
        std::cerr << "Could not create temporary file: errno=" <<errno;
        exit(1);
    }

    (void)unlink(fullname);
    (void)sigprocmask(SIG_SETMASK, &oldset, NULL);
}

static void create_hooks(void) {
    int err;
    size_t unsigned_size = sizeof(unsigned);
    //create new arena
    err = je_mallctl("arenas.create", (void *)&g_arena_index, &unsigned_size, NULL, 0);
    if(err) {
        std::cerr << "Could not create arena";
        exit(1);
    }
    char cmd[64];
    const size_t retainGrowLimit = 2 * 1024 * 1024; // 2 MB
    snprintf(cmd, sizeof(cmd), "arena.%u.retain_grow_limit", g_arena_index);
    err = je_mallctl(cmd, NULL, NULL, (void *)&retainGrowLimit,
                        sizeof(retainGrowLimit));
    if (err) {
        std::cerr << "retain_grow_limit failed";
        exit(1);
    }

    //setup extent_hooks for newly created arena
    extent_hooks_t *new_hooks = &custom_extent_hooks;
    snprintf(cmd, sizeof(cmd), "arena.%u.extent_hooks", g_arena_index);
    err = je_mallctl(cmd, NULL, NULL, (void *)&new_hooks, sizeof(extent_hooks_t *));
    if(err) {
        std::cerr << "Could not setup extent_hooks";
        exit(1);
    }
}

static size_t get_abandoned_vm(void) {
    char cmd[128];
    uint64_t epoch = 1;
    size_t sz = sizeof(epoch);
    size_t abandoned_vm;
    int err = je_mallctl("epoch", &epoch, &sz, &epoch, sz);
    if(err) {
        std::cerr << "Epoch failed";
        exit(1);
    }
    snprintf(cmd, 128, "stats.arenas.%u.abandoned_vm", g_arena_index);
    err = je_mallctl(cmd, &abandoned_vm, &sz, NULL, 0);
    if(err) {
        std::cerr << "get abandoned_vm stat failed";
        exit(1);
    }
    return abandoned_vm;
}

static void do_workload(void) {
    std::random_device rd;
    std::mt19937 mt(rd());
    size_t block_size[] = {32774, 23, 36, 4102, 18, 24};
    std::uniform_int_distribution<> m_size(0, ARRAY_SIZE(block_size) - 1);
    for (size_t i=0; i<N_OPERATION_LIMIT ;++i) {
        int index = m_size(mt);
        size_t size = block_size[index];
        size_t length = g_vec_strs.size() / 2;
        std::uniform_int_distribution<size_t> m_index(0, length - 1);

        char* ptr = static_cast<char *>(my_alloc(size));
        if (ptr) {
            memset(ptr, 0, size);
            g_allocated_size+= my_usable_size(ptr);
            g_vec_strs.push_back(ptr);
        } else {
            //evict random item if allocation not succeeded
            size_t to_evict = m_index(mt);
            char *str_to_evict = g_vec_strs[to_evict];
            g_allocated_size-= my_usable_size(str_to_evict);
            my_free(str_to_evict);
            g_vec_strs.erase(g_vec_strs.begin() + to_evict);
        }
        if (get_abandoned_vm() != 0) {
            print_stats_and_exit();
        }
    }
}

int main()
{
    create_temporary_file(FILE_PATH);
    create_hooks();
    do_workload();
    return 0;
}
