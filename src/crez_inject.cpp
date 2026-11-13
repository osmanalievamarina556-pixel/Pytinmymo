// crez_inject.cpp: инжектор arm64 Android, удалённый dlopen через ptrace
// Использование: crez_inject <pid> /data/local/tmp/crez/libcrez.so
// Не проверено на устройстве. Нужен root.
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <asm/ptrace.h>
#include <elf.h>
#include <csignal>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

static bool get_regs(pid_t p, user_pt_regs& r) {
    struct iovec io { &r, sizeof r };
    return ptrace(PTRACE_GETREGSET, p, (void*)NT_PRSTATUS, &io) == 0;
}

static bool set_regs(pid_t p, user_pt_regs& r) {
    struct iovec io { &r, sizeof r };
    return ptrace(PTRACE_SETREGSET, p, (void*)NT_PRSTATUS, &io) == 0;
}

// адрес начала mapping для библиотеки в целевом процессе
static uint64_t remote_base(pid_t pid, const char* lib) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    uint64_t base = 0;
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, lib)) { base = strtoull(line, nullptr, 16); break; }
    }
    fclose(f);
    return base;
}

static int inject(pid_t pid, const char* lib) {
    // dlopen в нашем процессе; libc одинаково лежит в целевом (zygote fork)
    Dl_info di{};
    void* dlo = dlsym(RTLD_DEFAULT, "dlopen");
    if (!dlo || !dladdr(dlo, &di)) { fprintf(stderr, "dladdr fail\n"); return 1; }
    uint64_t off = (uint64_t)dlo - (uint64_t)di.dli_fbase;
    uint64_t rbase = remote_base(pid, di.dli_fname);
    if (!rbase) { fprintf(stderr, "база %s не найдена в pid %d\n", di.dli_fname, pid); return 1; }
    uint64_t remote_dlopen = rbase + off;
    printf("dlopen local=%p remote=0x%llx (%s)\n", dlo,
           (unsigned long long)remote_dlopen, di.dli_fname);

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) { perror("attach"); return 1; }
    int st = 0;
    waitpid(pid, &st, __WALL);

    user_pt_regs saved{}, regs{};
    if (!get_regs(pid, saved)) {
        perror("getregs");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
    }
    regs = saved;

    char memp[64];
    snprintf(memp, sizeof memp, "/proc/%d/mem", pid);
    int fd = open(memp, O_RDWR);
    if (fd < 0) {
        perror("open mem");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
    }

    // путь к библиотеке кладём на стек целевого процесса
    uint64_t path_addr = (saved.sp - 1024) & ~0xFULL;
    size_t plen = strlen(lib) + 1;
    pwrite(fd, lib, plen, (off_t)path_addr);

    // BRK на текущем pc: по возврату из dlopen остановим процесс
    uint64_t pc = saved.pc;
    uint32_t orig = 0, brk = 0xD4200000;   // BRK #0
    pread(fd, &orig, 4, (off_t)pc);
    pwrite(fd, &brk, 4, (off_t)pc);

    regs.regs[0] = path_addr;   // const char* filename
    regs.regs[1] = RTLD_NOW;    // flags
    regs.regs[30] = pc;         // lr: вернуться на BRK
    regs.sp = (path_addr - 256) & ~0xFULL;
    regs.pc = remote_dlopen;
    set_regs(pid, regs);

    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    waitpid(pid, &st, __WALL);

    int rc = 0;
    if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP) {
        get_regs(pid, regs);
        uint64_t handle = regs.regs[0];
        if (handle) {
            printf("ok, handle=0x%llx\n", (unsigned long long)handle);
        } else {
            printf("dlopen вернул 0: библиотека не загружена (см. dlerror в логе игры)\n");
            rc = 2;
        }
    } else if (WIFSTOPPED(st)) {
        get_regs(pid, regs);
        printf("процесс остановлен сигналом %d на pc=0x%llx\n",
               WSTOPSIG(st), (unsigned long long)regs.pc);
        rc = 3;
    } else {
        printf("процесс завершился\n");
        rc = 4;
    }

    // восстанавливаем код и регистры, только если процесс жив
    if (WIFSTOPPED(st)) {
        pwrite(fd, &orig, 4, (off_t)pc);
        set_regs(pid, saved);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    }
    close(fd);
    return rc;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid> <path/to/lib.so>\n", argv[0]);
        return 1;
    }
    return inject((pid_t)atoi(argv[1]), argv[2]);
}
