/*
 * Hexagon emulation for qemu: main translation routines.
 *
 * Copyright (c) 2017-2019 Comsecuris UG (haftungsbeschraenkt)
 *
 * Based on target/arm/arm-semi.c which is
 *  Copyright (c) 2005, 2007 CodeSourcery.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "qemu.h"

#define HEXAGON_SEMI_HEAP_SIZE (128 * 1024 * 1024)

#define TARGET_SYS_OPEN        0x001
#define TARGET_SYS_CLOSE       0x002
#define TARGET_SYS_WRITEC      0x003
#define TARGET_SYS_WRITE0      0x004
#define TARGET_SYS_WRITE       0x005
#define TARGET_SYS_READ        0x006
#define TARGET_SYS_READC       0x007
#define TARGET_SYS_ISTTY       0x009
#define TARGET_SYS_SEEK        0x00a
#define TARGET_SYS_FLEN        0x00c
#define TARGET_SYS_TMPNAM      0x00d
#define TARGET_SYS_REMOVE      0x00e
#define TARGET_SYS_RENAME      0x00f
#define TARGET_SYS_CLOCK       0x010
#define TARGET_SYS_TIME        0x011
#define TARGET_SYS_SYSTEM      0x012
#define TARGET_SYS_ERRNO       0x013
#define TARGET_SYS_GET_CMDLINE 0x015
#define TARGET_SYS_HEAPINFO    0x016
#define TARGET_SYS_EXIT        0x018
#define TARGET_SYS_SYNCCACHE   0x019
#define TARGET_SYS_FTELL       0x100
#define TARGET_SYS_FSTAT       0x101
#define TARGET_SYS_STATVFS     0x102
#define TARGET_SYS_STAT        0x103
#define TARGET_SYS_GETCWD      0x104
#define TARGET_SYS_ACCESS      0x105
#define TARGET_SYS_FCNTL       0x106
#define TARGET_SYS_GETOD       0x107
#define TARGET_SYS_OPENDIR     0x180
#define TARGET_SYS_CLOSEDIR    0x181
#define TARGET_SYS_MKDIR       0x183
#define TARGET_SYS_RMDIR       0x184
#define TARGET_SYS_FTRUNC      0x186

#define GET_ARG(n) do {                                 \
    if (get_user_u32(arg ## n, args + (n) * 4)) {   \
        return -1;                                  \
    }                                               \
} while (0)

#define SET_ARG(n, val)                                 \
     put_user_u32(val, args + (n) * 4)

static int open_modeflags[12] = {
    O_RDONLY,
    O_RDONLY | O_BINARY,
    O_RDWR,
    O_RDWR | O_BINARY,
    O_WRONLY | O_CREAT | O_TRUNC,
    O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
    O_RDWR | O_CREAT | O_TRUNC,
    O_RDWR | O_CREAT | O_TRUNC | O_BINARY,
    O_WRONLY | O_CREAT | O_APPEND,
    O_WRONLY | O_CREAT | O_APPEND | O_BINARY,
    O_RDWR | O_CREAT | O_APPEND,
    O_RDWR | O_CREAT | O_APPEND | O_BINARY
};

target_ulong do_hexagon_semihosting(CPUHexagonState *env)
{
    HexagonCPU *cpu = hexagon_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    target_ulong args;
    target_ulong arg0, arg1, arg2;
    char * s;
    int nr;
    uint32_t ret, len;
    TaskState *ts = cs->opaque;

    nr = env->gpr[0];
    args = env->gpr[1];

    switch (nr) {
    case TARGET_SYS_OPEN:
        GET_ARG(0);
        GET_ARG(1);
        GET_ARG(2);
        s = lock_user_string(arg0);
        if (!s) {
            /* FIXME - should this error code be -TARGET_EFAULT ? */
            return (uint32_t)-1;
        }
        if (arg1 >= 12) {
            unlock_user(s, arg0, 0);
            return (uint32_t)-1;
        }
        if (strcmp(s, ":tt") == 0) {
            int result_fileno = arg1 < 4 ? STDIN_FILENO : STDOUT_FILENO;
            unlock_user(s, arg0, 0);
            return result_fileno;
        }
        /*
        if (use_gdb_syscalls()) {
            ret = hexagon_gdb_syscall(cpu, hexagon_semi_cb, "open,%s,%x,1a4", arg0,
                                  (int)arg2+1, gdb_open_modeflags[arg1]);
        } else {
            ret = set_swi_errno(ts, open(s, open_modeflags[arg1], 0644));
        }
        */
        ret = open(s, open_modeflags[arg1], 0644);
        unlock_user(s, arg0, 0);
        return ret;
    case TARGET_SYS_CLOSE:
        GET_ARG(0);
        /*
        if (use_gdb_syscalls()) {
            return hexagon_gdb_syscall(cpu, hexagon_semi_cb, "close,%x", arg0);
        } else {
        }
        */
        return close(arg0);
    case TARGET_SYS_WRITEC:
        {
          char c;

          if (get_user_u8(c, args))
              /* FIXME - should this error code be -TARGET_EFAULT ? */
              return (uint32_t)-1;
          /* Write to debug console.  stderr is near enough.  */
          /*
          if (use_gdb_syscalls()) {
                return hexagon_gdb_syscall(cpu, hexagon_semi_cb, "write,2,%x,1", args);
          } else {
                return write(STDERR_FILENO, &c, 1);
          }
          */
          return write(STDERR_FILENO, &c, 1);
        }
    case TARGET_SYS_WRITE0:
        if (!(s = lock_user_string(args)))
            /* FIXME - should this error code be -TARGET_EFAULT ? */
            return (uint32_t)-1;
        len = strlen(s);
        /*
        if (use_gdb_syscalls()) {
            return hexagon_gdb_syscall(cpu, hexagon_semi_cb, "write,2,%x,%x",
                                   args, len);
        } else {
            ret = write(STDERR_FILENO, s, len);
        }
        */
        ret = write(STDERR_FILENO, s, len);
        unlock_user(s, args, 0);
        return ret;
    case TARGET_SYS_WRITE:
        GET_ARG(0);
        GET_ARG(1);
        GET_ARG(2);
        len = arg2;
        /*
        if (use_gdb_syscalls()) {
            hexagon_semi_syscall_len = len;
            return hexagon_gdb_syscall(cpu, hexagon_semi_cb, "write,%x,%x,%x",
                                   arg0, arg1, len);
        } else {
        */
            s = lock_user(VERIFY_READ, arg1, len, 1);
            if (!s) {
                /* FIXME - should this error code be -TARGET_EFAULT ? */
                return (uint32_t)-1;
            }
            ret = write(arg0, s, len);
            unlock_user(s, arg1, 0);
            if (ret == (uint32_t)-1)
                return -1;
            return len - ret;
        //}
    case TARGET_SYS_READ:
        GET_ARG(0);
        GET_ARG(1);
        GET_ARG(2);
        len = arg2;
        /*
        if (use_gdb_syscalls()) {
            hexagon_semi_syscall_len = len;
            return hexagon_gdb_syscall(cpu, hexagon_semi_cb, "read,%x,%x,%x",
                                   arg0, arg1, len);
        } else {
        */
            s = lock_user(VERIFY_WRITE, arg1, len, 0);
            if (!s) {
                /* FIXME - should this error code be -TARGET_EFAULT ? */
                return (uint32_t)-1;
            }
            do {
                ret = read(arg0, s, len);
            } while (ret == -1 && errno == EINTR);
            unlock_user(s, arg1, len);
            if (ret == (uint32_t)-1)
                return -1;
            return len - ret;
        //}
    case TARGET_SYS_READC:
        ret = fgetc(stdin);
        return ret;
    case TARGET_SYS_ISTTY:
        GET_ARG(0);
        /*
        if (use_gdb_syscalls()) {
            return hexagon_gdb_syscall(cpu, hexagon_semi_cb, "isatty,%x", arg0);
        } else {
            return isatty(arg0);
        }
        */
        return isatty(arg0);
    case TARGET_SYS_SEEK:
        GET_ARG(0);
        GET_ARG(1);
        /*
        if (use_gdb_syscalls()) {
            return hexagon_gdb_syscall(cpu, hexagon_semi_cb, "lseek,%x,%x,0",
                                   arg0, arg1);
        }  else {
        */
            ret = lseek(arg0, arg1, SEEK_SET);
            if (ret == (uint32_t)-1)
              return -1;
            return 0;
        //}
    case TARGET_SYS_FLEN:
        GET_ARG(0);
        /*
        if (use_gdb_syscalls()) {
            return hexagon_gdb_syscall(cpu, hexagon_semi_flen_cb, "fstat,%x,%x",
                                   arg0, hexagon_flen_buf(cpu));
        } else {
        */
            struct stat buf;
            ret = fstat(arg0, &buf);
            if (ret == (uint32_t)-1)
                return -1;
            return buf.st_size;
        //}
    case TARGET_SYS_TMPNAM:
        /* XXX: Not implemented.  */
        return -1;
    case TARGET_SYS_REMOVE:
        GET_ARG(0);
        GET_ARG(1);
        /*
        if (use_gdb_syscalls()) {
            ret = hexagon_gdb_syscall(cpu, hexagon_semi_cb, "unlink,%s",
                                  arg0, (int)arg1+1);
        } else {
        */
            s = lock_user_string(arg0);
            if (!s) {
                /* FIXME - should this error code be -TARGET_EFAULT ? */
                return (uint32_t)-1;
            }
            ret =  remove(s);
            unlock_user(s, arg0, 0);
        //}
        return ret;
    case TARGET_SYS_RENAME:
        GET_ARG(0);
        GET_ARG(1);
        GET_ARG(2);
        /*
        if (use_gdb_syscalls()) {
            return hexagon_gdb_syscall(cpu, hexagon_semi_cb, "rename,%s,%s",
                                   arg0, (int)arg1+1, arg2, (int)arg3+1);
        } else {
        */
            char *s2;
            s = lock_user_string(arg0);
            s2 = lock_user_string(arg2);
            if (!s || !s2)
                /* FIXME - should this error code be -TARGET_EFAULT ? */
                ret = (uint32_t)-1;
            else
                ret = rename(s, s2);
            if (s2)
                unlock_user(s2, arg2, 0);
            if (s)
                unlock_user(s, arg0, 0);
            return ret;
        //}
    case TARGET_SYS_CLOCK:
        return clock() / (CLOCKS_PER_SEC / 100);
    case TARGET_SYS_TIME:
        return time(NULL);
    case TARGET_SYS_SYSTEM:
        GET_ARG(0);
        GET_ARG(1);
        /*
        if (use_gdb_syscalls()) {
            return hexagon_gdb_syscall(cpu, hexagon_semi_cb, "system,%s",
                                   arg0, (int)arg1+1);
        } else {
        */
            s = lock_user_string(arg0);
            if (!s) {
                /* FIXME - should this error code be -TARGET_EFAULT ? */
                return (uint32_t)-1;
            }
            ret = system(s);
            unlock_user(s, arg0, 0);
            return ret;
        //}
    case TARGET_SYS_GET_CMDLINE:
        {
            /* Build a command-line from the original argv.
             *
             * The inputs are:
             *     * arg0, pointer to a buffer of at least the size
             *               specified in arg1.
             *     * arg1, size of the buffer pointed to by arg0 in
             *               bytes.
             *
             * The outputs are:
             *     * arg0, pointer to null-terminated string of the
             *               command line.
             *     * arg1, length of the string pointed to by arg0.
             */

            char *output_buffer;
            size_t input_size;
            size_t output_size = 0;
            size_t string_length = 0;
            int status = 0;
            GET_ARG(0);
            GET_ARG(1);
            input_size = arg1;
            /* Compute the size of the output string.  */
            unsigned int i;
            unsigned int argc = (ts->info->arg_end - ts->info->arg_start) / (TARGET_LONG_BITS / 8);
            for(i = 0; i < argc; i++) {
                string_length = strlen((char *)g2h(ts->info->arg_strings) + output_size);
                output_size += string_length + 1;
            }

            if (!output_size) {
                /* We special-case the "empty command line" case (argc==0).
                   Just provide the terminating 0. */
                output_size = 1;
            }

            if (output_size > input_size) {
                 /* Not enough space to store command-line arguments.  */
                return -1;
            }

            /* Adjust the command-line length.  */
            if (SET_ARG(1, output_size - 1)) {
                /* Couldn't write back to argument block */
                return -1;
            }

            /* Lock the buffer on the ARM side.  */
            output_buffer = lock_user(VERIFY_WRITE, arg0, output_size, 0);
            if (!output_buffer) {
                return -1;
            }

            /* Copy the command-line arguments.  */
#if !defined(CONFIG_USER_ONLY)
            pstrcpy(output_buffer, output_size, cmdline);
#else
            if (output_size == 1) {
                /* Empty command-line.  */
                output_buffer[0] = '\0';
                goto out;
            }

            if (copy_from_user(output_buffer, ts->info->arg_strings,
                               output_size)) {
                status = -1;
                goto out;
            }

            /* Separate arguments by white spaces. */
            for (i = 0; i < output_size - 1; i++) {
                if (output_buffer[i] == 0) {
                    output_buffer[i] = ' ';
                }
            }

            /* Hexagon puts a trailing whitespace before the terminator */
            output_buffer[output_size - 1] = ' ';
            output_buffer[output_size] = '\0';
        out:
#endif
            /* Unlock the buffer on the ARM side.  */
            unlock_user(output_buffer, arg0, output_size);

            return status;
        }
    case TARGET_SYS_HEAPINFO:
        {
            target_ulong retvals[4];
            target_ulong limit;
            int i;

            GET_ARG(0);

#ifdef CONFIG_USER_ONLY
            /* Some C libraries assume the heap immediately follows .bss, so
               allocate it using sbrk.  */
            if (!ts->heap_limit) {
                abi_ulong ret;

                ts->heap_base = do_brk(0);
                limit = ts->heap_base + HEXAGON_SEMI_HEAP_SIZE;
                /* Try a big heap, and reduce the size if that fails.  */
                for (;;) {
                    ret = do_brk(limit);
                    if (ret >= limit) {
                        break;
                    }
                    limit = (ts->heap_base >> 1) + (limit >> 1);
                }
                ts->heap_limit = limit;
            }

            retvals[0] = ts->heap_base;
            retvals[1] = ts->heap_limit;
            retvals[2] = 0; /* XXX: hexagon-sim puts the stack_base to 0 */
            retvals[3] = 0; /* Stack limit.  */
#else
            limit = ram_size;
            /* TODO: Make this use the limit of the loaded application.  */
            retvals[0] = limit / 2;
            retvals[1] = limit;
            retvals[2] = limit; /* Stack base */
            retvals[3] = 0; /* Stack limit.  */
#endif

            for (i = 0; i < ARRAY_SIZE(retvals); i++) {
                bool fail;

                fail = put_user_u32(retvals[i], arg0 + i * 4);

                if (fail) {
                    /* Couldn't write back to argument block */
                    return -1;
                }
            }
            /* HEAPINFO does not clobber r0 */
            return env->gpr[0];
        }
    case TARGET_SYS_EXIT:
        gdb_exit(env, args);
        exit(args);
    case TARGET_SYS_SYNCCACHE:
        /* We are not emulating caches, just return */
        return 0;
    case 0xcd:
        /* This syscall is called inside the free function */
        return 0;
    case TARGET_SYS_FTELL:
        GET_ARG(0);
        ret = lseek(arg0, 0, SEEK_CUR);
        return ret;
    case TARGET_SYS_FSTAT:
        return 0;
    case TARGET_SYS_STATVFS:
        return 0;
    case TARGET_SYS_STAT:
        return 0;
    case TARGET_SYS_GETCWD:
        {
            GET_ARG(0);
            GET_ARG(1);
            len = arg1;

            s = lock_user(VERIFY_WRITE, arg0, len, 0);
            if (!s) {
                /* FIXME - should this error code be -TARGET_EFAULT ? */
                return (uint32_t)-1;
            }

            char * ret = getcwd(s, arg1);

            if(!arg1 && !ret)
                return -1;

            unlock_user(s, arg1, len);
            return arg1;
        }
    case TARGET_SYS_ACCESS:
        GET_ARG(0);
        GET_ARG(1);
        s = lock_user_string(arg0);
        if (!s) {
            /* FIXME - should this error code be -TARGET_EFAULT ? */
            return (uint32_t)-1;
        }
        if (arg1 > 4) {
            unlock_user(s, arg0, 0);
            return (uint32_t)-1;
        }
        ret = access(s, arg1);
        unlock_user(s, arg0, 0);
        return ret;
    case TARGET_SYS_FCNTL:
        GET_ARG(0);
        GET_ARG(1);
        GET_ARG(2);
        return fcntl(arg0, arg1, arg2);
    case TARGET_SYS_GETOD:
        {
            GET_ARG(0);

            s = lock_user(VERIFY_WRITE, arg0, sizeof(struct timeval), 0);
            if (!s) {
                /* FIXME - should this error code be -TARGET_EFAULT ? */
                return (uint32_t)-1;
            }

            gettimeofday((struct timeval *)s, NULL);

            unlock_user(s, arg0, sizeof(struct timeval));
            return 0;
        }
    case TARGET_SYS_OPENDIR:
        {
            GET_ARG(0);
            GET_ARG(1);
            DIR *dir;
            s = lock_user_string(arg0);
            if (!s) {
                /* FIXME - should this error code be -TARGET_EFAULT ? */
                return (uint32_t)-1;
            }
            dir = opendir(s);
            if (!dir)
                return -1;

            /* TODO: Copy information in new buffer before returning it */

            unlock_user(s, arg0, 0);
            return 0;
        }
    case TARGET_SYS_CLOSEDIR:
        return 0;
    case TARGET_SYS_MKDIR:
            /* Create a folder
             *
             * The inputs are:
             *     * r1, contains the string of the folder name
             *     * r2, contains the mode parameter
             *
             * The outputs are:
             *     * 0, contains the return code
             */
        s = lock_user_string(env->gpr[1]);
        int mode = env->gpr[2];
        if (!s) {
            /* FIXME - should this error code be -TARGET_EFAULT ? */
            return (uint32_t)-1;
        }
        if (mode >= 12) {
            unlock_user(s, env->gpr[1], 0);
            return (uint32_t)-1;
        }
        ret = mkdir(s, 0644);
        unlock_user(s, env->gpr[1], 0);
        return ret;
    case TARGET_SYS_RMDIR:
            /* Delete a folder
             *
             * The inputs are:
             *     * r1, contains the string of the folder name
             *
             * The outputs are:
             *     * 0, contains the return code
             */
        s = lock_user_string(env->gpr[1]);
        if (!s) {
            /* FIXME - should this error code be -TARGET_EFAULT ? */
            return (uint32_t)-1;
        }
        ret = rmdir(s);
        unlock_user(s, env->gpr[1], 0);
        return ret;
    case TARGET_SYS_FTRUNC:
        GET_ARG(0);
        GET_ARG(1);
        ret = ftruncate(arg0, arg1);
        return ret;
    default:
        fprintf(stderr, "qemu: Unsupported SemiHosting SWI 0x%02x\n", nr);
        cpu_dump_state(cs, stderr, fprintf, 0);
        abort();
    }
}
