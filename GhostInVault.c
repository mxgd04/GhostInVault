//Ghost in the Vault

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/mman.h>

#define _DC0  0xB33F
#define _DC1  0x8C4A
#define _DC2  0xF00D
#define _DC3  0x1337
#define _DC4  0xCAFE
#define _DC5  0xDEAD
#define _DC6  0x4242

#define KS 0xCC
#define PID_MAGIC 0xDEAD

static volatile uint64_t _op_g0 = 0xA5A5A5A5ULL;
static volatile uint64_t _op_g1 = 0x5A5A5A5AULL;

#define OP_T  ( ((_op_g0 | ~_op_g0) & 0xFF) == 0xFF )
#define OP_F  ( ((_op_g1 & ~_op_g1) & 0xFF) != 0x00 )


static const unsigned char es_banner[] = {
    0xf1,0xf1,0xf1,0xec,0x8b,0xa4,0xa3,0xbf,0xb8,0xec,0xa5,0xa2,0xec,0xb8,0xa4,0xa9,
    0xec,0x9a,0xad,0xb9,0xa0,0xb8,0xec,0xf1,0xf1,0xf1,0xc6,0x00
};

static const unsigned char es_prompt[]  = {
    0x9c,0xad,0xbf,0xbf,0xbb,0xa3,0xbe,0xa8,0xf6,0xec,0x00
};

static const unsigned char es_denied[]  = {
    0x8d,0xaf,0xaf,0xa9,0xbf,0xbf,0xec,0xa8,0xa9,0xa2,0xa5,0xa9,0xa8,0xe2,0xc6,0x00
};

static const unsigned char es_granted[] = {
    0x8d,0xaf,0xaf,0xa9,0xbf,0xbf,0xec,0xab,0xbe,0xad,0xa2,0xb8,0xa9,0xa8,0xe2,0xec,
    0x88,0xa9,0xaf,0xbe,0xb5,0xbc,0xb8,0xa5,0xa2,0xab,0xec,0xba,0xad,0xb9,0xa0,0xb8,
    0xec,0xa8,0xad,0xb8,0xad,0xe2,0xe2,0xe2,0xc6,0x00
};

static const unsigned char es_done[] = {
    0x88,0xa3,0xa2,0xa9,0xe2,0xec,0x8a,0xa5,0xa0,0xa9,0xec,0xeb,0xbf,0xa9,0xaf,0xbe,
    0xa9,0xb8,0xe2,0xa8,0xad,0xb8,0xeb,0xec,0xab,0xa9,0xa2,0xa9,0xbe,0xad,0xb8,0xa9,
    0xa8,0xe2,0xec,0x8b,0xa3,0xa3,0xa8,0xec,0xa0,0xb9,0xaf,0xa7,0xe2,0xc6,0x00
};

static const unsigned char es_dbg[] = {
    0x88,0xa9,0xae,0xb9,0xab,0xab,0xa9,0xbe,0xec,0xa8,0xa9,0xb8,0xa9,0xaf,0xb8,0xa9,0xa8,0xe2,0xec,0x8b,0xa3,0xa3,0xa8,0xae,0xb5,0xa9,0xe2,0xc6,0x00
};

static const unsigned char es_err[] = {
    0x89,0xbe,0xbe,0xa3,0xbe,0xf6,0xec,0xaf,0xad,0xa2,0xa2,0xa3,0xb8,0xec,0xbb,0xbe,0xa5,0xb8,0xa9,0xec,0xbf,0xa9,0xaf,0xbe,0xa9,0xb8,0xe2,0xa8,0xad,0xb8,0xc6,0x00
};

static const unsigned char es_fake[] = {
    0xf8,0xfb,0x8f,0x83,0x82,0xb7,0xb8,0xa4,0xfd,0xbf,0x93,0xfd,0xbf,0x93,0xad,0x93,0xb8,0xbe,0xf8,0xbc,0xb1,0xc6,0x00
};

static const unsigned char es_urandom[] = {
    0xe3,0xa8,0xa9,0xba,0xe3,0xb9,0xbe,0xad,0xa2,0xa8,0xa3,0xa1,0x00
};

static const unsigned char es_outfile[] = {
    0xbf,0xa9,0xaf,0xbe,0xa9,0xb8,0xe2,0xa8,0xad,0xb8,0x00
};

static const unsigned char es_pss[] = {
    0xe3,0xbc,0xbe,0xad,0xaf,0xe3,0xbf,0xa9,0xa0,0xaa,0xe3,0xbf,0xb8,0xad,0xb9,0xbf,0xba,0x00
};

static const unsigned char es_tpid[] = {
    0x98,0xbe,0xad,0xaf,0xa9,0xba,0x9c,0xa5,0xa8,0xf6,0x00
};

static void xs(char *dst, const unsigned char *src, size_t maxlen)
{
    size_t i = 0;
    while (src[i] && i < maxlen - 1) {
        dst[i] = (char)(src[i] ^ KS);
        i++;
    }
    dst[i] = '\0';
}

static const unsigned char sbox[256] = {
    0xae,0xec,0x30,0xd1,0xdd,0x82,0xe5,0x44,0x8a,0x43,0xdc,0xc0,0x32,0x85,0xaf,0x1d,
    0xf7,0x5d,0x3d,0x2d,0xb9,0xcc,0x20,0x8c,0x98,0x7a,0xa7,0x5c,0x4e,0x4c,0xfc,0x80,
    0x51,0xcb,0xf2,0x52,0xf8,0x72,0xca,0xcf,0x12,0xc7,0x22,0x6b,0x83,0x4f,0x78,0x6a,
    0x73,0x41,0x8e,0x0b,0x34,0xb3,0x9b,0xe8,0x0e,0x19,0x9f,0xea,0x0d,0x2a,0x5e,0xee,
    0x5f,0x01,0xc5,0xb0,0x2c,0xfd,0x04,0xe4,0xf4,0x29,0x54,0xd2,0x5a,0xa4,0x75,0x9a,
    0xe0,0xd7,0xd0,0xa5,0xc9,0x39,0x45,0x0a,0x2e,0x28,0x58,0x86,0xd3,0x99,0xa0,0x36,
    0x49,0x4a,0x69,0x61,0x3b,0xa6,0x66,0x47,0xbc,0x1f,0x95,0x81,0xd5,0x1e,0x13,0xdb,
    0x92,0x48,0xf9,0xb7,0xb6,0x11,0x62,0x0f,0xed,0x8b,0x37,0xfb,0x7d,0x63,0x5b,0x64,
    0x55,0xa9,0xf6,0x9e,0xc8,0x70,0x05,0x2b,0x6f,0x08,0x4b,0x35,0x59,0xbf,0x96,0x07,
    0xe7,0x1a,0xf1,0x74,0x6d,0xf3,0x50,0xc4,0xbb,0xb4,0xc2,0x10,0x26,0xff,0x71,0x46,
    0x1b,0x1c,0x3c,0x93,0x8d,0xba,0xa2,0x2f,0x7e,0x53,0x24,0xc1,0x3f,0x79,0xbd,0x02,
    0x38,0xdf,0x60,0xd6,0x7b,0x6c,0x94,0xa1,0x14,0x4d,0xeb,0x57,0xa8,0x27,0x18,0xab,
    0xe6,0x6e,0x00,0x77,0xf5,0x65,0xaa,0x09,0x03,0x7c,0xad,0x9d,0xd8,0xe3,0xc3,0x21,
    0xef,0xe1,0x67,0x33,0xb1,0x42,0x06,0xfe,0x15,0x90,0xc6,0x31,0xfa,0xbe,0x8f,0x25,
    0xf0,0x16,0xd9,0x91,0xb5,0x7f,0x3e,0xe2,0xb8,0x56,0x23,0x3a,0xde,0x9c,0x17,0x84,
    0xe9,0x40,0x0c,0x76,0xcd,0x88,0xd4,0xa3,0x89,0x87,0xb2,0x97,0xce,0x68,0xda,0xac
};

#define FLAG_LEN 27
static const unsigned char store[FLAG_LEN] = {
    0xa4,0x1c,0x7f,0x37,0x91,0x12,0xd1,0x64,
    0xe3,0x3f,0x52,0x8f,0xa4,0x7c,0x08,0xda,
    0x51,0x01,0x77,0xc9,0x51,0xc1,0xb0,0xee,
    0xcf,0x56,0x5f
};

#define TABLE_XOR 0x15
#define PASS_LEN  10

static const unsigned char pw_table[16] = {
    0xac,0xb5,0xea,0xb1,0x58,0xe9,0xab,0xea,0x4a,0xaa,0x6b,0xb5,0x1d,0x08,0x86,0x2e
};

static const unsigned char pw_idx_raw[20] = {
    0xFF, 3, 0xFE, 7, 0xFD, 1, 0xFC, 11, 0xFB, 5, 0xFA, 14, 0xF9, 0, 0xF8, 9, 0xF7, 2, 0xF6, 6
};

static int _anti_ptrace(void) {
    return (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) ? 1 : 0;
}

static int _anti_tracerpid(void) {
    char buf[512];
    char path[32], tstr[16];
    xs(path, es_pss,  sizeof(path));
    xs(tstr, es_tpid, sizeof(tstr));

    FILE *f = fopen(path, "r");
    memset(path, 0, sizeof(path));
    if (!f) return 0; 

    while (fgets(buf, sizeof(buf), f)) {
        if (strncmp(buf, tstr, strlen(tstr)) == 0) {
            int pid = 0;
            const char *p = buf + strlen(tstr);
            while (*p == ' ' || *p == '\t') p++;
            while (*p >= '0' && *p <= '9') { pid = pid*10 + (*p-'0'); p++; }
            fclose(f);
            memset(tstr, 0, sizeof(tstr));
            memset(buf,  0, sizeof(buf));
            return (pid != 0) ? 1 : 0;
        }
    }
    fclose(f);
    memset(tstr, 0, sizeof(tstr));
    return 0;
}

static int _anti_timing(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo1, hi1, lo2, hi2;
    __asm__ volatile ("rdtsc" : "=a"(lo1),"=d"(hi1));
    volatile uint32_t dummy = 0;
    for (int i = 0; i < 512; i++) dummy ^= (uint32_t)i;
    (void)dummy;
    __asm__ volatile ("rdtsc" : "=a"(lo2),"=d"(hi2));
    uint64_t t1 = ((uint64_t)hi1<<32)|lo1;
    uint64_t t2 = ((uint64_t)hi2<<32)|lo2;
    return (t2 - t1 > 5000000ULL) ? 1 : 0;
#else
    return 0;
#endif
}

static int _anti_ldpreload(void) {
    const char env_path[] = "/proc/self/environ";
    int fd = open(env_path, O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    ssize_t i = 0;
    while (i < n) {
        if (strncmp(buf+i, "LD_PRELOAD=", 11) == 0 && buf[i+11] != '\0') {
            memset(buf, 0, sizeof(buf));
            return 1;
        }
        while (i < n && buf[i] != '\0') i++;
        i++;
    }
    memset(buf, 0, sizeof(buf));
    return 0;
}

static int _anti_swbp(void) {
    extern void _start(void); 
    unsigned char *base = (unsigned char *)((uintptr_t)_start & ~0xFFFULL);
    int count = 0, i;
    for (i = 0; i < 4096; i++) {
        if (base[i] == 0xCC) count++;
    }
    return (count > 1) ? 1 : 0;
}

static void _check_debug(void) {
    char buf[64];
    int bad = 0;

    if (OP_T) bad |= _anti_ptrace();
    if (OP_T) bad |= _anti_tracerpid();
    
    static volatile int _called = 0;
    if (_called) {
        bad |= _anti_timing();
        bad |= _anti_ldpreload();
        bad |= _anti_swbp();
    }
    _called = 1;

    if (bad) {
        xs(buf, es_dbg, sizeof(buf));
        fputs(buf, stderr);
        memset(buf, 0, sizeof(buf));
        volatile char junk[256];
        memset((void*)junk, 0xCC, sizeof(junk));
        _exit(1);
    }
}

static uint32_t _text_checksum(void) {
    const unsigned char ep[] = { 0xe3,0xbc,0xbe,0xa3,0xaf,0xe3,0xbf,0xa9,0xa0,0xaa,0xe3,0xa9,0xb4,0xa9,0x00 };
    char exe_path[32];
    xs(exe_path, ep, sizeof(exe_path));

    FILE *ef = fopen(exe_path, "rb");
    memset(exe_path, 0, sizeof(exe_path));
    if (!ef) return 0xDEADBEEFUL;

    fseek(ef, 0, SEEK_END);
    long esz = ftell(ef);
    rewind(ef);
    if (esz <= 0 || esz > 0x400000) { fclose(ef); return 0xDEADBEEFUL; }

    unsigned char *edata = (unsigned char *)malloc((size_t)esz);
    if (!edata) { fclose(ef); return 0xDEADBEEFUL; }
    if ((long)fread(edata, 1, (size_t)esz, ef) != esz) {
        free(edata); fclose(ef); return 0xDEADBEEFUL;
    }
    fclose(ef);

    if (edata[0] != 0x7F || edata[1] != 'E') { free(edata); return 0; }

    uint64_t shoff    = *(uint64_t *)(edata + 0x28);
    uint16_t shentsz  = *(uint16_t *)(edata + 0x3A);
    uint16_t shnum    = *(uint16_t *)(edata + 0x3C);
    uint16_t shstrndx = *(uint16_t *)(edata + 0x3E);

    if (shoff + (uint64_t)shstrndx * shentsz + 0x28 > (uint64_t)esz) {
        free(edata); return 0;
    }
    uint64_t stroff = *(uint64_t *)(edata + shoff + shstrndx * shentsz + 0x18);

    const unsigned char et[] = { 0xe2,0xb8,0xa9,0xb4,0xb8,0x00 };
    char sname[8];
    xs(sname, et, sizeof(sname));

    uint32_t chk = 0x811C9DC5UL;
    uint16_t i;
    for (i = 0; i < shnum; i++) {
        uint64_t sh   = shoff + (uint64_t)i * shentsz;
        uint32_t noff = *(uint32_t *)(edata + sh);
        uint64_t naddr = stroff + noff;
        if (naddr >= (uint64_t)esz) continue;

        const char *name = (const char *)(edata + naddr);
        if (strncmp(name, sname, 5) != 0) continue;

        uint64_t off  = *(uint64_t *)(edata + sh + 0x18);
        uint64_t size = *(uint64_t *)(edata + sh + 0x20);
        if (off + size > (uint64_t)esz) break;

        uint64_t j;
        for (j = 0; j < size; j++) {
            chk ^= edata[off + j];
            chk *= 0x01000193UL; 
        }
        break;
    }

    memset(sname, 0, sizeof(sname));
    free(edata);
    return chk;
}

static void _derive_master_key(uint32_t chk, unsigned char mk[4]) {
    struct utsname uts;
    uint32_t hn_hash = 5381;
    if (uname(&uts) == 0) {
        const unsigned char *h = (const unsigned char *)uts.nodename;
        while (*h) { hn_hash = ((hn_hash << 5) + hn_hash) ^ *h; h++; }
    }

    uint32_t uid = (uint32_t)getuid();
    volatile uint32_t ct_seed = 0;
    ct_seed ^= 0x1234; ct_seed ^= 0x4DD8; 

    uint32_t km = (chk ^ hn_hash ^ uid ^ ct_seed);
    uint32_t a = km, b = chk, c = hn_hash, d = uid;
#define QR(x,y,z,w) \
    x+=y; w^=x; w=(w<<16)|(w>>16); \
    z+=w; y^=z; y=(y<<12)|(y>>20); \
    x+=y; w^=x; w=(w<< 8)|(w>>24); \
    z+=w; y^=z; y=(y<< 7)|(y>>25);
    QR(a,b,c,d) QR(a,b,c,d) QR(a,b,c,d)
#undef QR

    mk[0] = (unsigned char)( a        & 0xFF);
    mk[1] = (unsigned char)((b >> 8)  & 0xFF);
    mk[2] = (unsigned char)((c >> 16) & 0xFF);
    mk[3] = (unsigned char)((d >> 24) & 0xFF);
}

static int _check_password(const char *input) {
    char expected[PASS_LEN + 1];
    int i;
    for (i = 0; i < PASS_LEN; i++) {
        unsigned char idx = pw_idx_raw[1 + i*2];
        expected[i] = (char)((pw_table[idx] ^ KS) ^ TABLE_XOR);
    }
    expected[PASS_LEN] = '\0';

    int match = (strncmp(input, expected, PASS_LEN + 1) == 0);
    memset(expected, 0, sizeof(expected));
    return match;
}

static void _xtea_dec_block(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0=v[0], v1=v[1];
    uint32_t sum = 0xC6EF3720UL; 
    uint32_t delta = 0x9E3779B9UL;
    int i;
    for (i = 0; i < 32; i++) {
        v1 -= (((v0<<4)^(v0>>5)) + v0) ^ (sum + key[(sum>>11)&3]);
        sum -= delta;
        v0 -= (((v1<<4)^(v1>>5)) + v1) ^ (sum + key[sum&3]);
    }
    v[0]=v0; v[1]=v1;
}

static void _xtea_decrypt(unsigned char *data, size_t len, const unsigned char mk[4]) {
    uint32_t key[4];
    key[0] = ((uint32_t)mk[0]<<24)|((uint32_t)mk[1]<<16)|((uint32_t)mk[2]<< 8)| (uint32_t)mk[3];
    key[1] = key[0] ^ 0xDEADBEEFUL;
    key[2] = key[0] ^ 0xCAFEBABEUL;
    key[3] = key[0] ^ 0xFEEDFACEUL;

    size_t i;
    for (i = 0; i + 7 < len; i += 8) {
        uint32_t v[2];
        memcpy(v, data+i, 8);
        _xtea_dec_block(v, key);
        memcpy(data+i, v, 8);
    }
    for (; i < len; i++)
        data[i] ^= mk[i%4];
}

static int _read_urandom(unsigned char *key, size_t n) {
    char path[16];
    xs(path, es_urandom, sizeof(path));
    FILE *f = fopen(path, "rb");
    memset(path, 0, sizeof(path));
    if (!f) return 0;
    int ok = ((size_t)fread(key, 1, n, f) == n);
    fclose(f);
    return ok;
}

static void _write_output(const unsigned char *mk, pid_t pid, uint32_t chk) {
    int i;
    unsigned char blob[FLAG_LEN];

    for (i = 0; i < FLAG_LEN; i++) {
        blob[i] = store[i];
    }

    _xtea_decrypt(blob, FLAG_LEN, mk);

    for (i = 0; i < FLAG_LEN; i++)
        blob[i] ^= sbox[(i * 7 + 3) % 256];

    unsigned char rt_key[8];
    if (!_read_urandom(rt_key, 8)) {
        for (i = 0; i < 8; i++) rt_key[i] = (unsigned char)(0x42 ^ i);
    }

    unsigned char payload[FLAG_LEN];
    for (i = 0; i < FLAG_LEN; i++)
        payload[i] = blob[i] ^ rt_key[i % 8];
    memset(blob, 0, sizeof(blob));

    unsigned char pb[4];
    pb[0] = (unsigned char)((pid >> 9)  & 0xFF);
    pb[1] = (unsigned char)( pid        & 0xFF);
    pb[2] = (unsigned char)((pid >> 3)  & 0xFF);
    pb[3] = (unsigned char)((pid >> 17) & 0xFF);

    unsigned char key_obf[8];
    for (i = 0; i < 8; i++) key_obf[i] = rt_key[i] ^ pb[i%4];

    uint32_t chk_obf = chk ^ 0xFACEB00CUL;

    char opath[16];
    xs(opath, es_outfile, sizeof(opath));
    FILE *f = fopen(opath, "wb");
    memset(opath, 0, sizeof(opath));
    if (!f) { _exit(1); }

    unsigned char magic[4] = {0xFA, 0xAC, 0x77, 0x1D};
    unsigned char ver   = 0x05;
    unsigned char plen  = (unsigned char)FLAG_LEN;

    fwrite(magic,    1, 4,        f);
    fwrite(&ver,     1, 1,        f);
    fwrite(&plen,    1, 1,        f);
    fwrite(key_obf,  1, 8,        f);
    fwrite(pb,       1, 4,        f);
    fwrite(&chk_obf, 1, 4,        f);
    fwrite(payload,  1, FLAG_LEN, f);
    fclose(f);

    memset(payload,  0, sizeof(payload));
    memset(key_obf,  0, sizeof(key_obf));
    memset(rt_key,   0, sizeof(rt_key));
    memset(pb,       0, sizeof(pb));
}

static uint32_t __attribute__((noinline)) _fake_hash_a(const char *s) {
    uint32_t h = _DC3;
    while (*s) { h = (h << 5) + h + (unsigned char)*s++; }
    return h ^ _DC0;
}
static void __attribute__((noinline)) _fake_validate(const char *p, uint32_t seed) {
    uint32_t v = _fake_hash_a(p) ^ seed;
    volatile uint32_t r = v * _DC1 ^ _DC4;
    (void)r;
}
static uint32_t __attribute__((noinline)) _fake_mix(uint32_t a, uint32_t b) {
    return ((a ^ _DC2) + (b ^ _DC5)) * _DC6;
}

#define ST_INIT    0x9E37U
#define ST_CHKSUM  0x3C6EU
#define ST_BANNER  0xDAA5U
#define ST_INPUT   0x78DCU
#define ST_VERIFY  0x1713U
#define ST_DENY    0xB54AU
#define ST_GRANT   0x5381U
#define ST_OUT     0xF1B8U
#define ST_WRITE   0x8FEFU
#define ST_DONE    0x2E26U
#define ST_DEAD    0x0000U

int main(void) {
    uint32_t state = ST_INIT;
    uint32_t chk   = 0;
    char     input[128];
    unsigned char mk[4] = {0,0,0,0};
    pid_t    pid = 0;

    if (OP_F) { volatile int _x = (int)_fake_mix(0,0); (void)_x; }

    while (state != ST_DEAD) {
        switch (state) {

        case ST_INIT:
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
                char buf[64];
                xs(buf, es_dbg, sizeof(buf));
                fputs(buf, stderr);
                memset(buf, 0, sizeof(buf));
                return 1;
            }
            
            if (OP_F) { _fake_validate("", 0); state = ST_DEAD; break; }
            
            state = ST_CHKSUM;
            break;

        case ST_CHKSUM:
            chk = _text_checksum();
            state = OP_T ? ST_BANNER : ST_DEAD;
            break;

        case ST_BANNER: {
            char buf[64];
            xs(buf, es_banner, sizeof(buf)); fputs(buf, stdout); memset(buf,0,sizeof(buf));
            xs(buf, es_prompt, sizeof(buf)); fputs(buf, stdout); memset(buf,0,sizeof(buf));
            fflush(stdout);
            state = ST_INPUT;
            break;
        }

        case ST_INPUT:
            memset(input, 0, sizeof(input));
            if (!fgets(input, sizeof(input), stdin)) { state = ST_DEAD; break; }
            {
                size_t l = strlen(input);
                if (l > 0 && input[l-1] == '\n') input[--l] = '\0';
            }
            if (OP_F) {
                char lbuf[48];
                xs(lbuf, es_fake, sizeof(lbuf));
                fputs(lbuf, stdout);
                memset(lbuf, 0, sizeof(lbuf));
                state = ST_DEAD;
                break;
            }
            state = ST_VERIFY;
            break;

        case ST_VERIFY: {
            int ok = _check_password(input);
            memset(input, 0, sizeof(input));
            state = ok ? ST_GRANT : ST_DENY;
            break;
        }

        case ST_DENY: {
            char buf[32];
            xs(buf, es_denied, sizeof(buf)); fputs(buf, stdout); memset(buf,0,sizeof(buf));
            state = ST_DEAD;
            break;
        }

        case ST_GRANT: {
            char buf[64];
            xs(buf, es_granted, sizeof(buf)); fputs(buf, stdout); memset(buf,0,sizeof(buf));
            xs(buf, es_fake,    sizeof(buf)); fputs(buf, stdout); memset(buf,0,sizeof(buf));
            state = ST_OUT;
            break;
        }

        case ST_OUT:
            pid = getpid();
            _derive_master_key(chk, mk);
            state = ST_WRITE;
            break;

        case ST_WRITE:
            _write_output(mk, pid, chk);
            memset(mk, 0, sizeof(mk));
            state = ST_DONE;
            break;

        case ST_DONE: {
            char buf[64];
            xs(buf, es_done, sizeof(buf)); fputs(buf, stdout); memset(buf,0,sizeof(buf));
            state = ST_DEAD;
            break;
        }

        default:
            state = ST_DEAD;
            break;
        }
    }

    memset(input, 0, sizeof(input));
    memset(mk,    0, sizeof(mk));
    return 0;
}