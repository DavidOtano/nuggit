#include <cstdlib>
#include <cstring>
#include <string>
#include "wpn_tables.h"

namespace ng::wpn::crypt {
namespace frontcode {

/* macro magic */
#define _fct wpn_frontcode_table
#define _fcrt wpn_frontcode_reverse_table
#define _tcp0 wpn_tcp_table_0
#define _tcp1 wpn_tcp_table_1
#define _tcp2 wpn_tcp_table_2
#define _tcp3 wpn_tcp_table_3
#define _tcp4 wpn_tcp_table_4
#define _tcp6 wpn_tcp_table_6
#define _tcp7 wpn_tcp_table_7
#define _udp0 wpn_udp_table_0
#define _udp1 wpn_udp_table_1
#define _udp2 wpn_udp_table_2
#define _udp3 wpn_udp_table_3

void encrypt(const uint8_t* src, uint8_t* dst) {
    uint8_t crypt[12];

    for (int i = 0; i < 12; i++) crypt[i] = rand() % 255;

    for (int i = 9; i >= 0; i--) {
        crypt[0] = (_fcrt[0][crypt[0]] - src[i * 12 + 0]);
        crypt[1] = (_fcrt[1][crypt[1]] - src[i * 12 + 1]);
        crypt[2] = (_fcrt[2][crypt[2]] ^ src[i * 12 + 2]);
        crypt[3] = (_fcrt[3][crypt[3]] - src[i * 12 + 3]);
        crypt[4] = (_fcrt[4][crypt[4]] ^ src[i * 12 + 4]);
        crypt[5] = (_fcrt[5][crypt[5]] ^ src[i * 12 + 5]);
        crypt[6] = (_fcrt[6][crypt[6]] ^ src[i * 12 + 6]);
        crypt[7] = (_fcrt[7][crypt[7]] - src[i * 12 + 7]);
        crypt[8] = (_fcrt[8][crypt[8]] ^ src[i * 12 + 8]);
        crypt[9] = (_fcrt[9][crypt[9]] - src[i * 12 + 9]);
        crypt[10] = (_fcrt[10][crypt[10]] - src[i * 12 + 10]);
        crypt[11] = (_fcrt[11][crypt[11]] ^ src[i * 12 + 11]);

        dst[(i + 1) * 12 + 0] = src[i * 12 + 0] + crypt[0];
        dst[(i + 1) * 12 + 1] = src[i * 12 + 1] + crypt[1];
        dst[(i + 1) * 12 + 2] = src[i * 12 + 2] ^ crypt[2];
        dst[(i + 1) * 12 + 3] = src[i * 12 + 3] + crypt[3];
        dst[(i + 1) * 12 + 4] = src[i * 12 + 4] ^ crypt[4];
        dst[(i + 1) * 12 + 5] = src[i * 12 + 5] ^ crypt[5];
        dst[(i + 1) * 12 + 6] = src[i * 12 + 6] ^ crypt[6];
        dst[(i + 1) * 12 + 7] = src[i * 12 + 7] + crypt[7];
        dst[(i + 1) * 12 + 8] = src[i * 12 + 8] ^ crypt[8];
        dst[(i + 1) * 12 + 9] = src[i * 12 + 9] + crypt[9];
        dst[(i + 1) * 12 + 10] = src[i * 12 + 10] + crypt[10];
        dst[(i + 1) * 12 + 11] = src[i * 12 + 11] ^ crypt[11];
    }

    std::memcpy(crypt, dst, 12);
}

void decrypt(const uint8_t* src, uint8_t* dst) {
    uint8_t crypt[12];

    std::memcpy(crypt, src, 12);

    for (int i = 0; i < 10; i++) {
        dst[i * 12 + 0] = src[12 + i * 12 + 0] - crypt[0];
        dst[i * 12 + 1] = src[12 + i * 12 + 1] - crypt[1];
        dst[i * 12 + 2] = src[12 + i * 12 + 2] ^ crypt[2];
        dst[i * 12 + 3] = src[12 + i * 12 + 3] - crypt[3];
        dst[i * 12 + 4] = src[12 + i * 12 + 4] ^ crypt[4];
        dst[i * 12 + 5] = src[12 + i * 12 + 5] ^ crypt[5];
        dst[i * 12 + 6] = src[12 + i * 12 + 6] ^ crypt[6];
        dst[i * 12 + 7] = src[12 + i * 12 + 7] - crypt[7];
        dst[i * 12 + 8] = src[12 + i * 12 + 8] ^ crypt[8];
        dst[i * 12 + 9] = src[12 + i * 12 + 9] - crypt[9];
        dst[i * 12 + 10] = src[12 + i * 12 + 10] - crypt[10];
        dst[i * 12 + 11] = src[12 + i * 12 + 11] ^ crypt[11];

        crypt[0] = _fct[0][(dst[i * 12 + 0] + crypt[0]) & 0xFF];
        crypt[1] = _fct[1][(dst[i * 12 + 1] + crypt[1]) & 0xFF];
        crypt[2] = _fct[2][(dst[i * 12 + 2] ^ crypt[2]) & 0xFF];
        crypt[3] = _fct[3][(dst[i * 12 + 3] + crypt[3]) & 0xFF];
        crypt[4] = _fct[4][(dst[i * 12 + 4] ^ crypt[4]) & 0xFF];
        crypt[5] = _fct[5][(dst[i * 12 + 5] ^ crypt[5]) & 0xFF];
        crypt[6] = _fct[6][(dst[i * 12 + 6] ^ crypt[6]) & 0xFF];
        crypt[7] = _fct[7][(dst[i * 12 + 7] + crypt[7]) & 0xFF];
        crypt[8] = _fct[8][(dst[i * 12 + 8] ^ crypt[8]) & 0xFF];
        crypt[9] = _fct[9][(dst[i * 12 + 9] + crypt[9]) & 0xFF];
        crypt[10] =
            wpn_frontcode_table[10][(dst[i * 12 + 10] + crypt[10]) & 0xFF];
        crypt[11] =
            wpn_frontcode_table[11][(dst[i * 12 + 11] ^ crypt[11]) & 0xFF];
    }
}

}  // namespace frontcode

namespace tcp {

uint16_t get_crypt_key_id(const uint8_t* block) {
    uint8_t kb[16];

    std::memcpy(kb, block, 16);

    for (int i = 104; i >= 0; i--) {
        uint8_t b = (i) ? kb[(i - 1) & 0x0F] : 0x57;
        if (i % 5)
            kb[i & 0x0F] -= b;
        else
            kb[i & 0x0F] ^= b;
    }

    uint8_t key_id = (uint8_t)(kb[9] - (kb[14] ^ kb[8] ^ kb[1]));
    if (kb[4] != (kb[15] ^ kb[13] ^ kb[5] ^ kb[2]) ||
        (kb[12] ^ kb[10] ^ kb[7] ^ kb[6] ^ kb[3] ^ kb[0]) !=
            (uint8_t)(kb[11] - (key_id >> 7)))
        return 0xFFFF;

    return key_id;
}

void create_crypt_key_id(uint16_t id, uint8_t* block) {
    for (int i = 0; i < 16; i++) block[i] = rand() % 255;

    block[4] = block[15] ^ block[13] ^ block[5] ^ block[2];
    block[9] = (block[14] ^ block[8] ^ block[1]) + id;
    block[11] =
        (block[12] ^ block[10] ^ block[7] ^ block[6] ^ block[3] ^ block[0]) +
        (id >> 7);

    for (int i = 0; i < 105; i++) {
        uint8_t K = (i) ? block[(i - 1) & 0x0F] : 0x57;
        if (i % 5)
            block[i & 0x0F] += K;
        else
            block[i & 0x0F] ^= K;
    }
}

uint16_t get_crypt_key(const uint8_t* block, uint32_t* up_key,
                       uint32_t* down_key) {
    std::ignore = up_key;
    std::ignore = down_key;

    const uint16_t key_id = get_crypt_key_id(block);
    bool up_plus, down_plus;
    uint8_t uk0, uk1, uk2, uk3, ud, dk0, dk1, dk2, dk3, dd;
    uint32_t _up_key = 0, _down_key = 0;

    switch (key_id) {
        case 0x0050:
        case 0x0051:
            uk0 = 2;
            uk1 = 5;
            uk2 = 9;
            uk3 = 11;
            ud = 0x68;
            up_plus = false;  // SV PR
            dk0 = 4;
            dk1 = 12;
            dk2 = 10;
            dk3 = 7;
            dd = 0x67;
            down_plus = false;  // SV PR
            break;

        case 0x0052:
        case 0x0053:
            uk0 = 7;
            uk1 = 3;
            uk2 = 9;
            uk3 = 5;
            ud = 0x54;
            up_plus = true;  // SV SE
            dk0 = 2;
            dk1 = 8;
            dk2 = 13;
            dk3 = 6;
            dd = 0x55;
            down_plus = true;  // SV SE
            break;

        case 0x0057:
        case 0x0058:
            uk0 = 7;
            uk1 = 3;
            uk2 = 9;
            uk3 = 5;
            ud = 0x22;
            up_plus = false;  // SV CH
            dk0 = 2;
            dk1 = 8;
            dk2 = 13;
            dk3 = 6;
            dd = 0x7A;
            down_plus = true;  // SV CH
            break;

        default:
            return key_id;
    }

    _up_key = block[uk3];
    _up_key <<= 8;
    _up_key |= block[uk2];
    _up_key <<= 8;
    _up_key |= block[uk1];
    _up_key <<= 8;
    _up_key |= (uint8_t)((up_plus) ? (block[uk0] + ud) : (block[uk0] - ud));

    _down_key = block[dk3];
    _down_key <<= 8;
    _down_key |= block[dk2];
    _down_key <<= 8;
    _down_key |= block[dk1];
    _down_key <<= 8;
    _down_key |= (uint8_t)((down_plus) ? (block[dk0] + dd) : (block[dk0] - dd));

    if (key_id == 0x0051 || key_id == 0x0053 || key_id == 0x0058) {
        *up_key = _down_key;
        *down_key = _up_key;
    } else {
        *up_key = _up_key;
        *down_key = _down_key;
    }

    return key_id;
}

inline uint8_t encrypt1(uint8_t s, uint8_t* ckey) {
    uint8_t r = 0;

    switch (ckey[2] & 0x03) {
        case 0:
            r = ckey[1] ^ _tcp3[s];
            break;
        case 1:
            r = ckey[1] ^ _tcp7[s];
            break;
        case 2:
            r = _tcp1[ckey[0] ^ s];
            break;
        case 3:
            r = _tcp7[ckey[3] ^ s];
            break;
    }

    ckey[0] += ckey[1];
    ckey[1] ^= ckey[3];
    ckey[2] += _tcp4[r];
    ckey[3] ^= ckey[2];
    ckey[1]++;
    ckey[2]++;
    ckey[3]++;
    return r;
}

inline uint8_t decrypt1(uint8_t s, uint8_t* ckey) {
    uint8_t r = 0;
    switch (ckey[2] & 0x03) {
        case 0:
            r = _tcp2[ckey[1] ^ s];
            break;
        case 1:
            r = _tcp6[ckey[1] ^ s];
            break;
        case 2:
            r = ckey[0] ^ _tcp0[s];
            break;
        case 3:
            r = ckey[3] ^ _tcp6[s];
            break;
    }

    ckey[0] += ckey[1];
    ckey[1] ^= ckey[3];
    ckey[2] += _tcp4[s];
    ckey[3] ^= ckey[2];
    ckey[1]++;
    ckey[2]++;
    ckey[3]++;

    return r;
}

uint32_t encrypt(uint8_t* buffer, int length, uint32_t up_key) {
    uint32_t ref = up_key;

    for (int i = 0; i < length; i++)
        buffer[i] = encrypt1(buffer[i], (uint8_t*)&ref);

    return ref;
}

uint32_t decrypt(uint8_t* buffer, int length, uint32_t down_key) {
    uint32_t ref = down_key;

    for (int i = 0; i < length; i++)
        buffer[i] = decrypt1(buffer[i], (uint8_t*)&ref);

    return ref;
}

void create_genac_key(uint8_t* ac) {
    for (int j = 0; j < 6; j++) {
        ac[j] = rand() % 255;
        ac[3] = ac[1] ^ ac[2] ^ ac[4];
        ac[0] = (ac[4] ^ ac[1]) + ac[2];
        ac[5] = 0;
        uint8_t d = 0xd5;

        for (int i = 0; i < 102; i++) {
            if (i % 5 != 0) {
                ac[(i % 6)] = ac[(i % 6)] + d;
                d = ac[(i % 6)];
            } else {
                ac[(i % 6)] = ac[(i % 6)] ^ d;
                d = ac[(i % 6)];
            }
        }
    }
}

void km_mangle_nonsense(uint8_t* block) {
    block[0] = ~block[0];
    block[1] ^= 0xf0;
    block[2] ^= 0x0f;
    block[3] ^= 0x77;
    block[4] ^= 0x77;
    block[5] = ~block[5];
    block[6] ^= 0xf0;
    block[7] ^= 0x0f;
    block[8] ^= 0x77;
    block[9] ^= 0x77;
    block[10] = ~block[10];
    block[11] ^= 0xf0;
    block[12] ^= 0x0f;
    block[13] ^= 0x77;
    block[14] ^= 0x77;
}

}  // namespace tcp

namespace udp {

void encrypt(uint8_t* buffer, int length) {
    uint32_t max = (uint32_t)length + ((uint32_t)length << 4);
    if (!max) return;
    uint32_t count = 1;

    while (count < max) {
        buffer[count % (uint32_t)length] =
            _udp3[buffer[count % (uint32_t)length]] ^
            _udp1[_udp0[(count - 1) & 0xFF] ^
                  buffer[(count - 1) % (uint32_t)length]];
        count++;
    }
}

void decrypt(uint8_t* buffer, int length) {
    if (length > 5) {
        uint32_t count = (uint32_t)length + ((uint32_t)length << 4);
        while (count-- > 1)
            buffer[count % (uint32_t)length] =
                _udp2[_udp1[buffer[(count - 1) % (uint32_t)length] ^
                            _udp0[(count - 1) & 0xFF]] ^
                      buffer[count % (uint32_t)length]];
    }
}

}  // namespace udp

namespace filesystem {
inline void hash_sub(uint8_t* buffer, uint32_t length, uint8_t* hash) {
    uint8_t b, n;
    uint8_t* bp;

    if (length <= 16) return;

    b = 0xC9;
    n = 0;
    bp = buffer;

    while (bp < buffer + length - 16) {
        hash[0] += bp[0];
        hash[1] += bp[1];
        hash[2] += bp[2];
        hash[3] += bp[3];
        hash[4] += bp[4];
        hash[5] += bp[5];
        hash[6] += bp[6];
        hash[7] += bp[7];
        hash[8] += bp[8];
        hash[9] += bp[9];
        hash[10] += bp[10];
        hash[11] += bp[11];
        hash[12] += bp[12];
        hash[13] += bp[13];
        hash[14] += bp[14];
        hash[15] += bp[15];

        hash[0] ^= b;
        hash[1] ^= hash[0];
        hash[2] ^= hash[1];
        hash[3] ^= hash[2];
        hash[4] ^= hash[3];
        hash[5] ^= hash[4];
        hash[6] ^= hash[5];
        hash[7] ^= hash[6];
        hash[8] ^= hash[7];
        hash[9] ^= hash[8];
        hash[10] ^= hash[9];
        hash[11] ^= hash[10];
        hash[12] ^= hash[11];
        hash[13] ^= hash[12];
        hash[14] ^= hash[13];
        hash[15] ^= hash[14];

        b = n + hash[15];
        b = (b << 1) + (b >> 7);
        bp += 0x10;
        n++;
    }
}

bool get_file_hash(const std::string& file_path, uint32_t* hash,
                   uint32_t* length) {
    FILE* in;
    uint32_t len;
    uint32_t blockskip;

    if ((in = fopen(file_path.c_str(), "rb")) == nullptr) return false;

    uint8_t buf[0x20000];

    fseek(in, 0, SEEK_END);

    *length = (uint32_t)ftell(in);

    fseek(in, 0, SEEK_SET);

    blockskip = *length / 0x20000 / 10;
    if (blockskip < 5) blockskip = 5;

    hash[0] = hash[1] = hash[2] = hash[3] = 0;

    len = (uint32_t)fread(buf, 1, 0x20000, in);

    while (1) {
        hash_sub(buf, len, (uint8_t*)hash);
        if (len < 0x20000) break;

        fseek(in, 0x20000 * (blockskip - 1), SEEK_CUR);

        len = (uint32_t)fread(buf, 1, 0x20000, in);
    }

    fclose(in);
    return true;
}

}  // namespace filesystem

}  // namespace ng::wpn::crypt
