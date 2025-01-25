#ifndef NG_PACKET_H
#define NG_PACKET_H

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

// clang-format off

#define swap16(val)                                 \
        ((val << 8) & 0xFF00) |                     \
        ((val >> 8) & 0x00FF)

#define swap32(val)                                 \
        ((val >> 24) & 0x000000FF) |                \
        ((val >>  8) & 0x0000FF00) |                \
        ((val <<  8) & 0x00FF0000) |                \
        ((val << 24) & 0xFF000000)

#define swap64(val)                                 \
        ((val << 56) & 0xFF00000000000000) |        \
        ((val << 40) & 0x00FF000000000000) |        \
        ((val << 24) & 0x0000FF0000000000) |        \
        ((val <<  8) & 0x000000FF00000000) |        \
        ((val >>  8) & 0x00000000FF000000) |        \
        ((val >> 24) & 0x0000000000FF0000) |        \
        ((val >> 40) & 0x000000000000FF00) |        \
        ((val >> 56) & 0x00000000000000FF)

// clang-format on

namespace ng::wpn::proto {

class packet_buffer_t {
public:
    packet_buffer_t() : m_buffer(512), m_cur(0), m_len(0) {}

    /**
     * inserts a value into the buffer following a type-format:
     * B -> byte.
     * W -> unsigned 16bit integer (word).
     * D -> unsigned 32bit integer (dword).
     * Q -> unsignes 64bit integer (qword).
     * S -> null-terminated string.
     */
    template <typename T>
    int format(std::string_view fmt, T arg) {
        put(fmt.front(), arg);
        return 1;
    }

    /**
     * inserts values into the buffer following a type-format:
     * B -> byte.
     * W -> unsigned 16bit integer (word).
     * D -> unsigned 32bit integer (dword).
     * Q -> unsignes 64bit integer (qword).
     * S -> null-terminated string.
     */
    template <typename T, typename... Args>
    int format(std::string_view fmt, T arg, Args... args) {
        put(fmt.front(), arg);
        return 1 + format(fmt.substr(1), args...);
    }

    /**
     * puts a value from the buffer following a type-format:
     * B -> byte.
     * W -> unsigned 16bit integer (word).
     * D -> unsigned 32bit integer (dword).
     * Q -> unsignes 64bit integer (qword).
     * S -> null-terminated string.
     */
    template <typename T>
    void put(char type_code, T arg) {
        switch (type_code) {
            case 'B': { /* BYTE */
                store<uint8_t>() = (uint8_t)arg;
                break;
            }
            case 'W': { /* WORD */
                store<uint16_t>() = u16le(arg);
                break;
            }
            case 'D': { /* DWORD */
                store<uint32_t>() = u32le(arg);
                break;
            }
            case 'Q': { /* QWORD */
                store<uint64_t>() = u64le(arg);
                break;
            }
        }
    }

    /**
     * puts a value from the buffer following a type-format:
     * B -> byte.
     * W -> unsigned 16bit integer (word).
     * D -> unsigned 32bit integer (dword).
     * Q -> unsignes 64bit integer (qword).
     * S -> null-terminated string.
     */
    void put(char type_code, std::string arg) {
        switch (type_code) {
            case 'S': { /* null-terminated string */
                uint16_t len = (uint16_t)arg.length();
                size_probe(len + 1);
                std::memcpy(m_buffer.data() + m_cur, arg.c_str(), len);
                m_buffer.data()[m_cur + len] = '\0';
                m_cur += len + 1;
                m_len += len + 1;
                break;
            }
        }
    }

    /**
     * puts a value from the buffer following a type-format:
     * B -> byte.
     * W -> unsigned 16bit integer (word).
     * D -> unsigned 32bit integer (dword).
     * Q -> unsignes 64bit integer (qword).
     * S -> null-terminated string.
     */
    void put(char type_code, const char* arg) {
        switch (type_code) {
            case 'S': { /* null-terminated string */
                auto str = arg;
                uint16_t len = (uint16_t)std::strlen(str);
                size_probe(len + 1);
                std::memcpy(m_buffer.data() + m_cur, str, len);
                m_buffer.data()[m_cur + len] = '\0';
                m_cur += len + 1;
                m_len += len + 1;
                break;
            }
        }
    }

    /**
     * gets a value from the buffer following a type-format:
     * B -> byte.
     * W -> unsigned 16bit integer (word).
     * D -> unsigned 32bit integer (dword).
     * Q -> unsignes 64bit integer (qword).
     * S -> null-terminated string.
     */
    template <typename T>
    void get(char type_code, T& arg) {
        switch (type_code) {
            case 'B': /* BYTE */
                arg = static_cast<T>(retrieve<uint8_t>());
                break;
            case 'W': /* WORD */
                arg = static_cast<T>(u16(retrieve<uint16_t>()));
                break;
            case 'D': /* DWORD */
                arg = static_cast<T>(u32(retrieve<uint32_t>()));
                break;
            case 'Q': /* QWORD */
                arg = static_cast<T>(u64(retrieve<uint64_t>()));
                break;
        }
    }

    /**
     * gets a value from the buffer following a type-format:
     * B -> byte.
     * W -> unsigned 16bit integer (word).
     * D -> unsigned 32bit integer (dword).
     * Q -> unsignes 64bit integer (qword).
     * S -> null-terminated string.
     */
    void get(char type_code, std::string& arg) {
        switch (type_code) {
            case 'S': { /* null-terminated string */
                auto ptr = reinterpret_cast<char*>(m_buffer.data() + m_cur);
                arg = ptr;
                m_cur += (uint16_t)std::strlen(ptr) + 1;
                break;
            }
        }
    }

    /**
     * scans a value from the buffer following a type-format:
     * B -> byte.
     * W -> unsigned 16bit integer (word).
     * D -> unsigned 32bit integer (dword).
     * Q -> unsignes 64bit integer (qword).
     * S -> null-terminated string.
     */
    template <typename T>
    int scan(std::string_view fmt, T& arg) {
        get(fmt.front(), arg);
        return 1;
    }

    /**
     * scans values from the buffer following a type-format:
     * B -> byte.
     * W -> unsigned 16bit integer (word).
     * D -> unsigned 32bit integer (dword).
     * Q -> unsignes 64bit integer (qword).
     * S -> null-terminated string.
     */
    template <typename T, typename... Args>
    int scan(std::string_view fmt, T& arg, Args&... args) {
        get(fmt.front(), arg);
        return 1 + scan(fmt.substr(1), args...);
    }

    /**
     * resets the read/write cursor position.
     */
    void reset_cursor() { m_cur = 0; }

    /**
     * resets the buffer cursor position and length.
     */
    void reset() {
        m_cur = 0;
        m_len = 0;
    }

    /**
     * retrieves the type of the first packet in the buffer
     */
    uint16_t type() const {
        return u16(*reinterpret_cast<const uint16_t*>(m_buffer.data()));
    }

    /**
     * retrieves the length of the first packet in the buffer.
     */
    uint16_t length() const {
        if (m_len < 4) return 0;
        return u16(*reinterpret_cast<const uint16_t*>((m_buffer.data() + 2)));
    }

    /**
     * retrieves an unsigned 16bit integer from the buffer at the current
     * position.
     */
    uint16_t uint16() {
        auto ret = u16(*reinterpret_cast<uint16_t*>(m_buffer.data() + m_cur));
        m_cur += 2;
        return ret;
    }

    /**
     * retrieves an unsigned 32bit integer from the buffer at the current
     * position.
     */
    uint32_t uint32() {
        auto ret = u32(*reinterpret_cast<uint32_t*>(m_buffer.data() + m_cur));
        m_cur += 4;
        return ret;
    }

    /**
     * retrieves a null-terminated string from the buffer at the current
     * position.
     */
    std::string string() {
        std::string str = reinterpret_cast<char*>(m_buffer.data() + m_cur);
        m_cur += (uint16_t)str.length() + 1;
        return str;
    }

    /**
     * skips the header bytes (usually useless once we have the type)
     */
    void skip_header() {
        if (m_buffer.size() <= 4) {
            size_probe(4);
        }
        m_cur = 4;
    }

    /**
     * writes the packet header
     */
    void write_header(uint16_t type) {
        *reinterpret_cast<uint16_t*>(m_buffer.data()) = u16le(type);
        *reinterpret_cast<uint16_t*>(m_buffer.data() + 2) = u16le(m_len);
    }

    /**
     * copies a buffer
     */
    void insert(uint8_t* buffer, int len) {
        size_probe(len + 1);
        std::memcpy(m_buffer.data() + m_len, buffer, len);
        m_len += len;
    }

    /**
     * skips the front packet
     */
    void skip_front() {
        m_cur = 0;

        auto len = length() + 4;
        if (!m_len || m_len <= len) {
            m_len = 0;
            return;
        }

        std::memmove(m_buffer.data(), m_buffer.data() + len, m_len - len);
        m_len -= len;
    }

    operator uint8_t*() { return m_buffer.data(); }
    operator const uint8_t*() const { return m_buffer.data(); }
    operator char*() { return reinterpret_cast<char*>(m_buffer.data()); }
    operator const char*() const {
        return reinterpret_cast<const char*>(m_buffer.data());
    }
    template <typename T>
    T* data() {
        return reinterpret_cast<T*>(m_buffer.data());
    }

    uint16_t& buffer_length() { return m_len; }
    uint16_t buffer_length_with_header() const { return m_len + 4; }

protected:
    std::vector<uint8_t> m_buffer;
    uint16_t m_cur;
    uint16_t m_len;
    void size_probe(size_t len = 1) {
        while (m_len + len > m_buffer.size()) {
            m_buffer.resize(m_buffer.size() * 2);
        }
    }
    static inline bool is_le() {
        int num = 1;
        return *reinterpret_cast<char*>(&num) == 1;
    }
    static int16_t i16le(int16_t ret) { return is_le() ? ret : swap16(ret); }
    static uint16_t u16le(uint16_t ret) { return is_le() ? ret : swap16(ret); }
    static uint16_t u16(uint16_t ret) { return is_le() ? ret : swap16(ret); }
    static int16_t i16(int16_t ret) { return is_le() ? ret : swap16(ret); }
    static int32_t i32le(int32_t ret) { return is_le() ? ret : swap32(ret); }
    static int32_t i32(int32_t ret) { return is_le() ? ret : swap32(ret); }
    static uint32_t u32le(uint32_t ret) { return is_le() ? ret : swap32(ret); }
    static uint32_t u32(uint32_t ret) { return is_le() ? ret : swap32(ret); }
    static int64_t i64le(int64_t ret) { return is_le() ? ret : swap64(ret); }
    static uint64_t u64(uint64_t ret) { return is_le() ? ret : swap64(ret); }
    static uint64_t u64le(uint64_t ret) { return is_le() ? ret : swap64(ret); }
    static int64_t i64(int64_t ret) { return is_le() ? ret : swap64(ret); }

    template <typename T>
    T& store() {
        const auto sz = sizeof(T);
        const auto pos = m_cur;

        size_probe(sz);
        m_cur += sz;
        m_len += sz;
        return *reinterpret_cast<T*>(m_buffer.data() + pos);
    }

    template <typename T>
    T retrieve() {
        const auto sz = sizeof(T);
        const auto pos = m_cur;
        assert(m_cur + sz < m_buffer.size());
        m_cur += sz;
        return *reinterpret_cast<const T*>(m_buffer.data() + pos);
    }
};

}  // namespace ng::wpn::proto

#endif
