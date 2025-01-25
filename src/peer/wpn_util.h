#ifndef NG_WPN_UTIL_H
#define NG_WPN_UTIL_H

#include <string>
#include "peer_types.h"

namespace ng::wpn::util {

typedef enum : uint16_t {
    ng_unknown = 0x00,
    ng_144k = 0x01,
    ng_288k = 0x02,
    ng_336k = 0x03,
    ng_56k = 0x04,
    ng_64k = 0x05,
    ng_128k = 0x06,
    ng_cable = 0x07,
    ng_dsl = 0x08,
    ng_t1 = 0x09,
    ng_t3 = 0x0A
} line_type_t;

[[maybe_unused]] static std::string get_line_type(uint16_t line_type) {
    switch (line_type) {
        case ng_unknown:
            return "Unknown";
        case ng_144k:
            return "14.4K";
        case ng_288k:
            return "28.8K";
        case ng_336k:
            return "33.6K";
        case ng_56k:
            return "56K";
        case ng_64k:
            return "64K ISDN";
        case ng_128k:
            return "128.8K ISDN";
        case ng_cable:
            return "Cable";
        case ng_dsl:
            return "DSL";
        case ng_t1:
            return "T1";
        case ng_t3:
            return "T3+";
        default:
            return "N/A";
    }
}

[[maybe_unused]] static bool is_server_type(uint16_t type) {
    switch (type) {
        case NG_PRIMARY_SERVER:
        case NG_SECONDARY_SERVER:
        case NG_CHAT_SERVER:
            return true;
    }

    return false;
}

[[maybe_unused]] static bool is_valid_type(uint16_t type) {
    switch (type) {
        case NG_PRIMARY_CLIENT:
        case NG_PRIMARY_SERVER:
        case NG_SECONDARY_CLIENT:
        case NG_SECONDARY_SERVER:
        case NG_CHAT_CLIENT:
        case NG_CHAT_SERVER:
            return true;
    }

    return false;
}

}  // namespace ng::wpn::util

#endif
