#ifndef NG_BAN_CONTROL_H
#define NG_BAN_CONTROL_H

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "logging.h"
#include "macro-utils.h"
#include "socket-defs.h"
#include "../config.h"

namespace ng::wpn::chat {
enum ban_type { BT_USER_IP = 0, BT_USER_PARTIAL, BT_IP, BT_IP_RANGE };

struct ban_entry_t {
    uint16_t type;
    std::string username;
    std::string ip;
    std::string from;
    std::string to;
};

struct ban_control {
    bool ban_user_partial(const std::string& partial_username) {
        if (std::any_of(bans.begin(), bans.end(), [&](const auto& ban) {
                return ban.type == BT_USER_PARTIAL &&
                       ban.username == partial_username;
            })) {
            return false;
        }

        bans.push_back(
            ban_entry_t{.type = BT_USER_PARTIAL, .username = partial_username});

        return true;
    }

    bool ban_user_ip(const std::string& username, const std::string& ip) {
        if (std::any_of(bans.begin(), bans.end(), [&](const auto& ban) {
                return ban.type == BT_USER_IP && ban.username == username &&
                       ban.ip == ip;
            })) {
            return false;
        }

        bans.push_back(
            ban_entry_t{.type = BT_USER_IP, .username = username, .ip = ip});

        return true;
    }

    bool ban_ip(const std::string& ip) {
        if (std::any_of(bans.begin(), bans.end(), [&](const auto& ban) {
                return ban.type == BT_IP && ban.ip == ip;
            })) {
            return false;
        }

        bans.push_back(ban_entry_t{.type = BT_IP, .username = "", .ip = ip});

        return true;
    }

    bool ban_ip_range(const std::string& from, const std::string& to) {
        if (std::any_of(bans.begin(), bans.end(), [&](const auto& ban) {
                return ban.type == BT_IP_RANGE && ban.from == from &&
                       ban.to == to;
            })) {
            return false;
        }

        bans.push_back(
            ban_entry_t{.type = BT_IP_RANGE, .from = from, .to = to});

        return true;
    }

    bool unban_user(const std::string& username) {
        const auto it =
            std::remove_if(bans.begin(), bans.end(), [&](const auto& ban) {
                return (ban.type == BT_USER_IP ||
                        ban.type == BT_USER_PARTIAL) &&
                       ban.username.find(username) != std::string::npos;
            });

        if (it != bans.end()) {
            bans.erase(it, bans.end());
            return true;
        }

        return false;
    }

    bool unban_ip(const std::string& ip) {
        const auto it =
            std::remove_if(bans.begin(), bans.end(), [&](const auto& ban) {
                return (ban.type == BT_IP || ban.type == BT_USER_IP) &&
                       ban.ip == ip;
            });

        if (it != bans.end()) {
            bans.erase(it, bans.end());
            return true;
        }

        return false;
    }

    bool unban_ip_range(const std::string& from, const std::string& to) {
        const auto it =
            std::remove_if(bans.begin(), bans.end(), [&](const auto& ban) {
                return (ban.type == BT_IP_RANGE) && ban.from == from &&
                       ban.to == to;
            });

        if (it != bans.end()) {
            bans.erase(it, bans.end());
            return true;
        }

        return false;
    }

    bool is_banned(const std::string& username, const std::string& ip) {
        std::string stripped = name0(username);
        return std::any_of(bans.begin(), bans.end(), [&](const auto& ban) {
            switch (ban.type) {
                case BT_USER_PARTIAL:
                    return username.find(ban.username) != std::string::npos;
                case BT_USER_IP:
                    return name0(ban.username) == stripped || ban.ip == ip;
                case BT_IP:
                    return ban.ip == ip;
                case BT_IP_RANGE:
                    auto ipaddr = ip_to_uint(ip);
                    auto from = ip_to_uint(ban.from);
                    auto to = ip_to_uint(ban.to);
                    return ipaddr >= from && ipaddr <= to;
            }

            return false;
        });
    }

    void clear() { bans.clear(); }

    bool save() {
        using ng::logging::error, ng::logging::get_error_message;
        std::ofstream banlist(get_config_file_path("banlist.conf"));

        if (!banlist.is_open()) {
            error("failed to save the banlist. {}", get_error_message(errno));
            return false;
        }

        for (const auto& ban : bans) {
            banlist << ban.type << ",";
            banlist << ban.username.length() << ",";
            banlist << ban.username << ",";
            banlist << ban.ip.length() << ",";
            banlist << ban.ip << ",";
            banlist << ban.from.length() << ",";
            banlist << ban.from << ",";
            banlist << ban.to.length() << ",";
            banlist << ban.to << "\n";
        }

        banlist.close();
        return true;
    }

    template <typename T>
    T extract_numeric(std::stringstream& ss) {
        T res;
        ss >> res;
        ss.ignore();
        return res;
    }

    void extract_string(std::stringstream& ss, std::string& str) {
        auto length = extract_numeric<size_t>(ss);
        str.resize(length);
        ss.read(&str[0], length);
        ss.ignore();
    }

    bool load() {
        std::ifstream banlist(get_config_file_path("banlist.conf"));
        if (!banlist.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(banlist, line)) {
            ban_entry_t entry;
            std::stringstream ss(line);

            entry.type = extract_numeric<uint16_t>(ss);
            extract_string(ss, entry.username);
            extract_string(ss, entry.ip);
            extract_string(ss, entry.from);
            extract_string(ss, entry.to);

            bans.push_back(entry);
        }

        return true;
    }

    std::vector<ban_entry_t> bans;
};
}  // namespace ng::wpn::chat

#endif
