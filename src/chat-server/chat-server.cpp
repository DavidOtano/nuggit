#include <algorithm>
#include <cctype>
#include <chrono>
#include <future>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include "chat-user.h"
#if defined(_WIN32) || defined(_WIN64)
#include <winerror.h>
#endif
#include <logging.h>
#include <memory>
#include <regex>
#include <vector>
#include "chat-server.h"
#include "color-formatter.h"
#include "http.h"
#include "string-utils.h"
#include "deferred-exec.h"
#include "macro_utils.h"
#include "socket-defs.h"
#include "../nuggit-config.h"
#include "../crypt/wpn_crypt.h"
#include "semver.h"

namespace ng::wpn::chat {

#define MAX_RECEIVE_BUFFER_SZ 1024
#define STORED_MESSAGE_COUNT 10
#define LOGIN_TTL 10

using namespace ng::wpn::proto;
using namespace ng::wpn::crypt::tcp;
using namespace ng::logging;

/*
 * a shorthand to enqueue a packet to the specified user.
 */
#define enq(__ctx__, __type__, __format__, ...) \
    enqueue(__ctx__, __type__,                  \
            [&](auto& buff) { buff.format(__format__, __VA_ARGS__); })

/*
 * a shorthand to enqueue a packet to all logged in users.
 */
#define enqall(__type__, __format__, ...) \
    enqueue_all(__type__,                 \
                [&](auto& buff) { buff.format(__format__, __VA_ARGS__); })

/*
 * a shorthand macro to check if the specified user is currently logged in.
 */
#define logged_in(__ctx__) __ctx__->status.logged_in

/*
 * echo a message to the specified user
 */
#define echo(__ctx__, __text__)                                          \
    if (__ctx__->is353) {                                                \
        enq(__ctx__, 0x00D2, "S", __text__);                             \
    } else {                                                             \
        enq(__ctx__, 0x00CB, "SS", "", remove_encoded_colors(__text__)); \
    }

/*
 * echo a message to the specified user (formatted)
 */
#define echof(__ctx__, __fmt__, ...)                                   \
    if (__ctx__->is353) {                                              \
        enq(__ctx__, 0x00D2, "S", std::format(__fmt__, __VA_ARGS__));  \
    } else {                                                           \
        enq(__ctx__, 0x00CB, "SS", "",                                 \
            remove_encoded_colors(std::format(__fmt__, __VA_ARGS__))); \
    }

/*
 * echo a message to the specified user in color
 */
#define echo_clr(__ctx__, __text__) \
    echo(__ctx__, format_colorful_string(__text__, !__ctx__->is353));

/*
 * echo a message to the specified user in color (formatted)
 */
#define echo_clrf(__ctx__, __fmt__, ...)                                    \
    echo(__ctx__, format_colorful_string(std::format(__fmt__, __VA_ARGS__), \
                                         !__ctx__->is353))

#define echo_all(__text__)                  \
    for (const auto& user : m_chat_users) { \
        if (!logged_in(user)) {             \
            continue;                       \
        }                                   \
        echo(user, __text__);               \
    }

#define echo_allf(__fmt__, ...)             \
    for (const auto& user : m_chat_users) { \
        if (!logged_in(user)) {             \
            continue;                       \
        }                                   \
        echof(user, __fmt__, __VA_ARGS__);  \
    }

#define echo_all_clr(__text__)              \
    for (const auto& user : m_chat_users) { \
        if (!logged_in(user)) {             \
            continue;                       \
        }                                   \
        echo_clr(user, __text__);           \
    }

#define echo_all_clrf(__fmt__, ...)            \
    for (const auto& user : m_chat_users) {    \
        if (!logged_in(user)) {                \
            continue;                          \
        }                                      \
        echo_clrf(user, __fmt__, __VA_ARGS__); \
    }

/*
 * shutdown the user's socket for receiving and kick them after the specified
 * amount of seconds has elapsed.
 *
 * useful to allow the user to read a warning notification before being booted.
 */
#define kick_on_timer(__ctx__, __sec__)                               \
    if (__ctx__->s.shutdown(SHUT_RD)) {                               \
        __ctx__->is_shutdown = true;                                  \
        __ctx__->disconnect_after.set(std::chrono::seconds(__sec__)); \
    } else {                                                          \
        __ctx__->s.close();                                           \
    }

#define assert_command_input(__ctx__, __exp__)   \
    if (!(__exp__)) {                            \
        echo(__ctx__, "Invalid command input."); \
        return;                                  \
    }

#define assert_find_user(__ctx__, __username__, __exec__)     \
    if (!find_user_by_partial_name(__username__, __exec__)) { \
        echo(__ctx__, "Unable to find the specified user.");  \
        return;                                               \
    }

static uint64_t get_system_uptime_seconds() {
    uint64_t seconds = 0;

#if defined(_WIN32) || defined(_WIN64)
    seconds = GetTickCount64() / 1000;
#else
    std::ifstream uptime_file("/proc/uptime");
    std::string uptime_string;

    if (uptime_file.is_open()) {
        uptime_file >> uptime_string;
        seconds = std::stoull(uptime_string);
        uptime_file.close();
    } else {
        warn("error opening /proc/uptime", get_error_message(errno));
    }
#endif

    return seconds;
}

static std::string get_time_since(uint64_t elapsed_seconds) {
    auto days = elapsed_seconds / 86400;
    auto hours = (elapsed_seconds % 86400) / 3600;
    auto minutes = (elapsed_seconds % 3600) / 60;
    auto seconds = elapsed_seconds % 60;

    std::ostringstream oss;

    if (days) {
        oss << days << "d ";
    }

    if (days || hours) {
        oss << hours << "h ";
    }

    if (days || hours || minutes) {
        oss << minutes << "m ";
    }

    oss << seconds << "s";

    return oss.str();
}

static std::string get_time_since(
    const std::chrono::time_point<std::chrono::high_resolution_clock>& tp) {
    const auto elapsed = std::chrono::high_resolution_clock::now() - tp;
    const auto elapsed_seconds =
        std::chrono::duration_cast<std::chrono::seconds>(elapsed);

    return get_time_since(elapsed_seconds.count());
}

static std::string get_version_string() {
    static thread_local std::string version;

    if (version.empty()) {
        version =
            std::format("{}.{}.{}", BUILD_MAJOR, BUILD_MINOR, BUILD_NUMBER);
    }

    return version;
}

static bool is_ip(const std::string& str) {
#include "ip_regex.inc"

    if (std::regex_match(str, ip_regex)) {
        return true;
    }

    return false;
}

static bool is_ip_range(const std::string& str) {
#include "ip_range_regex.inc"

    if (std::regex_match(str, ip_range_regex)) {
        return true;
    }

    return false;
}

static std::string get_channel_hash(const std::string& ip, uint16_t port) {
    std::ostringstream stream;
    stream << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
           << ip_to_uint(ip);
    stream << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
           << port;
    return stream.str();
}

chat_server::chat_server(nuggit_config_reader& nuggit_config) noexcept
    : m_nuggit_config(nuggit_config),
      m_created_at(std::chrono::high_resolution_clock::now()),
      m_total_messages(0),
      m_total_joins(0),
      m_resolver_interval(std::chrono::seconds(144000)) {
    if (!m_ban_control.load()) {
        warn("unable to load banlist. continuing.");
    } else {
        info("banlist loaded.");
    }
}

bool chat_server::init() {
    info("starting chat server...");

    if (!m_nuggit_config.loaded()) {
        error("no server configuration loaded...");
        return false;
    }

    info("chat server started! waiting for clients...");
    info("channel name: {}_{}", chan_name(0), chan_hash());
    return true;
}

bool send_and_receive_buffered_data(std::unique_ptr<chat_user_context_t>& ctx) {
    static uint8_t buffer[MAX_RECEIVE_BUFFER_SZ] = {0};

    if (ctx->disconnect_after.is_set() && ctx->disconnect_after.has_elapsed()) {
        if (!logged_in(ctx)) {
            info("{} -> disconnected.", ctx->ip);
        } else {
            info("{} ({}) -> disconnected.", ctx->info.username, ctx->ip);
        }
        ctx->s.close();
        return false;
    }

    if (!logged_in(ctx) &&
        std::chrono::high_resolution_clock::now() - ctx->created_at >
            std::chrono::seconds(LOGIN_TTL)) {
        info("{} -> forcefully disconnected due to timeout.", ctx->ip);
        ctx->s.close();
        return false;
    }

    if (!ctx->is_shutdown) {
        auto res = ctx->s.receive(reinterpret_cast<char*>(buffer),
                                  MAX_RECEIVE_BUFFER_SZ, 0);

        if (res == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                if (!logged_in(ctx)) {
                    info("{} -> disconnected: {}", ctx->ip,
                         get_error_message(WSAGetLastError()));
                } else {
                    info("{} ({}) -> disconnected: {}", ctx->info.username,
                         ctx->ip, get_error_message(WSAGetLastError()));
                }
                ctx->s.close();
                return false;
            }
        } else if (res == 0) {
            if (!logged_in(ctx)) {
                info("{} -> disconnected.", ctx->ip);
            } else {
                info("{} ({}) -> disconnected.", ctx->info.username, ctx->ip);
            }
            ctx->s.close();
            return false;
        } else {
            ctx->keys.down = decrypt(buffer, res, ctx->keys.down);
            ctx->recv_buffer.insert(buffer, res);
        }
    }

    uint16_t& len = ctx->send_buffer.buffer_length();
    if (len > 0) {
        auto res = ctx->s.send(ctx->send_buffer, len, 0);
        if (res == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                info("{} -> disconnected: {}", ctx->ip,
                     get_error_message(WSAGetLastError()));
                ctx->s.close();
                return false;
            }
        } else {
            if (len > (size_t)res) {
                std::memmove(ctx->send_buffer.data<char>(),
                             ctx->send_buffer.data<char>() + res, len - res);
            }
            len -= res;
        }
    }

    return true;
}

bool chat_server::process() {
    /* remove disconnected users */
    std::erase_if(m_chat_users, [&](std::unique_ptr<chat_user_context_t>& ctx) {
        const auto remove = !send_and_receive_buffered_data(ctx);
        if (remove && ctx->status.logged_in) {
            notify_has_parted(ctx);
        }
        return remove;
    });

    for (const auto& user : m_chat_users) {
        /* ping */
        if (user->ping.is_set() && user->ping.has_elapsed()) {
            user->ping.reset();
            enq(user, 0xFDE8, "B", 0);
        }

        /* handle queued packets */
        uint16_t& len = user->recv_buffer.buffer_length();
        if (len >= 4 && user->recv_buffer.length() + 4 <= len) {
            if (handle_packet(user)) {
                user->recv_buffer.skip_front();
            }
        }
    }

    return true;
}

void chat_server::enqueue_all(const uint8_t* buffer, uint16_t len) {
    for (const auto& ctx : m_chat_users) {
        if (!logged_in(ctx)) {
            continue;
        }
        enqueue(ctx, buffer, len);
    }
}

void chat_server::enqueue_all(
    uint16_t type, const std::function<void(packet_buffer_t& buffer)>& writer) {
    const auto& buffer = write_packet(type, writer);
    enqueue_all(buffer, buffer.buffer_length_with_header());
}

void chat_server::enqueue(const std::unique_ptr<chat_user_context_t>& ctx,
                          const uint8_t* buffer, uint16_t len) {
    uint8_t tmp_buffer[MAX_RECEIVE_BUFFER_SZ] = {0};
    memcpy(tmp_buffer, buffer, len);

    ctx->keys.up = encrypt(tmp_buffer, len, ctx->keys.up);
    ctx->send_buffer.insert(tmp_buffer, len);
}

void chat_server::enqueue(
    const std::unique_ptr<chat_user_context_t>& ctx, uint16_t type,
    const std::function<void(packet_buffer_t& buffer)>& writer) {
    const auto& buffer = write_packet(type, writer);
    enqueue(ctx, buffer, buffer.buffer_length_with_header());
}

bool chat_server::handle_packet(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    ctx->recv_buffer.reset_cursor();

    /* client id/version packet */
    if (ctx->recv_buffer.type() == 0x9905) {
        ctx->recv_buffer.skip_header();
        ctx->recv_buffer.scan("SS", ctx->client_name, ctx->client_version);
        ctx->recv_buffer.skip_front();
        return true;
    }

    if (!logged_in(ctx)) {
        switch (ctx->recv_buffer.type()) {
            case 0x0064: /* join request */
                if (!handle_join(ctx)) {
                    return false;
                }
                break;
            case 0x13ED: /* 3.53 support */
                ctx->is353 = true;
                break;
            case 0x13EE: /* user redirected from another channel */
                ctx->recv_buffer.skip_header();
                ctx->recv_buffer.scan("S", ctx->redirected_from);
                /* TODO: add redirect blocking */
                break;
            default:
                info("unhandled pre-login packet type: {}",
                     ctx->recv_buffer.type());
                print_packet(ctx);
                break;
        }

        return true;
    }

    switch (ctx->recv_buffer.type()) {
        case 0x00C8:
        case 0x1450: /* message */
            handle_message(ctx);
            break;
        case 0x0065: /* rename */
            handle_rename(ctx);
            break;
        case 0x9901:
            handle_ipsend(ctx);
            break;
        case 0x00CA: {
            std::string text;
            ctx->recv_buffer.skip_header();
            ctx->recv_buffer.scan("S", text);
            handle_action_command(ctx, text);
            break;
        }
        case 0xFDE8: /* ping */
            break;
        default:
            info("unhandled packet type: {}", ctx->recv_buffer.type());
            print_packet(ctx);
            break;
    }

    return true;
}

void chat_server::handle_ipsend(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    ctx->ipsend_enabled = true;

    for (const auto& user : m_chat_users) {
        if (!logged_in(ctx)) {
            continue;
        }

        enq(ctx, 0x9902, "SDWWWBSS", user->info.username, user->info.primary.ip,
            user->info.primary.port, user->info.files, user->info.line_type,
            user->rank(), user->ip, user->hostname);
    }

    enq(ctx, 0x9903, "B", 0);
}

bool chat_server::is_username_taken(
    const std::string& username,
    const std::unique_ptr<chat_user_context_t>& exclude) const {
    if (std::any_of(m_chat_users.begin(), m_chat_users.end(),
                    [&](const auto& user) {
                        if (user == exclude) {
                            return false;
                        }
                        return logged_in(user) &&
                               name0(user->info.username) == name0(username);
                    })) {
        return true;
    }

    return false;
}

bool chat_server::is_channelname_valid(const std::string& channelname) {
    static thread_local std::regex channelname_regex("^.+_[0-9a-fA-F]{12}$");

    return std::regex_match(channelname, channelname_regex);
}

void chat_server::notify_topic(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    std::string topic = "";
    if (m_nuggit_config.chat_server().topics().size() > 0) {
        topic = m_nuggit_config.chat_server().topics()[0];
    }

    enq(ctx, 0x012C, "S", topic);
}

void chat_server::notify_motd(const std::unique_ptr<chat_user_context_t>& ctx) {
    using ng::string::utils::replace;
    echo(ctx, " ");
    for (const auto& line : m_nuggit_config.chat_server().motd()) {
        std::string mut_line = line;

        interpolate_name(ctx, mut_line);
        mut_line = format_colorful_string(mut_line, false);
        interpolate_raw_name(ctx, mut_line);
        interpolate_motd_variables(ctx, mut_line);

        echo(ctx, mut_line);
    }
    echo(ctx, " ");
}

void chat_server::notify_chat_history(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    if (!m_nuggit_config.chat_server().show_chat_history() ||
        !m_chat_history.size()) {
        return;
    }

    auto header = m_nuggit_config.chat_server().chat_history_header();
    if (!header.empty()) {
        std::string line;
        std::stringstream ss(header);

        while (std::getline(ss, line)) {
            echo_clr(ctx, line);
        }
    }

    for (const auto& message : m_chat_history) {
        echo_clr(ctx, message);
    }

    auto footer = m_nuggit_config.chat_server().chat_history_footer();
    if (!footer.empty()) {
        std::string line;
        std::stringstream ss(footer);

        while (std::getline(ss, line)) {
            echo_clr(ctx, line);
        }
    }
}

void chat_server::notify_userlist(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    for (const auto& user : m_chat_users) {
        if (!logged_in(user)) {
            continue;
        }

        if (ctx->is353) {
            enq(ctx, 0x0072, "SDWWDB", user->info.username,
                user->info.primary.ip, user->info.primary.port,
                user->info.line_type, user->info.files, user->rank());
        } else {
            enq(ctx, 0x006F, "SDWWDB", user->info.username,
                user->info.primary.ip, user->info.primary.port,
                user->info.line_type, user->info.files);
        }
    }
}

void chat_server::notify_join(const std::unique_ptr<chat_user_context_t>& ctx) {
    using ng::string::utils::replace;

    std::string formatted_join_string;
    std::string formatted_join_string_ip;
    const auto fancy_entry = m_nuggit_config.chat_server().fancy_entry();
    if (fancy_entry) {
        formatted_join_string =
            m_nuggit_config.chat_server().fancy_entry_message();
        formatted_join_string_ip =
            m_nuggit_config.chat_server().fancy_entry_message_ip();
        interpolate_name(ctx, formatted_join_string);
        interpolate_name(ctx, formatted_join_string_ip);
        replace(formatted_join_string, "$FILES$",
                std::format("{}", ctx->info.files));
        replace(formatted_join_string_ip, "$FILES$",
                std::format("{}", ctx->info.files));
        replace(formatted_join_string, "$LINE$",
                util::get_line_type(ctx->info.line_type));
        replace(formatted_join_string_ip, "$LINE$",
                util::get_line_type(ctx->info.line_type));
        replace(formatted_join_string_ip, "$IP$", ctx->ip);
    } else {
        formatted_join_string = std::format(
            "{}{} {}({} {} files) has entered", COL(4), ctx->info.username,
            COL(4), util::get_line_type(ctx->info.line_type), ctx->info.files);
    }
    append_chat_history(formatted_join_string);

    const auto ip = ip_to_uint(ctx->ip);
    for (const auto& user : m_chat_users) {
        if (!logged_in(user)) {
            continue;
        }

        if (user->is353 && fancy_entry && !user->has_access('b')) {
            enq(user, 0x0072, "SDWWDB", ctx->info.username,
                ctx->info.primary.ip, ctx->info.primary.port,
                ctx->info.line_type, ctx->info.files, ctx->rank());

            if (!user->has_access('I')) {
                echo_clr(user, formatted_join_string);
            } else {
                echo_clr(user, formatted_join_string_ip);
            }
        } else if (!user->has_access('I') && user->is353) {
            enq(user, 0x0071, "SDWWDB", ctx->info.username,
                ctx->info.primary.ip, ctx->info.primary.port,
                ctx->info.line_type, ctx->info.files, ctx->rank());
        } else if (user->is353) {
            enq(user, 0x0075, "SDWWDBD", ctx->info.username,
                ctx->info.primary.ip, ctx->info.primary.port,
                ctx->info.line_type, ctx->info.files, ctx->rank(), ip);
        } else { /* 3.31 */
            enq(user, 0x006E, "SDWWD", ctx->info.username, ctx->info.primary.ip,
                ctx->info.primary.port, ctx->info.line_type, ctx->info.files);
        }

        if (user->ipsend_enabled) {
            enq(user, 0x9902, "SDWWWBSS", ctx->info.username,
                ctx->info.primary.ip, ctx->info.primary.port, ctx->info.files,
                ctx->info.line_type, ctx->rank(), ctx->ip, ctx->hostname);
        }
    }
}

void chat_server::notify_rename(const std::unique_ptr<chat_user_context_t>& ctx,
                                const std::string& new_username,
                                uint32_t new_pri_ip, uint16_t new_pri_port,
                                uint16_t new_line_type, uint16_t new_files) {
    if (m_nuggit_config.chat_server().rename_notification() &&
        new_username != ctx->info.username) {
        using ng::string::utils::replace;
        auto rename_format =
            m_nuggit_config.chat_server().rename_notification_format();

        const auto username = ctx->info.username;
        replace(rename_format, "$NEWNAME$", name9(new_username));
        replace(rename_format, "$NEWNAME0$", name0(new_username));
        replace(rename_format, "$NEWNAME3$", name3(new_username));
        replace(rename_format, "$NEWNAME9$", name9(new_username));
        interpolate_name(ctx, rename_format);
        echo_all_clr(rename_format);
    }

    const auto buff353 = write_packet(0x0074, [&](auto& buffer) {
        buffer.format("SDWSDWWDB", ctx->info.username, ctx->info.primary.ip,
                      ctx->info.primary.port, new_username, new_pri_ip,
                      new_pri_port, new_line_type, new_files, ctx->rank());
    });

    const auto buff331 = write_packet(0x0070, [&](auto& buffer) {
        buffer.format("SDWSDWWD", ctx->info.username, ctx->info.primary.ip,
                      ctx->info.primary.port, new_username, new_pri_ip,
                      new_pri_port, new_line_type, new_files);
    });

    for (const auto& user : m_chat_users) {
        if (!logged_in(user)) {
            continue;
        }

        if (user->is353) {
            enqueue(user, buff353, buff353.buffer_length_with_header());
        } else {
            enqueue(user, buff331, buff331.buffer_length_with_header());
        }
    }
}

void chat_server::notify_has_parted(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    if (ctx->is_hidden) {
        return;
    }

    const auto parted_string =
        std::format("{}{} {}has left", COL(5), ctx->info.username, COL(5));
    append_chat_history(parted_string);

    enqall(0x0073, "SDW", ctx->info.username, ctx->info.primary.ip,
           ctx->info.primary.port);
}

void chat_server::notify_redirect(const std::string& channelname) {
    enqall(0x0190, "S", channelname);
}

void chat_server::notify_exile(const std::unique_ptr<chat_user_context_t>& ctx,
                               const std::string& channelname) {
    enq(ctx, 0x0190, "S", channelname);
}

void chat_server::notify_join_request_accepted(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    packet_buffer_t composite_packet;
    composite_packet.reset();
    composite_packet.skip_header();
    composite_packet.format("B", 0x31);

    if (ctx->is353 && m_nuggit_config.chat_server().fancy_entry()) {
        /**
         * HACK: necessary to get RoboMX to close the system window when using
         * fancy entry messages. ¯\_(ツ)_/¯
         *
         * pretty clever solution as RoboMX will continue reading the buffer
         * as if the packets are separate. WinMX will ignore everything past '1'
         * (0x31).
         */

        /* server identifier/version packet */
        composite_packet.insert_at_cursor(
            write_packet(0x9905, [&](auto& buffer) {
                buffer.format("SS", "nuggit", get_version_string());
            }));

        /* user has joined (3.31) */
        composite_packet.insert_at_cursor(
            write_packet(0x006E, [&](auto& buffer) {
                buffer.format("SDWWD", ctx->info.username, ctx->info.primary.ip,
                              ctx->info.primary.port, ctx->info.line_type,
                              ctx->info.files);
            }));

        /* user has left */
        composite_packet.insert_at_cursor(
            write_packet(0x0073, [&](auto& buffer) {
                buffer.format("SDW", ctx->info.username, ctx->info.primary.ip,
                              ctx->info.primary.port);
            }));
    }

    composite_packet.write_header(0x0066);
    enqueue(ctx, composite_packet,
            composite_packet.buffer_length_with_header());
}

bool chat_server::handle_join(const std::unique_ptr<chat_user_context_t>& ctx) {
    return std::visit(
        join_state_visitor{
            [&](std::monostate&) {
                ctx->recv_buffer.skip_header();
                ctx->recv_buffer.scan("SWDWDS", ctx->info.channelname,
                                      ctx->info.line_type, ctx->info.primary.ip,
                                      ctx->info.primary.port, ctx->info.files,
                                      ctx->info.username);

                ctx->client_name = "WinMX";
                ctx->client_version = ctx->is353 ? "3.53" : "3.31";

                notify_join_request_accepted(ctx);

                enq(ctx, 0x9905, "SS", "nuggit", get_version_string());

                if (ctx->is353) {
                    enq(ctx, 0x0068, "B", 0x31);
                    enq(ctx, 0x9904, "S", "#c%d#");
                }

                if (m_ban_control.is_banned(ctx->info.username, ctx->ip)) {
                    echo(ctx, "You have been banned.");
                    info("banned user {} ({}) attempted to enter.",
                         ctx->info.username, ctx->ip);
                    kick_on_timer(ctx, 5);
                    return true;
                }

                if (!check_capacity()) {
                    echo(ctx, "Server is at capacity. Please try again later.");
                    kick_on_timer(ctx, 5);
                    return true;
                }

                /* validate the user details */
                if (!validate_user(ctx)) {
                    info("{} -> login rejected due to invalid username...",
                         ctx->ip);
                    kick_on_timer(ctx, 5);
                    return true;
                }

                /* send server signature, topic, motd, and user list */
                echof(ctx, "This channel is powered by nuggit {}",
                      get_version_string());

                echof(ctx, "{}Resolving {}country...", COL(2), COL(2));
                ctx->join_state = resolve_country(ctx->ip);

                return false;
            },
            [&](std::future<country_result>& fut) {
                if (fut.wait_for(std::chrono::seconds(0)) !=
                    std::future_status::ready) {
                    return false;
                }

                ctx->country = fut.get().country;

                echof(ctx, "{}Resolving {}hostname...", COL(2), COL(2));
                ctx->join_state = resolve_hostname(ctx->ip);
                return false;
            },
            [&](std::future<hostname_result>& fut) {
                if (fut.wait_for(std::chrono::seconds(0)) !=
                    std::future_status::ready) {
                    return false;
                }

                ctx->hostname = fut.get().hostname;

                notify_topic(ctx);
                notify_motd(ctx);
                notify_chat_history(ctx);
                notify_userlist(ctx);

                /* notify ipsend support */
                if (ctx->is353) {
                    enq(ctx, 0x9900, "B", 0x31);
                }

                m_total_joins++;
                ctx->status.logged_in = true;

                /* send join notification */
                info("{} -> {} has joined.", ctx->ip, ctx->info.username);
                notify_join(ctx);
                ctx->access =
                    m_nuggit_config.chat_server_login().default_access();
                ctx->format =
                    m_nuggit_config.chat_server_login().default_format();

                /* set ping timer */
                ctx->ping.set(std::chrono::seconds(60));

                return true;
            }},
        ctx->join_state);
}

void chat_server::handle_message(
    const std::unique_ptr<chat_user_context_t>& ctx, const std::string& msg) {
    using ng::string::utils::replace;

    std::string message = msg;

    /* if no message was passed in, retrieve it from the packet */
    if (message.empty()) {
        ctx->recv_buffer.skip_header();
        ctx->recv_buffer.scan("S", message);
        message = message.substr(0, ctx->recv_buffer.length());
    }

    if (!ctx->has_access('F') && !ctx->spam_ctrl.can_send()) {
        if (ctx->spam_ctrl.should_notify > 0) {
            echo(ctx, "You've been throttled for spamming.");
            info("{} ({}) has been throttled for spamming.", ctx->info.username,
                 ctx->ip);
        }
        return;
    }

    if (message.find("#\\n#") != std::string::npos && ctx->has_access('N')) {
        replace(message, "#\\n#", "\n");
        std::stringstream ss(message);
        std::string message_line;
        while (std::getline(ss, message_line)) {
            handle_message(ctx, message_line);
        }
        return;
    }

    ctx->last_message = message;
    ctx->message_count++;
    m_total_messages++;
    info("<{}> {}", name0(ctx->info.username), message);
    if (!sanity_check(message)) {
        echo(ctx, "llegal pattern detected. Message blocked.");
        return;
    }

    if (message.front() == '/') {
        handle_command(ctx, message);
        return;
    }

    if (!ctx->has_access('a')) {
        echo(ctx, "You are silenced. Please try again later.");
        return;
    }

    std::string formatted = ctx->format;
    interpolate_name(ctx, formatted);
    replace(formatted, "$TEXT$", message);
    append_chat_history(formatted);

    for (const auto& user : m_chat_users) {
        if (!logged_in(user)) {
            continue;
        }

        if (user->is353 && !user->has_access('b') && user->has_access('C')) {
            echo_clr(user, formatted);
        } else {
            if (user->has_access('b')) {
                enq(user, 0x00C9, "SSB", ctx->info.username, message,
                    ctx->rank());
            } else {
                enq(user, 0x00C9, "SSB",
                    format_colorful_string(name0(ctx->info.username), true),
                    format_colorful_string(message, true), ctx->rank());
            }
        }
    }
}

void chat_server::handle_rename(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    ctx->recv_buffer.skip_header();
    std::string username;
    uint32_t pri = 0, files = 0;
    uint16_t port = 0, line = 0;

    ctx->recv_buffer.scan("WDWDS", line, pri, port, files, username);

    if (!is_username_valid(username)) {
        echo(ctx, "Invalid username.");
        kick_on_timer(ctx, 5);
        return;
    }

    if (is_username_taken(username, ctx)) {
        echo(ctx, "Username already taken.");
        kick_on_timer(ctx, 5);
        return;
    }

    notify_rename(ctx, username, pri, port, line, files);

    if (ctx->info.username != username) {
        info("{} renamed to {}", ctx->info.username, username);
    }

    ctx->info.username = username;
    ctx->info.primary.ip = pri;
    ctx->info.primary.port = port;
    ctx->info.line_type = line;
    ctx->info.files = files;
}

void chat_server::print_packet(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    std::stringstream ss;
    ss << std::hex;

    for (auto i = 0; i < ctx->recv_buffer.length(); ++i) {
        ss << std::setw(2) << std::setfill('0')
           << (int)ctx->recv_buffer.data<uint8_t>()[i + 4] << " ";
    }

    info("{}", ss.str());
}

void chat_server::handle_command(
    const std::unique_ptr<chat_user_context_t>& ctx, const std::string& command,
    bool is_hidden) {
    static std::vector<std::string> ignored_commands = {
        "/me ",         "/action ", "/emote ",   "/login ",
        "/forcelogin ", "/opmsg ",  "/message ", "/hidecmd "};
    lazy::deferred_exec deferred;
    bool suppress_invalid = false;

    auto cmd = command;
    string::utils::to_lower(cmd);

    auto should_ignore = std::any_of(
        ignored_commands.begin(), ignored_commands.end(),
        [&](const auto& ignored_cmd) { return cmd.starts_with(ignored_cmd); });

    if (cmd.starts_with("/hidecmd ")) {
        if (!ctx->has_access('H')) {
            should_ignore = false;
            suppress_invalid = true;

            deferred.enqueue([&]() {
                echo(ctx, "Insufficient access to perform this action.");
            });
        } else {
            handle_command(ctx, skip_space(command), true);
            return;
        }
    }

    if (!should_ignore && !is_hidden) {
        echof(ctx, "{}> {}{}", COL(8), COL(1), command);
        for (const auto& user : m_chat_users) {
            if (user == ctx || !logged_in(user) || !user->has_access('W')) {
                continue;
            }

            echof(user, "{}<{}> {}{}", COL(8), ctx->info.username, COL(1),
                  command);
        }
    }

    if (cmd.starts_with("/me ") || cmd.starts_with("/action ") ||
        cmd.starts_with("/emote ")) {
        handle_action_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/login ")) {
        handle_login_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/kick ")) {
        handle_kick_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/ban ")) {
        handle_ban_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/kickban ")) {
        handle_kickban_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/unban ")) {
        handle_unban_command(ctx, skip_space(command));
    } else if (cmd == "/listbans") {
        handle_listbans_command(ctx);
    } else if (cmd == "/clearbans") {
        handle_clearbans_command(ctx);
    } else if (cmd == "/hide" || cmd.starts_with("/hide ")) {
        const auto len = skip_space_or_eos(command);
        handle_hide_command(ctx, command.substr(len));
    } else if (cmd.starts_with("/redirect ")) {
        handle_redirect_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/exile ")) {
        handle_exile_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/forcelogin ")) {
        handle_forcelogin_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/setaccess ")) {
        handle_setaccess_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/setformat ")) {
        handle_setformat_command(ctx, skip_space(command));
    } else if (cmd == "/color" || cmd == "/colors" || cmd == "/colour" ||
               cmd == "/colours") {
        handle_color_command(ctx);
    } else if (cmd.starts_with("/opmsg ")) {
        handle_opmsg_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/notice ")) {
        handle_notice_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/gnotice ")) {
        handle_gnotice_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/privnotice ")) {
        handle_privnotice_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/message ")) {
        handle_message_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/stats")) {
        const auto len = skip_space_or_eos(command);
        handle_stats_command(ctx, command.substr(len));
    } else if (cmd == "/access") {
        handle_access_command(ctx);
    } else if (cmd == "/logout") {
        handle_logout_command(ctx);
    } else if (cmd == "/bot") {
        handle_bot_command(ctx);
    } else if (cmd.starts_with("/channelname ") ||
               cmd.starts_with("/channelname2 ") ||
               cmd.starts_with("/channelname3 ")) {
        auto index = *std::find_if(command.begin(), command.end(), ::isdigit);

        if (index == '\0') {
            index = '1';
        }

        handle_channelname_command(ctx, skip_space(command), index - '0');
    } else if (cmd.starts_with("/topic ") || cmd.starts_with("/topic2 ") ||
               cmd.starts_with("/topic3 ")) {
        auto index = *std::find_if(command.begin(), command.end(), ::isdigit);

        if (index == '\0') {
            index = '1';
        }

        handle_topic_command(ctx, skip_space(command), index - '0');
    } else if (cmd == "/motd") {
        handle_motd_command(ctx);
    } else if (cmd.starts_with("/setmotd ")) {
        handle_setmotd_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/addmotd ")) {
        handle_addmotd_command(ctx, skip_space(command));
    } else if (cmd.starts_with("/limit ")) {
        handle_limit_command(ctx, skip_space(command));
    } else if (cmd == "/reload") {
        handle_reload_command(ctx);
    } else if (cmd == "/who") {
        handle_who_command(ctx);
    } else if (!suppress_invalid) {
        echo(ctx, "Invalid command.");
    }
}

void chat_server::handle_action_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "A")) {
        return;
    }

    const auto stripped_username =
        name0(format_colorful_string(ctx->info.username, true));
    const auto action_formatted =
        std::format("{}{} {}{}", COL(3), stripped_username, COL(3), command);
    append_chat_history(action_formatted);

    for (const auto& user : m_chat_users) {
        if (!logged_in(user)) {
            continue;
        }

        if (ctx->is353 && !user->has_access('b')) {
            echo(user, action_formatted);
        } else {
            enq(user, 0x00CB, "SS",
                ctx->has_access('b') ? ctx->info.username : stripped_username,
                command);
        }
    }
}

void chat_server::handle_login_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command)) {
        return;
    }

    std::string access, format;
    const auto rank = ctx->rank();

    if (m_nuggit_config.chat_server_login().with_password(command, access,
                                                          format)) {
        ctx->access = access;
        ctx->format = format;

        echo(ctx, "Login successful.");
        echof(ctx, "Access: {}", access);

        if (rank != ctx->rank()) {
            notify_rename(ctx, ctx->info.username, ctx->info.primary.ip,
                          ctx->info.primary.port, ctx->info.line_type,
                          ctx->info.files);
        }

        return;
    }

    echo(ctx, "Invalid login.");
}

void chat_server::handle_kick_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "K")) {
        return;
    }

    const auto exec = [&](const auto& user) {
        if (user->has_access('P') && !check_access(ctx, "k")) {
            return;
        }

        user->s.close();
    };

    assert_find_user(ctx, command, exec);
}

void chat_server::handle_ban_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "B")) {
        return;
    }

    const auto exec = [&](const auto& user) {
        if (user->has_access('P') && !check_access(ctx, "k")) {
            return;
        }

        info("{} ({}) has been banned.", user->info.username, user->ip);
        m_ban_control.ban_user_ip(user->info.username, user->ip);
    };

    if (find_user_by_partial_name(command, exec)) {
        echo(ctx, "The user has been banned.");
    } else if (is_ip(command)) {
        m_ban_control.ban_ip(command);
        info("ip banned: {}", command);
        echof(ctx, "IP banned: {}", command);
    } else if (is_ip_range(command)) {
        std::string from, to;
        extract_ip_range(command, from, to);

        if (from == to) {
            handle_ban_command(ctx, from);
            return;
        }

        m_ban_control.ban_ip_range(from, to);
        info("ip range banned: {}-{}", from, to);
        echof(ctx, "IP range banned: {}-{}", from, to);
    } else {
        info("partial name banned: {}", command);
        m_ban_control.ban_user_partial(command);
    }

    if (!m_ban_control.save()) {
        warn("unable to save the banlist. {}", get_error_message(errno));
    }
}

void chat_server::handle_kickban_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "KB")) {
        return;
    }

    const auto exec = [&](const auto& user) {
        if (user->has_access('P') && !check_access(ctx, "k")) {
            return;
        }

        info("{} ({}) has been banned.", user->info.username, user->ip);
        echof(ctx, "{} has been banned.", user->info.username);

        m_ban_control.ban_user_ip(user->info.username, user->ip);
        if (!m_ban_control.save()) {
            warn("unable to save the banlist. {}", get_error_message(errno));
        }

        user->s.close();
    };

    assert_find_user(ctx, command, exec);
}

void chat_server::handle_unban_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "U")) {
        return;
    }

    if (is_ip(command)) {
        if (!m_ban_control.unban_ip(command)) {
            echo(ctx,
                 "Could not locate the specified IP in the ban list. Did you "
                 "make a mistake?");
            return;
        }

        echof(ctx, "IP {} has been unbanned.", command);
    } else if (is_ip_range(command)) {
        std::string from, to;
        extract_ip_range(command, from, to);
        if (!m_ban_control.unban_ip_range(from, to)) {
            echo(ctx,
                 "Could not locate the specified IP range in the ban list. Did "
                 "you make a mistake?");
            return;
        }

        echof(ctx, "IP range {}-{} has been unbanned.", from, to);
    } else {
        if (m_ban_control.unban_user(command)) {
            echo(ctx,
                 "Could not locate any records containing '{}' in the ban "
                 "list. Did you make a mistake?");
            return;
        }

        echof(ctx, "Successfully removed all ban records containing '{}'",
              command);
    }

    if (!m_ban_control.save()) {
        warn("unable to save the banlist. {}", get_error_message(errno));
    }
}

void chat_server::handle_listbans_command(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    if (!check_access(ctx, "L")) {
        return;
    }

    if (m_ban_control.bans.size() == 0) {
        echo(ctx, "The ban list is empty. :-)");
        return;
    }

    echo(ctx, "Ban list:");
    for (const auto& ban : m_ban_control.bans) {
        switch (ban.type) {
            case BT_USER_IP:
                echof(ctx, "User banned: {} - {}", ban.username, ban.ip);
                break;
            case BT_USER_PARTIAL:
                echof(ctx, "Partial/full username banned: '{}'", ban.username);
                break;
            case BT_IP:
                echof(ctx, "IP banned: {}", ban.ip);
                break;
            case BT_IP_RANGE:
                echof(ctx, "IP range banned: {}-{}", ban.from, ban.to);
                break;
        }
    }
    echo(ctx, " ");
}

void chat_server::handle_clearbans_command(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    if (!check_access(ctx, "U")) {
        return;
    }

    m_ban_control.clear();

    echo(ctx, "The banlist has been cleared. :-)");

    if (!m_ban_control.save()) {
        warn("unable to save the banlist. {}", get_error_message(errno));
    }
}

void chat_server::handle_hide_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (!check_access(ctx, "h")) {
        return;
    }

    const auto echo_message_hide = "You've been hidden.";
    const auto echo_message_unhide = "You're no longer hidden.";
    if (command.length() == 0) {
        if (!ctx->is_hidden) {
            echo(ctx, echo_message_hide);
            notify_has_parted(ctx);
        } else {
            echo(ctx, echo_message_unhide);
            notify_join(ctx);
        }
        ctx->is_hidden = !ctx->is_hidden;
        return;
    }

    const auto exec = [&](const auto& user) {
        if (user->is_hidden) {
            echo(user, echo_message_hide);
            echof(ctx, "{} has been hidden.", ctx->info.username);
            notify_has_parted(user);
        } else {
            echo(user, echo_message_unhide);
            echof(ctx, "{} is no longer hidden.", ctx->info.username);
            notify_join(user);
        }
        user->is_hidden = !user->is_hidden;
    };

    assert_find_user(ctx, command, exec);
}

void chat_server::handle_redirect_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (!check_access(ctx, "R")) {
        return;
    }

    assert_command_input(ctx, is_channelname_valid(command));
    notify_redirect(command);
}

void chat_server::handle_exile_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "e")) {
        return;
    }

    std::stringstream ss(command);
    std::string username;
    std::string channelname;

    assert_command_input(ctx, std::getline(ss, username, ' '));
    assert_command_input(ctx, std::getline(ss, channelname, '\0'));
    assert_command_input(ctx, is_channelname_valid(channelname));

    const auto exec = [&](const auto& user) {
        notify_exile(user, channelname);
    };

    assert_find_user(ctx, username, exec);
}

void chat_server::handle_forcelogin_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "f")) {
        return;
    }

    std::stringstream ss(command);
    std::string username;
    std::string login;

    if (!std::getline(ss, username, ' ')) {
        echo(ctx, "Failed to parse the username.");
        return;
    }

    if (!std::getline(ss, login, '\0')) {
        echo(ctx, "Failed to parse the login.");
        return;
    }

    const auto exec = [&](const auto& user) {
        if (user == ctx) {
            handle_login_command(ctx, login);
            return;
        }

        std::string access;
        std::string format;
        if (m_nuggit_config.chat_server_login().with_password(login, access,
                                                              format)) {
            const auto rank = user->rank();
            user->access = access;
            user->format = format;

            echo(ctx, "Login successful.");
            echof(user, "Access: {}", access);

            if (rank != user->rank()) {
                notify_rename(user, user->info.username, user->info.primary.ip,
                              user->info.primary.port, user->info.line_type,
                              user->info.files);
            }
        }
    };

    assert_find_user(ctx, username, exec);
}

void chat_server::handle_setaccess_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "*")) {
        return;
    }

    std::stringstream ss(command);
    std::string username;
    std::string access;

    assert_command_input(ctx, std::getline(ss, username, ' '));
    assert_command_input(
        ctx, std::getline(ss, access, '\0') && access.length() < 32);

    const auto exec = [&](const auto& user) {
        const auto rank = user->rank();
        user->access = access;

        if (user != ctx) {
            echof(ctx, "User: {} Access: {}", user->info.username, access);
            echof(user, "Access: {}", access);
        } else {
            echo(ctx, "Your access has been set.");
        }

        if (rank != user->rank()) {
            notify_rename(user, user->info.username, user->info.primary.ip,
                          user->info.primary.port, user->info.line_type,
                          user->info.files);
        }
    };

    assert_find_user(ctx, username, exec);
}

void chat_server::handle_setformat_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "z")) {
        return;
    }

    std::stringstream ss(command);
    std::string username;
    std::string format;

    assert_command_input(ctx, std::getline(ss, username, ' '));

    if (!std::getline(ss, format)) {
        format = username;
        ctx->format = format;
        echo(ctx, "Format set.");
        return;
    }

    assert_command_input(ctx, format.length() < 32);

    const auto exec = [&](const auto& user) {
        user->format = format;
        echo(ctx, "Format set.");
    };

    assert_find_user(ctx, username, exec);
}

constexpr std::string get_color_menu() {
    std::string colors_menu = "";
    colors_menu += COL(8) + "You can use any color from ";
    colors_menu += COL(1) + "1 ";
    colors_menu += COL(8) + "to ";
    colors_menu += COL(1) + "255\n";
    colors_menu += COL(8) + "The following colors are recommended:\n";
    colors_menu += list_available_colors();
    return colors_menu;
}

void chat_server::handle_color_command(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    if (!ctx->is353) {
        echo(ctx, "Colorful text is only supported for 3.53+ clients.");
        return;
    }

    std::string color_menu = get_color_menu();
    std::stringstream ss(color_menu);
    std::string line;
    while (std::getline(ss, line)) {
        echo(ctx, line);
    }
}

void chat_server::handle_opmsg_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    using ng::string::utils::replace;
    if (is_invalid_command_input(ctx, command)) {
        return;
    }

    auto opmsg_format = m_nuggit_config.chat_server().opmsg_format();
    interpolate_name(ctx, opmsg_format);
    replace(opmsg_format, "$TEXT$", command);

    for (const auto& user : m_chat_users) {
        if (!logged_in(user) || !user->has_access('O')) {
            continue;
        }

        echo_clr(user, opmsg_format);
    }
}

void chat_server::handle_notice_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "n")) {
        return;
    }

    for (const auto& user : m_chat_users) {
        if (!logged_in(user)) {
            continue;
        }

        echo_clr(user, command);
    }
}

void chat_server::handle_gnotice_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "G")) {
        return;
    }

    std::stringstream ss(command);
    std::string access;
    std::string message;

    assert_command_input(ctx, std::getline(ss, access, ' '));
    assert_command_input(ctx, std::getline(ss, message) && !message.empty());

    for (const auto& user : m_chat_users) {
        if (!logged_in(user) &&
            !std::all_of(access.begin(), access.end(), [&user](const auto& c) {
                return user->access.find(c) != std::string::npos;
            })) {
            continue;
        }

        echo_clr(user, command);
    }
}

void chat_server::handle_privnotice_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "mn")) {
        return;
    }

    std::stringstream ss(command);
    std::string username;
    std::string notice;

    assert_command_input(ctx, std::getline(ss, username, ' '));
    assert_command_input(ctx, std::getline(ss, notice));

    const auto exec = [&](const auto& user) { echo_clr(user, notice); };

    assert_find_user(ctx, username, exec);
}

void chat_server::handle_message_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "m")) {
        return;
    }

    std::stringstream ss(command);
    std::string username;
    std::string message;

    assert_command_input(ctx, std::getline(ss, username, ' '));
    assert_command_input(ctx, std::getline(ss, message));

    const auto exec = [&](const auto& user) {
        using ng::string::utils::replace;

        if (user == ctx) {
            echo(ctx, "Why are you talking to yourself? Please seek help.");
            return;
        }

        std::string recv_fmt =
            m_nuggit_config.chat_server().private_message_recv_format();
        std::string send_fmt =
            m_nuggit_config.chat_server().private_message_send_format();

        replace(recv_fmt, "$RNAME0$", name0(user->info.username));
        replace(recv_fmt, "$RNAME3$", name3(user->info.username));
        replace(recv_fmt, "$RNAME9$", name9(user->info.username));
        replace(recv_fmt, "$TEXT$", message);
        interpolate_name(ctx, recv_fmt);

        replace(send_fmt, "$RNAME0$", name0(user->info.username));
        replace(send_fmt, "$RNAME3$", name3(user->info.username));
        replace(send_fmt, "$RNAME9$", name9(user->info.username));
        replace(send_fmt, "$TEXT$", message);
        interpolate_name(ctx, send_fmt);

        echo_clr(ctx, send_fmt);
        echo_clr(user, recv_fmt);
    };

    assert_find_user(ctx, username, exec);
}

void chat_server::handle_stats_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (command.empty()) {
        if (check_access(ctx, "S")) {
            echo(ctx, std::format("Channelname: {}", ctx->info.channelname));
            echo(ctx, std::format("Host uptime: {}",
                                  get_time_since(get_system_uptime_seconds())));
            echo(ctx, std::format("Channel uptime: {}",
                                  get_time_since(m_created_at)));
            echo(ctx, std::format("Current users: {}",
                                  std::count_if(m_chat_users.begin(),
                                                m_chat_users.end(),
                                                [](const auto& user) {
                                                    return logged_in(user);
                                                })));
            echo(ctx, std::format("Total joins: {}", m_total_joins));
            echo(ctx, std::format("Total messages: {}", m_total_messages));
            echo(ctx, std::format("This channel is powered by nuggit {}",
                                  get_version_string()));
        }
        return;
    }

    if (!check_access(ctx, "s")) {
        return;
    }

    const auto exec = [&](const auto& user) {
        echo(ctx, std::format("Username: {}", user->info.username));
        echo(ctx, std::format("Channelname: {}", user->info.channelname));
        echo(ctx, std::format("IP address: {}", user->ip));
        echo(ctx, std::format("Hostname: {}", user->hostname));
        echo(ctx, std::format("Access: {}", user->access));
        echo(ctx, std::format("Files: {}", user->info.files));
        echo(ctx, std::format("Total messages: {}", user->message_count));
        echo(ctx,
             std::format("Stay time: {}", get_time_since(user->created_at)));
        echo(ctx, std::format("Client: {} {}", user->client_name,
                              user->client_version));
        echo(ctx, std::format("Text format: {}", user->format));
    };

    assert_find_user(ctx, command, exec);
}

void chat_server::handle_access_command(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    echo(ctx, std::format("Your access: {}", ctx->access));
}

void chat_server::handle_logout_command(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    const auto rank = ctx->rank();

    ctx->access = m_nuggit_config.chat_server_login().default_access();
    ctx->format = m_nuggit_config.chat_server_login().default_format();

    if (rank != ctx->rank()) {
        notify_rename(ctx, ctx->info.username, ctx->info.primary.ip,
                      ctx->info.primary.port, ctx->info.line_type,
                      ctx->info.files);
    }

    echo(ctx, "Successfully logged out.");
}

void chat_server::handle_bot_command(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    using ng::string::utils::replace;
    if (!ctx->has_access('b')) {
        ctx->access += 'b';
        echo(ctx, "Bot mode enabled.");
    } else {
        replace(ctx->access, "b", "");
        echo(ctx, "Bot mode disabled.");
    }
}

void chat_server::handle_channelname_command(
    const std::unique_ptr<chat_user_context_t>& ctx, const std::string& command,
    size_t channel_index) {
    const auto& channelnames = m_nuggit_config.chat_server().channelnames();

    assert_command_input(ctx, channel_index <= channelnames.size());

    echo(ctx,
         std::format("Channelname: {}", channelnames.at(channel_index - 1)));
}

void chat_server::handle_topic_command(
    const std::unique_ptr<chat_user_context_t>& ctx, const std::string& command,
    int topic_index) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "T")) {
        return;
    }

    assert_command_input(ctx, topic_index > 0 && topic_index <= 3);

    m_nuggit_config.chat_server().set_topic(command, topic_index - 1);

    for (const auto& user : m_chat_users) {
        if (!logged_in(user)) {
            continue;
        }

        if (topic_index == 1) {
            notify_topic(user);
        } else {
            echof(user, "{}Topic{}: {}{}", COL(7), topic_index, COL(7),
                  m_nuggit_config.chat_server().topics()[topic_index - 1]);
        }
    }
}

void chat_server::handle_motd_command(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    notify_motd(ctx);
}

void chat_server::handle_setmotd_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (!check_access(ctx, "M")) {
        return;
    }

    m_nuggit_config.chat_server().set_motd(command);

    echo(ctx, "Successfully set the MOTD.");
}

void chat_server::handle_addmotd_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (!check_access(ctx, "M")) {
        return;
    }

    m_nuggit_config.chat_server().add_motd(command);

    echo(ctx, "Successfully appended to the MOTD.");
}

void chat_server::handle_limit_command(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (is_invalid_command_input(ctx, command) || !check_access(ctx, "l")) {
        return;
    }

    assert_command_input(
        ctx, std::all_of(command.begin(), command.end(), ::isdigit));

    auto limit = std::stoi(command);
    if (limit > 600) {
        limit = 600;
    }
    if (limit < 2) {
        limit = 2;
    }

    m_nuggit_config.chat_server().set_limit(limit);

    echof(ctx, "Limit set: {}", limit);
}

void chat_server::handle_reload_command(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    if (!check_access(ctx, "r")) {
        return;
    }

    try {
        if (!m_nuggit_config.load()) {
            warn("unable to load the config file...");
            echo(ctx, "Unable to load the config file");
            return;
        }
    } catch (std::runtime_error& e) {
        const auto what = e.what();
        error("unable to load config: {}", what);
        echof(ctx, "[error] unable to load the config: {}", what);
    }

    echo(ctx, "Config reloaded.");
}

void chat_server::handle_who_command(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    if (!check_access(ctx, "sSI")) {
        return;
    }

    echo_clr(ctx,
             "#c6#Users #c6#urrently in the channel: "
             "#c1#3.53#c6#/#c2#3.31#c6#/#c3#Bot#c6#/#c9#Hidden");
    for (const auto& user : m_chat_users) {
        echof(ctx, "{}{} [{}] ({})",
              user->is_hidden         ? COL(9)
              : user->has_access('b') ? COL(3)
              : !user->is353          ? COL(2)
                                      : COL(1),
              user->info.username, user->ip, user->access);
    }
    echo_clr(ctx, "#c6#End #c6#of users list.");
}

bool chat_server::check_access(const std::unique_ptr<chat_user_context_t>& ctx,
                               const std::string& access) {
    if (std::any_of(access.begin(), access.end(),
                    [&](const auto& c) { return !ctx->has_access(c); })) {
        echo(ctx, "Insufficient access to perform this action.");
        return false;
    }

    return true;
}

bool chat_server::check_capacity() {
    const auto user_count =
        std::count_if(m_chat_users.begin(), m_chat_users.end(),
                      [](const auto& user) { return logged_in(user); });

    return user_count < m_nuggit_config.chat_server().limit();
}

bool chat_server::find_user_by_partial_name(
    const std::string& partial_name,
    const std::function<void(const std::unique_ptr<chat_user_context_t>& ctx)>&
        func) {
    for (const auto& user : m_chat_users) {
        if (!logged_in(user) ||
            user->info.username.find(partial_name) == std::string::npos) {
            continue;
        }

        func(user);
        return true;
    }

    return false;
}

void chat_server::append_chat_history(const std::string& message) {
    if (!m_nuggit_config.chat_server().show_chat_history()) {
        return;
    }

    m_chat_history.push_back(message);

    while (m_chat_history.size() > STORED_MESSAGE_COUNT) {
        m_chat_history.erase(m_chat_history.begin());
    }
}

bool chat_server::is_invalid_command_input(
    const std::unique_ptr<chat_user_context_t>& ctx,
    const std::string& command) {
    if (command.length() == 0 ||
        std::all_of(command.begin(), command.end(), ::isspace)) {
        echo(ctx, "Invalid command input.");
        return true;
    }

    return false;
}

const std::string& chat_server::resolve_external_ip() {
    using namespace ng::web::http;

    if (m_external_ip.empty() || m_resolver_interval.has_elapsed()) {
        const auto resp = simple_get(
            m_nuggit_config.chat_server().external_ip_resolution_url());

        m_external_ip = std::visit(
            response_visitor{[](const success_response& r) -> std::string {
                                 info("resolved external ip ({})", r.text);
                                 return r.text;
                             },
                             [](const error_response&) -> std::string {
                                 warn("unable to resolve external ip. :-(");
                                 return "127.0.0.1";
                             }},
            resp);

        m_resolver_interval.reset();
    }

    return m_external_ip;
}

std::future<country_result> chat_server::resolve_country(
    const std::string& ip) {
    if (!m_nuggit_config.chat_server().resolve_countries()) {
        std::promise<country_result> res;
        res.set_value(country_result{""});
        return res.get_future();
    }

    return std::async(std::launch::async, [&]() -> country_result {
        using ng::string::utils::replace;
        using namespace ng::web::http;

        auto country_url = m_nuggit_config.chat_server().country_resolver_url();
        replace(country_url, "$IP$", ip);
        const auto resp = simple_get(country_url);

        const auto res = std::visit(
            response_visitor{
                [](const success_response& r) -> std::string { return r.text; },
                [](const error_response&) -> std::string { return "N/A"; },
            },
            resp);

        if (res.find(';') == std::string::npos) {
            return country_result{res};
        }

        std::stringstream ss(res);
        std::string country;

        while (std::getline(ss, country, ';')) {
            if (country.length() == 3) {
                return country_result{country};
            }
        }

        return country_result{country};
    });
}

bool chat_server::validate_user(
    const std::unique_ptr<chat_user_context_t>& ctx) {
    if (!is_username_valid(ctx->info.username)) {
        echo(ctx, "Login rejected. Username invalid.");
        return false;
    }

    if (is_username_taken(ctx->info.username, ctx)) {
        echo(ctx, "Login rejected. Username taken.");
        return false;
    }

    return true;
}

bool chat_server::is_username_valid(const std::string& username) {
    static thread_local std::regex name_regex("^\\S{3,}[0-9]{3}_[0-9]{5}$");

    if (username.length() > 48) {
        return false;
    }

    if (!sanity_check(username)) {
        return false;
    }

    if (!std::regex_match(username, name_regex)) {
        return false;
    }

    if (format_colorful_string(name0(username), true).length() < 3) {
        return false;
    }

    return true;
}

bool chat_server::sanity_check(const std::string& str) {
    if (str.length() == 0 || str.length() > 255) {
        return false;
    }

    const auto stripped = format_colorful_string(str, true);
    if (stripped.length() == 0 ||
        stripped.find("{\\rtf") != std::string::npos) {
        return false;
    }

    if (stripped.find("\r") != std::string::npos ||
        stripped.find("\n") != std::string::npos) {
        return false;
    }

    return true;
}

void chat_server::interpolate_name(
    const std::unique_ptr<chat_user_context_t>& ctx, std::string& str) {
    using ng::string::utils::replace;

    replace(str, "$NAME$", name9(ctx->info.username));
    replace(str, "$NAME0$", name0(ctx->info.username));
    replace(str, "$NAME3$", name3(ctx->info.username));
    replace(str, "$NAME9$", name9(ctx->info.username));
}

void chat_server::interpolate_raw_name(
    const std::unique_ptr<chat_user_context_t>& ctx, std::string& str) {
    using ng::string::utils::replace;

    replace(str, "$RAWNAME$", name9(ctx->info.username));
    replace(str, "$RAWNAME0$", name0(ctx->info.username));
    replace(str, "$RAWNAME3$", name3(ctx->info.username));
    replace(str, "$RAWNAME9$", name9(ctx->info.username));
}

void chat_server::interpolate_motd_variables(
    const std::unique_ptr<chat_user_context_t>& ctx, std::string& str) {
    using string::utils::replace;
    replace(str, "$IP$", ctx->ip);
    replace(str, "$HOSTNAME$", ctx->hostname);
    replace(str, "$FILES$", std::to_string(ctx->info.files));
    replace(str, "$LINE$", util::get_line_type(ctx->info.line_type));
    replace(str, "$HOSTUPTIME$", get_time_since(get_system_uptime_seconds()));
    replace(str, "$CHANNELUPTIME$", get_time_since(m_created_at));
    replace(str, "$CHANNELIP$", resolve_external_ip());
    replace(str, "$CHANNELPORT$",
            std::to_string(m_nuggit_config.nuggit().tcp_port()));
    replace(str, "$COUNTRY$", ctx->country);
}

packet_buffer_t chat_server::write_packet(
    uint16_t type, const std::function<void(packet_buffer_t& buffer)>& writer) {
    packet_buffer_t scratch_buffer;
    scratch_buffer.reset();
    scratch_buffer.skip_header();
    writer(scratch_buffer);
    scratch_buffer.write_header(type);
    return scratch_buffer;
}

chat_server::~chat_server() {}

}  // namespace ng::wpn::chat
