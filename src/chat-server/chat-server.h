#ifndef NG_CHAT_SERVER_H
#define NG_CHAT_SERVER_H

#include <chrono>
#include <functional>
#include <logging.h>
#include <memory>
#include <cstdint>
#include <timer.h>
#include "ban-control.h"
#include "chat-user.h"
#include "../peer/handshake.h"
#include "../nuggit-service.h"
#include "../nuggit-config.h"

namespace ng::wpn::chat {

using namespace wpn::proto;

class chat_server : public ng_service, public peer::peer_receiver {
public:
    chat_server(nuggit_config_reader& nuggit_config) noexcept;
    bool init();
    bool process() override;
    void accept(
        const std::unique_ptr<peer::handshake_context_t>& ctx) override {
        m_chat_users.emplace_back(chat_user_context_t::from_handshake(ctx));
    }
    ~chat_server();

protected:
    nuggit_config_reader& m_nuggit_config;
    std::vector<std::unique_ptr<chat_user_context_t>> m_chat_users;
    ban_control m_ban_control;
    std::vector<std::string> m_chat_history;
    std::chrono::time_point<std::chrono::high_resolution_clock> m_created_at;
    int m_total_messages;
    int m_total_joins;
    std::string m_external_ip;
    timer m_resolver_interval;

    void enqueue_all(const uint8_t* buffer, uint16_t len);
    void enqueue_all(
        uint16_t type,
        const std::function<void(packet_buffer_t& buffer)>& writer);
    void enqueue(const std::unique_ptr<chat_user_context_t>& ctx,
                 const uint8_t* buffer, uint16_t len);
    void enqueue(const std::unique_ptr<chat_user_context_t>& ctx, uint16_t type,
                 const std::function<void(packet_buffer_t& buffer)>& writer);

    bool validate_user(const std::unique_ptr<chat_user_context_t>& ctx);
    bool is_username_taken(
        const std::string& username,
        const std::unique_ptr<chat_user_context_t>& exclude) const;

    void notify_topic(const std::unique_ptr<chat_user_context_t>& ctx);
    void notify_motd(const std::unique_ptr<chat_user_context_t>& ctx);
    void notify_chat_history(const std::unique_ptr<chat_user_context_t>& ctx);
    void notify_userlist(const std::unique_ptr<chat_user_context_t>& ctx);
    void notify_join(const std::unique_ptr<chat_user_context_t>& ctx);
    void notify_rename(const std::unique_ptr<chat_user_context_t>& ctx,
                       const std::string& new_username, uint32_t new_pri_ip,
                       uint16_t new_pri_port, uint16_t new_line_type,
                       uint16_t new_files);
    void notify_has_parted(const std::unique_ptr<chat_user_context_t>& ctx);
    void notify_redirect(const std::string& channelname);
    void notify_exile(const std::unique_ptr<chat_user_context_t>& ctx,
                      const std::string& channelname);
    void notify_join_request_accepted(
        const std::unique_ptr<chat_user_context_t>& ctx);

    bool handle_packet(const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_ipsend(const std::unique_ptr<chat_user_context_t>& ctx);
    bool handle_join(const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_message(const std::unique_ptr<chat_user_context_t>& ctx,
                        const std::string& msg = "");
    void handle_rename(const std::unique_ptr<chat_user_context_t>& ctx);

    void print_packet(const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_command(const std::unique_ptr<chat_user_context_t>& ctx,
                        const std::string& command, bool is_hidden = false);
    void handle_action_command(const std::unique_ptr<chat_user_context_t>& ctx,
                               const std::string& command);
    void handle_login_command(const std::unique_ptr<chat_user_context_t>& ctx,
                              const std::string& command);
    void handle_kick_command(const std::unique_ptr<chat_user_context_t>& ctx,
                             const std::string& command);
    void handle_ban_command(const std::unique_ptr<chat_user_context_t>& ctx,
                            const std::string& command);
    void handle_kickban_command(const std::unique_ptr<chat_user_context_t>& ctx,
                                const std::string& command);
    void handle_unban_command(const std::unique_ptr<chat_user_context_t>& ctx,
                              const std::string& command);
    void handle_listbans_command(
        const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_clearbans_command(
        const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_hide_command(const std::unique_ptr<chat_user_context_t>& ctx,
                             const std::string& command);
    void handle_redirect_command(
        const std::unique_ptr<chat_user_context_t>& ctx,
        const std::string& cmmand);
    void handle_exile_command(const std::unique_ptr<chat_user_context_t>& ctx,
                              const std::string& command);
    void handle_forcelogin_command(
        const std::unique_ptr<chat_user_context_t>& ctx,
        const std::string& command);
    void handle_setaccess_command(
        const std::unique_ptr<chat_user_context_t>& ctx,
        const std::string& command);
    void handle_setformat_command(
        const std::unique_ptr<chat_user_context_t>& ctx,
        const std::string& command);
    void handle_color_command(const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_opmsg_command(const std::unique_ptr<chat_user_context_t>& ctx,
                              const std::string& command);
    void handle_notice_command(const std::unique_ptr<chat_user_context_t>& ctx,
                               const std::string& command);
    void handle_gnotice_command(const std::unique_ptr<chat_user_context_t>& ctx,
                                const std::string& command);
    void handle_privnotice_command(
        const std::unique_ptr<chat_user_context_t>& ctx,
        const std::string& command);
    void handle_message_command(const std::unique_ptr<chat_user_context_t>& ctx,
                                const std::string& command);
    void handle_stats_command(const std::unique_ptr<chat_user_context_t>& ctx,
                              const std::string& command);
    void handle_access_command(const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_logout_command(const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_channelname_command(
        const std::unique_ptr<chat_user_context_t>& ctx,
        const std::string& command, size_t channel_index);
    void handle_bot_command(const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_topic_command(const std::unique_ptr<chat_user_context_t>& ctx,
                              const std::string& command, int topic_index);
    void handle_motd_command(const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_setmotd_command(const std::unique_ptr<chat_user_context_t>& ctx,
                                const std::string& command);
    void handle_addmotd_command(const std::unique_ptr<chat_user_context_t>& ctx,
                                const std::string& command);
    void handle_limit_command(const std::unique_ptr<chat_user_context_t>& ctx,
                              const std::string& command);
    void handle_reload_command(const std::unique_ptr<chat_user_context_t>& ctx);
    void handle_who_command(const std::unique_ptr<chat_user_context_t>& ctx);
    void interpolate_motd_variables(
        const std::unique_ptr<chat_user_context_t>& ctx, std::string& str);

    bool check_access(const std::unique_ptr<chat_user_context_t>& ctx,
                      const std::string& access);
    bool check_capacity();
    bool find_user_by_partial_name(
        const std::string& partial_name,
        const std::function<
            void(const std::unique_ptr<chat_user_context_t>& ctx)>& func);
    void append_chat_history(const std::string& message);
    bool is_invalid_command_input(
        const std::unique_ptr<chat_user_context_t>& ctx,
        const std::string& command);
    const std::string& resolve_external_ip();
    std::future<country_result> resolve_country(const std::string& ip);

    static bool is_username_valid(const std::string& username);
    static bool is_channelname_valid(const std::string& channelname);
    static bool sanity_check(const std::string& str);
    static void interpolate_name(
        const std::unique_ptr<chat_user_context_t>& ctx, std::string& str);
    void interpolate_raw_name(const std::unique_ptr<chat_user_context_t>& ctx,
                              std::string& str);
    static packet_buffer_t write_packet(
        uint16_t type,
        const std::function<void(packet_buffer_t& buffer)>& writer);
};

}  // namespace ng::wpn::chat

#endif
