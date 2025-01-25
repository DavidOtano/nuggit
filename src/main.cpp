#include <semver.h>
#include <logging.h>
#include <string-utils.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include "nuggit-config.h"
#include "chat-server/chat-server.h"
#include "peer/handshake.h"
#include "peer/peer_types.h"

using ng::logging::error, ng::logging::info;
using namespace ng::wpn;

bool ng_use_timestamps = true;

/* forward declarations */
static std::string ng_version_string(void);

int main(int argc, char** argv) {
    using ng::string::utils::to_lower, ng::string::utils::trim;
    bool no_logo = false;
    std::vector<std::shared_ptr<ng::ng_service>> services;

    std::string config_path = "config.ini";
    for (auto i = 0; i < argc; i++) {
        std::string arg = argv[i];
        arg = to_lower(trim(arg));

        if (arg.starts_with("--config=")) {
            config_path = arg.substr(9);
            continue;
        } else if (arg == "--no-logo") {
            no_logo = true;
            continue;
        } else if (arg == "--no-timestamps") {
            ng_use_timestamps = false;
            continue;
        } else if (arg == "--version") {
            std::cout << ng_version_string() << "\n";
            return 0;
        } else if (arg.starts_with("--log-level=")) {
            auto level = arg.substr(12);
            if (std::all_of(level.begin(), level.end(), isdigit)) {
                ng::logging::_log_level =
                    (ng::logging::log_level_t)std::stoi(level);
            } else if (level == "error") {
                ng::logging::_log_level = ng::logging::NG_ERR;
            } else if (level == "warn") {
                ng::logging::_log_level = ng::logging::NG_WRN;
            } else if (level == "info") {
                ng::logging::_log_level = ng::logging::NG_INF;
            } else if (level == "trace") {
                ng::logging::_log_level = ng::logging::NG_TRC;
            }
        }
    }

    if (!no_logo && ng::logging::_log_level <= ng::logging::NG_INF) {
#include "ascii.inc"
        info(ng_version_string());
    }

    ng::nuggit_config_reader config;

    try {
        if (!config.load(config_path)) {
            error("unable to load the config...");
            return -1;
        }
    } catch (std::runtime_error& e) {
        auto what = e.what();
        error("unable to load config: {}", what);
        return -1;
    }
    info("config loaded!");

    const auto server =
        std::make_shared<peer::handshake_server>(std::chrono::seconds(5));
    server->set_port(config.nuggit().tcp_port());
    services.push_back(server);

    if (config.nuggit().chat_server()) {
        const auto chat_server =
            std::make_shared<ng::wpn::chat::chat_server>(config);
        chat_server->set_server_line(ng_version_string());

        if (!chat_server->init()) {
            return -1;
        }

        services.push_back(chat_server);
        server->add_receiver(NG_CHAT_SERVER, chat_server);
    }

    if (!server->init()) {
        return -1;
    }

    while (true) {
        for (const auto& service : services) {
            if (!service->process()) {
                return -1;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    return 0;
}

static std::string ng_version_string(void) {
    return std::format("nuggit {}.{}.{}", BUILD_MAJOR, BUILD_MINOR,
                       BUILD_NUMBER);
}
