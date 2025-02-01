#include <semver.h>
#include <logging.h>
#include <string-utils.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include "nuggit-config.h"
#include "chat-server/chat-server.h"
#include "nuggit-service.h"
#include "peer/handshake.h"
#include "peer/peer_types.h"

using ng::logging::error, ng::logging::info;
using namespace ng::wpn;

typedef std::vector<std::shared_ptr<ng::ng_service>> ng_services;

/* forward declarations */
static std::string ng_version_string(void);
bool configure_services(ng::nuggit_config_reader& config,
                        ng_services& services);
bool load_config(ng::nuggit_config_reader& config);
bool ng_init(int argc, char** argv);
int ng_run(const ng_services& services);

bool ng_use_timestamps = true;

int main(int argc, char** argv) {
    if (!ng_init(argc, argv)) {
        return 0;
    }

    ng::nuggit_config_reader config;
    if (!load_config(config)) {
        return -1;
    }

    ng_services services;
    if (!configure_services(config, services)) {
        return -1;
    }

    return ng_run(services);
}

static std::string ng_version_string(void) {
    return std::format("nuggit {}.{}.{}", BUILD_MAJOR, BUILD_MINOR,
                       BUILD_NUMBER);
}

bool configure_services(ng::nuggit_config_reader& config,
                        ng_services& services) {
    auto server =
        std::make_shared<peer::handshake_server>(std::chrono::seconds(5));
    server->set_port(config.nuggit().tcp_port());
    services.emplace_back(server);

    if (config.nuggit().chat_server()) {
        auto chat_server = std::make_shared<ng::wpn::chat::chat_server>(config);

        if (!chat_server->init()) {
            return false;
        }

        services.emplace_back(chat_server);
        server->add_receiver(NG_CHAT_SERVER, chat_server);
    }

    if (!server->init()) {
        return false;
    }

    return true;
}

bool load_config(ng::nuggit_config_reader& config) {
    try {
        if (!config.load()) {
            error("unable to load the config...");
            return false;
        }
    } catch (std::runtime_error& e) {
        auto what = e.what();
        error("unable to load config: {}", what);
        return false;
    }

    info("config loaded!");

    return true;
}

bool ng_init(int argc, char** argv) {
    using ng::string::utils::to_lower, ng::string::utils::trim;

    bool no_logo = false;
    for (auto i = 0; i < argc; i++) {
        std::string arg = argv[i];
        arg = to_lower(trim(arg));

        if (arg == "--no-logo") {
            no_logo = true;
            continue;
        } else if (arg == "--no-timestamps") {
            ng_use_timestamps = false;
            continue;
        } else if (arg == "--version") {
            std::cout << ng_version_string() << "\n";
            return false;
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

    return true;
}

int ng_run(const ng_services& services) {
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
