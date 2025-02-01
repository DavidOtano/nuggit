#ifndef NG_HTTP_H
#define NG_HTTP_H

#include <string>
#include <cpr/cpr.h>

namespace ng::web::http {

struct error_response {
    long status_code;
    cpr::ErrorCode error_code;
    std::string error_message;
};

struct success_response {
    std::string text;
};

template <class... Ts>
struct response_visitor : Ts... {
    using Ts::operator()...;
};

static const std::variant<success_response, error_response> simple_get(
    const std::string& url) {
    auto response = cpr::Get(cpr::Url{url});

    if (response.status_code >= 200 && response.status_code <= 299) {
        return success_response{.text = response.text};
    }

    return error_response{.status_code = response.status_code,
                          .error_code = response.error.code,
                          .error_message = response.error.message};
}

}  // namespace ng::web::http

#endif
