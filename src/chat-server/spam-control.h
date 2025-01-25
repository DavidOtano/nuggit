#ifndef NG_SPAM_CONTROL_H
#define NG_SPAM_CONTROL_H

#include "timer.h"
namespace ng::wpn::chat {

struct spam_control {
    spam_control() noexcept
        : messages(0), ktime(std::chrono::seconds(3)), should_notify(2) {}

    bool can_send() {
        if (ktime.has_elapsed()) {
            should_notify = 2;
            messages = 0;
        }
        ktime.reset();
        if (++messages > 5) {
            should_notify--;
            return false;
        }

        return true;
    }

    int messages;
    timer ktime;
    int should_notify;
};

}  // namespace ng::wpn::chat

#endif
