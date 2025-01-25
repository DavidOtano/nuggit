#ifndef NG_TIMER_H
#define NG_TIMER_H

#include <chrono>

namespace ng {

class timer {
public:
    timer(bool set)
        : m_tp(std::chrono::high_resolution_clock::now()),
          m_timeout(0),
          m_set(set) {}

    timer() : m_tp(std::chrono::high_resolution_clock::now()), m_timeout(0), m_set(false) {}

    timer(const std::chrono::seconds& timeout)
        : m_tp(std::chrono::high_resolution_clock::now()), m_timeout(timeout), m_set(true) {}
    timer(std::chrono::seconds&& timeout)
        : m_tp(std::chrono::high_resolution_clock::now()),
          m_timeout(std::forward<std::chrono::seconds>(timeout)), m_set(true) {}

    timer& operator=(const std::chrono::seconds& timeout) {
        m_tp = std::chrono::high_resolution_clock::now();
        m_timeout = timeout;
        m_set = true;
        return *this;
    }

    timer& operator=(std::chrono::seconds&& timeout) {
        m_timeout = std::forward<std::chrono::seconds>(timeout);
        return *this;
    }

    void reset() {
        m_set = true;
        m_tp = std::chrono::high_resolution_clock::now();
    }

    void set(const std::chrono::seconds& duration) {
        m_timeout = duration;
        reset();
    }

    void unset() { m_set = false; }

    bool has_elapsed() const {
        return std::chrono::high_resolution_clock::now() - m_tp > m_timeout;
    }

    bool is_set() const { return m_set; }

protected:
    std::chrono::time_point<std::chrono::high_resolution_clock> m_tp;
    std::chrono::seconds m_timeout;
    bool m_set;
};

}  // namespace ng

#endif
