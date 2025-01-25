#ifndef NG_SPIN_LOCK_H
#define NG_SPIN_LOCK_H

#include <atomic>

namespace ng::threading {
class spin_lock {
private:
    std::atomic<bool> m_locked;

public:
    spin_lock() : m_locked(false) {}

    void lock() { while (m_locked.exchange(true, std::memory_order_acquire)); }

    void unlock() { m_locked.store(false, std::memory_order_release); }

    class guard {
    public:
        guard(spin_lock& lock) : m_lock(lock) { m_lock.lock(); }
        ~guard() { m_lock.unlock(); }

    private:
        spin_lock& m_lock;
    };
};
}  // namespace ng::threading

#endif
