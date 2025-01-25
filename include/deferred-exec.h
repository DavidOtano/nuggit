#ifndef NG_DEFERRED_EXEC_H
#define NG_DEFERRED_EXEC_H

#include <functional>
#include <vector>

namespace ng::lazy {

class deferred_exec {
public:
    deferred_exec() {}
    deferred_exec(deferred_exec&& ex) : m_exec(std::move(ex.m_exec)) {}
    deferred_exec(const deferred_exec& ex) : m_exec(std::move(ex.m_exec)) {}
    deferred_exec(std::vector<std::function<void(void)>>&& exec)
        : m_exec(std::move(exec)) {}
    deferred_exec(const std::function<void(void)>& exec) {
        m_exec.push_back(exec);
    }

    void enqueue(const std::function<void(void)>& exec) {
        m_exec.push_back(exec);
    }

    ~deferred_exec() {
        for (const auto& exec : m_exec) {
            exec();
        }
    }

private:
    std::vector<std::function<void(void)>> m_exec;
};

}  // namespace ng::lazy

#endif
