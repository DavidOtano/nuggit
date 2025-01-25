#ifndef NG_RANDOM_H
#define NG_RANDOM_H

#include <cstdint>
#include <random>
namespace ng::utils::random {

namespace _ {
static thread_local std::random_device rd;
static thread_local std::mt19937 gen = std::mt19937(rd());
}  // namespace _

static int16_t next(int16_t min, int16_t max) {
    return std::uniform_int_distribution<int16_t>(min, max)(_::gen);
}

static uint16_t next(uint16_t min, uint16_t max) {
    return std::uniform_int_distribution<uint16_t>(min, max)(_::gen);
}

static int32_t next(int32_t min, int32_t max) {
    return std::uniform_int_distribution<int32_t>(min, max)(_::gen);
}

static uint32_t next(uint32_t min, uint32_t max) {
    return std::uniform_int_distribution<uint32_t>(min, max)(_::gen);
}

static int64_t next(int64_t min, int64_t max) {
    return std::uniform_int_distribution<int64_t>(min, max)(_::gen);
}

static uint64_t next(uint64_t min, uint64_t max) {
    return std::uniform_int_distribution<uint64_t>(min, max)(_::gen);
}

static double next(double min, double max) {
    return std::uniform_real_distribution<double>(min, max)(_::gen);
}

static float next(float min, float max) {
    return std::uniform_real_distribution<float>(min, max)(_::gen);
}

static int8_t next(int8_t min, int8_t max) {
    return (int8_t)next((int16_t)min, (int16_t)max);
}

static uint8_t next(uint8_t min, uint8_t max) {
    return (uint8_t)next((uint16_t)min, (uint16_t)max);
}

}  // namespace ng::utils::random

#endif
