#ifndef MEDUSA2_COMMON_PRECOMPILED_HPP_
#define MEDUSA2_COMMON_PRECOMPILED_HPP_

#include <poseidon/precompiled.hpp>
#include <poseidon/fwd.hpp>

#include <poseidon/shared_nts.hpp>
#include <poseidon/exception.hpp>
#include <poseidon/log.hpp>
#include <poseidon/profiler.hpp>
#include <poseidon/errno.hpp>
#include <poseidon/time.hpp>
#include <poseidon/random.hpp>
#include <poseidon/flags.hpp>
#include <poseidon/module_raii.hpp>
#include <poseidon/uuid.hpp>
#include <poseidon/endian.hpp>
#include <poseidon/string.hpp>
#include <poseidon/checked_arithmetic.hpp>
#include <poseidon/buffer_streams.hpp>
#include <poseidon/async_job.hpp>
#include <poseidon/atomic.hpp>

#ifdef POSEIDON_CXX11
#  include <cstdint>
#  include <array>
#  include <type_traits>
#endif

#define LOG_MEDUSA2(level_, ...)      LOG_MASK(0x4000 | (level_), __VA_ARGS__)
#define LOG_MEDUSA2_FATAL(...)        LOG_MEDUSA2(::Poseidon::Logger::LV_FATAL,   __VA_ARGS__)
#define LOG_MEDUSA2_ERROR(...)        LOG_MEDUSA2(::Poseidon::Logger::LV_ERROR,   __VA_ARGS__)
#define LOG_MEDUSA2_WARNING(...)      LOG_MEDUSA2(::Poseidon::Logger::LV_WARNING, __VA_ARGS__)
#define LOG_MEDUSA2_INFO(...)         LOG_MEDUSA2(::Poseidon::Logger::LV_INFO,    __VA_ARGS__)
#define LOG_MEDUSA2_DEBUG(...)        LOG_MEDUSA2(::Poseidon::Logger::LV_DEBUG,   __VA_ARGS__)
#define LOG_MEDUSA2_TRACE(...)        LOG_MEDUSA2(::Poseidon::Logger::LV_TRACE,   __VA_ARGS__)

#endif