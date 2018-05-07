// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

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
#include <poseidon/mutex.hpp>
#include <poseidon/recursive_mutex.hpp>

#define LOG_MEDUSA2_EXPLICIT(level_, ...)      LOG_EXPLICIT(0x4000 | (level_), __VA_ARGS__)

#define LOG_MEDUSA2_FATAL(...)        LOG_MEDUSA2_EXPLICIT(::Poseidon::Logger::level_fatal,   __VA_ARGS__)
#define LOG_MEDUSA2_ERROR(...)        LOG_MEDUSA2_EXPLICIT(::Poseidon::Logger::level_error,   __VA_ARGS__)
#define LOG_MEDUSA2_WARNING(...)      LOG_MEDUSA2_EXPLICIT(::Poseidon::Logger::level_warning, __VA_ARGS__)
#define LOG_MEDUSA2_INFO(...)         LOG_MEDUSA2_EXPLICIT(::Poseidon::Logger::level_info,    __VA_ARGS__)
#define LOG_MEDUSA2_DEBUG(...)        LOG_MEDUSA2_EXPLICIT(::Poseidon::Logger::level_debug,   __VA_ARGS__)
#define LOG_MEDUSA2_TRACE(...)        LOG_MEDUSA2_EXPLICIT(::Poseidon::Logger::level_trace,   __VA_ARGS__)

namespace Medusa2 {
	//
}

#endif