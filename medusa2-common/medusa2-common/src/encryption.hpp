// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#ifndef MEDUSA2_COMMON_ENCRYPTION_HPP_
#define MEDUSA2_COMMON_ENCRYPTION_HPP_

#include <poseidon/stream_buffer.hpp>
#include <boost/cstdint.hpp>
#include <boost/array.hpp>
#include <string>

namespace Medusa2 {
namespace Common {

extern Poseidon::Stream_buffer encrypt(Poseidon::Stream_buffer plaintext);
extern Poseidon::Stream_buffer decrypt(Poseidon::Stream_buffer ciphertext);

}
}

#endif
