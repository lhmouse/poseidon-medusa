#ifndef MEDUSA2_COMMON_ENCRYPTION_HPP_
#define MEDUSA2_COMMON_ENCRYPTION_HPP_

#include <poseidon/stream_buffer.hpp>
#include <string>

namespace Medusa2 {
namespace Common {

extern Poseidon::StreamBuffer encrypt(const std::string &key, Poseidon::StreamBuffer plaintext);
extern Poseidon::StreamBuffer decrypt(const std::string &key, Poseidon::StreamBuffer ciphertext);

}
}

#endif
