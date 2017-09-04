#ifndef MEDUSA2_COMMON_ENCRYPTION_HPP_
#define MEDUSA2_COMMON_ENCRYPTION_HPP_

#include <poseidon/stream_buffer.hpp>
#include <boost/cstdint.hpp>
#include <string>

namespace Medusa2 {
namespace Common {

extern Poseidon::StreamBuffer encrypt_explicit(const std::string &key, Poseidon::StreamBuffer plaintext, boost::uint64_t timestamp);
extern Poseidon::StreamBuffer decrypt_explicit(const std::string &key, Poseidon::StreamBuffer ciphertext, boost::uint64_t timestamp_lower, boost::uint64_t timestamp_upper);

extern Poseidon::StreamBuffer encrypt(Poseidon::StreamBuffer plaintext);
extern Poseidon::StreamBuffer decrypt(Poseidon::StreamBuffer ciphertext);

}
}

#endif
