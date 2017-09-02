#include "precompiled.hpp"
#include "encryption.hpp"
#include "protocol/error_codes.hpp"
#include <poseidon/sha256.hpp>
#include <poseidon/cbpp/exception.hpp>
#include <openssl/aes.h>

namespace Medusa2 {
namespace Common {

namespace {
	::AES_KEY aes_key_init_192(const unsigned char *key_bytes){
		::AES_KEY aes_key;
		const int err_code = ::AES_set_encrypt_key(key_bytes, 192, &aes_key);
		DEBUG_THROW_ASSERT(err_code == 0);
		return aes_key;
	}
	void aes_ctr_transform(Poseidon::StreamBuffer &b_out, Poseidon::StreamBuffer &b_in, const ::AES_KEY &aes_key){
		boost::array<unsigned char, 16> in, mask, out;
		boost::uint32_t cnt = 0x12345678;
		for(;;){
			const std::size_t n = b_in.get(in.data(), in.size());
			if(n == 0){
				break;
			}
			for(unsigned i = 0; i < 16; ++i){
				mask[i] = cnt;
				cnt = (cnt << 8) | (cnt >> 24);
			}
			++cnt;
			::AES_encrypt(mask.data(), out.data(), &aes_key);
			for(unsigned i = 0; i < 16; ++i){
				out[i] ^= in[i];
			}
			b_out.put(out.data(), n);
		}
	}
}

Poseidon::StreamBuffer encrypt(const std::string &key,
	Poseidon::StreamBuffer plaintext)
{
	PROFILE_ME;

	Poseidon::StreamBuffer ciphertext;
	boost::uint64_t timestamp_be;
	const AUTO(utc_now, Poseidon::get_utc_time());
	Poseidon::store_be(timestamp_be, utc_now);
	// TIMESTAMP: 8 bytes
	ciphertext.put(&timestamp_be, 8);
	Poseidon::Sha256_ostream sha256_os;
	sha256_os.write(key.data(), static_cast<std::streamsize>(key.size()))
	         .write(reinterpret_cast<const char *>(&timestamp_be), 8);
	AUTO(sha256, sha256_os.finalize());
	// KEY_CHECKSUM: 8 bytes
	ciphertext.put(sha256.data(), 8);
	const AUTO(aes_key, aes_key_init_192(sha256.data() + 8));
	// DATA_CHECKSUM: 8 bytes
	plaintext.dump(sha256_os);
	sha256 = sha256_os.finalize();
	ciphertext.put(sha256.data(), 8);
	// DATA: ? bytes
	aes_ctr_transform(ciphertext, plaintext, aes_key);
	return ciphertext;
}
Poseidon::StreamBuffer decrypt(const std::string &key,
	Poseidon::StreamBuffer ciphertext, boost::uint64_t timestamp_lower, boost::uint64_t timestamp_upper)
{
	PROFILE_ME;

	Poseidon::StreamBuffer plaintext;
	boost::uint64_t timestamp_be;
	// TIMESTAMP: 8 bytes
	if(ciphertext.get(&timestamp_be, 8) < 8){
		DEBUG_THROW(Poseidon::Cbpp::Exception,
			Protocol::ERR_END_OF_STREAM, Poseidon::sslit("End of stream encountered, expecting TIMESTAMP"));
	}
	const AUTO(timestamp, Poseidon::load_be(timestamp_be));
	if(timestamp < timestamp_lower){
		DEBUG_THROW(Poseidon::Cbpp::Exception,
			Protocol::ERR_AUTHORIZATION_FAILURE, Poseidon::sslit("Request expired"));
	}
	if(timestamp > timestamp_upper){
		DEBUG_THROW(Poseidon::Cbpp::Exception,
			Protocol::ERR_AUTHORIZATION_FAILURE, Poseidon::sslit("Timestamp too far in the future"));
	}
	// KEY_CHECKSUM: 8 bytes
	boost::array<unsigned char, 8> checksum;
	if(ciphertext.get(checksum.data(), 8) < 8){
		DEBUG_THROW(Poseidon::Cbpp::Exception,
			Protocol::ERR_END_OF_STREAM, Poseidon::sslit("End of stream encountered, expecting KEY_CHECKSUM"));
	}
	Poseidon::Sha256_ostream sha256_os;
	sha256_os.write(key.data(), static_cast<std::streamsize>(key.size()))
	         .write(reinterpret_cast<const char *>(&timestamp_be), 8);
	AUTO(sha256, sha256_os.finalize());
	if(std::memcmp(checksum.data(), sha256.data(), 8) != 0){
		DEBUG_THROW(Poseidon::Cbpp::Exception,
			Protocol::ERR_AUTHORIZATION_FAILURE, Poseidon::sslit("Incorrect key (checksum mismatch)"));
	}
	const AUTO(aes_key, aes_key_init_192(sha256.data() + 8));
	// DATA_CHECKSUM: 8 bytes
	if(ciphertext.get(checksum.data(), 8) < 8){
		DEBUG_THROW(Poseidon::Cbpp::Exception,
			Protocol::ERR_END_OF_STREAM, Poseidon::sslit("End of stream encountered, expecting DATA_CHECKSUM"));
	}
	// DATA: ? bytes
	aes_ctr_transform(plaintext, ciphertext, aes_key);
	plaintext.dump(sha256_os);
	sha256 = sha256_os.finalize();
	if(std::memcmp(checksum.data(), sha256.data(), 8) != 0){
		DEBUG_THROW(Poseidon::Cbpp::Exception,
			Protocol::ERR_DATA_CORRUPTED, Poseidon::sslit("Data corrupted (checksum mismatch)"));
	}
	return plaintext;
}

}
}
