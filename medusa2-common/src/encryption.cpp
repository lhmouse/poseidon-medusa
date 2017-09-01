#include "precompiled.hpp"
#include "encryption.hpp"
#include "protocol/error_codes.hpp"
#include <poseidon/sha256.hpp>
#include <poseidon/cbpp/exception.hpp>
#include <openssl/aes.h>

namespace Medusa2 {
namespace Common {

namespace {
	Poseidon::Sha256 get_key_hash(const std::string &key, const boost::uint64_t &nonce){
		Poseidon::Sha256_ostream sha256_os;
		sha256_os.write(reinterpret_cast<const char *>(key.data()), static_cast<std::streamsize>(key.size()))
		         .write(reinterpret_cast<const char *>(&nonce), static_cast<std::streamsize>(sizeof(nonce)));
		return sha256_os.finalize();
	}

	::AES_KEY aes_key_init(const Poseidon::Sha256 &sha256){
		::AES_KEY aes_key;
		const int err_code = ::AES_set_encrypt_key(sha256.data() + 8, 192, &aes_key);
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

Poseidon::StreamBuffer encrypt(const std::string &key, Poseidon::StreamBuffer plaintext){
	PROFILE_ME;

	Poseidon::StreamBuffer ciphertext;
	boost::uint64_t nonce;
	nonce = Poseidon::random_uint64();
	// NONCE: 8 bytes
	ciphertext.put(&nonce, 8);
	const AUTO(sha256, get_key_hash(key, nonce));
	// CHECKSUM: 8 bytes
	ciphertext.put(sha256.data(), 8);
	// DATA: ? bytes
	const AUTO(aes_key, aes_key_init(sha256));
	aes_ctr_transform(ciphertext, plaintext, aes_key);
	return ciphertext;
}
Poseidon::StreamBuffer decrypt(const std::string &key, Poseidon::StreamBuffer ciphertext){
	PROFILE_ME;

	Poseidon::StreamBuffer plaintext;
	boost::uint64_t nonce;
	// NONCE: 8 bytes
	if(ciphertext.get(&nonce, 8) < 8){
		DEBUG_THROW(Poseidon::Cbpp::Exception,
			Protocol::ERR_END_OF_STREAM, Poseidon::sslit("End of stream encountered, expecting NONCE"));
	}
	// CHECKSUM: 8 bytes
	boost::array<unsigned char, 8> checksum;
	if(ciphertext.get(checksum.data(), 8) < 8){
		DEBUG_THROW(Poseidon::Cbpp::Exception,
			Protocol::ERR_END_OF_STREAM, Poseidon::sslit("End of stream encountered, expecting CHECKSUM"));
	}
	const AUTO(sha256, get_key_hash(key, nonce));
	if(std::memcmp(checksum.data(), sha256.data(), 8) != 0){
		DEBUG_THROW(Poseidon::Cbpp::Exception,
			Protocol::ERR_AUTHORIZATION_FAILURE, Poseidon::sslit("Checksums mismatch"));
	}
	// DATA: ? bytes
	const AUTO(aes_key, aes_key_init(sha256));
	aes_ctr_transform(plaintext, ciphertext, aes_key);
	return plaintext;
}

MODULE_RAII(){
	Poseidon::StreamBuffer src, dst;
	src.put("hello world!");
	LOG_POSEIDON_FATAL("src = ", src);
	auto buf = encrypt("key", src);
	LOG_POSEIDON_FATAL("buf = ", buf);
	dst = decrypt("key", buf);
	LOG_POSEIDON_FATAL("dst = ", dst);
}

}
}
