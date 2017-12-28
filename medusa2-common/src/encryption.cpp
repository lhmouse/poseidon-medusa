#include "precompiled.hpp"
#include "encryption.hpp"
#include "mmain.hpp"
#include "protocol/error_codes.hpp"
#include <poseidon/sha256.hpp>
#include <poseidon/cbpp/exception.hpp>
#include <openssl/aes.h>

namespace Medusa2 {
namespace Common {

namespace {
	boost::container::flat_map<boost::array<unsigned char, 16>, std::string> g_authorized_users;
	boost::uint64_t g_message_lifetime = 60000;

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
				mask[i] = static_cast<unsigned char>(cnt);
				cnt = (cnt << 8) | (cnt >> 24);
			}
			++cnt;
			::AES_encrypt(mask.data(), out.data(), &aes_key);
			for(unsigned i = 0; i < 16; ++i){
				out[i] = static_cast<unsigned char>(out[i] ^ in[i]);
			}
			b_out.put(out.data(), n);
		}
	}
}

MODULE_RAII_PRIORITY(, INIT_PRIORITY_ESSENTIAL){
	PROFILE_ME;
	LOG_MEDUSA2_INFO("Initialize global cipher...");

	const AUTO(users, get_config_all_raw("encryption_authorized_user"));
	for(AUTO(it, users.begin()); it != users.end(); ++it){
		const AUTO_REF(str, *it);
		LOG_MEDUSA2_TRACE("> Authorized user: ", str);
		const AUTO(pos, str.find(':'));
		DEBUG_THROW_UNLESS(pos != std::string::npos, Poseidon::Exception, Poseidon::sslit("Invalid encryption_authorized_user (Hint: encryption_authorized_user = USERNAME:PASSWORD)"));
		DEBUG_THROW_UNLESS(pos != 0, Poseidon::Exception, Poseidon::sslit("Username must not be empty"));
		DEBUG_THROW_UNLESS(pos <= 16, Poseidon::Exception, Poseidon::sslit("Username must contain no more than 16 bytes"));
		boost::array<unsigned char, 16> username;
		std::memset(username.data(), 0, 16);
		std::memcpy(username.data(), str.data(), pos);
		const AUTO(pair, g_authorized_users.emplace(username, str));
		DEBUG_THROW_UNLESS(pair.second, Poseidon::Exception, Poseidon::sslit("Duplicate username"));
	}
	g_message_lifetime = get_config<boost::uint64_t>("encryption_message_lifetime", 60000);
}

Poseidon::StreamBuffer encrypt(Poseidon::StreamBuffer plaintext){
	PROFILE_ME;

	Poseidon::StreamBuffer ciphertext;
	const AUTO(utc_now, Poseidon::get_utc_time());

	AUTO(user_it, g_authorized_users.begin());
	DEBUG_THROW_ASSERT(g_authorized_users.size() > 0);
	std::advance(user_it, static_cast<std::ptrdiff_t>(Poseidon::random_uint32() % g_authorized_users.size()));
	// USERNAME: 16 bytes
	ciphertext.put(user_it->first.data(), 16);
	const boost::uint64_t timestamp = utc_now;
	boost::uint64_t timestamp_be;
	Poseidon::store_be(timestamp_be, timestamp);
	// TIMESTAMP: 8 bytes
	ciphertext.put(&timestamp_be, 8);
	Poseidon::Sha256_ostream sha256_os;
	sha256_os <<timestamp <<'#' <<user_it->second <<'#';
	AUTO(sha256, sha256_os.finalize());
	// KEY_CHECKSUM: 8 bytes
	ciphertext.put(sha256.data(), 8);
	const AUTO(aes_key, aes_key_init_192(sha256.data() + 8));
	// DATA_CHECKSUM: 8 bytes
	sha256_os <<timestamp <<'#' <<plaintext <<'#';
	sha256 = sha256_os.finalize();
	ciphertext.put(sha256.data(), 8);
	// DATA: ? bytes
	aes_ctr_transform(ciphertext, plaintext, aes_key);
	return ciphertext;
}
Poseidon::StreamBuffer decrypt(Poseidon::StreamBuffer ciphertext){
	PROFILE_ME;

	Poseidon::StreamBuffer plaintext;
	const AUTO(utc_now, Poseidon::get_utc_time());

	boost::array<unsigned char, 16> username;
	// USERNAME: 16 bytes
	DEBUG_THROW_UNLESS(ciphertext.get(&username, 16) == 16, Poseidon::Cbpp::Exception, Protocol::ERR_END_OF_STREAM,
		Poseidon::sslit("End of stream encountered, expecting USERNAME"));
	const AUTO(user_it, g_authorized_users.find(username));
	DEBUG_THROW_UNLESS(user_it != g_authorized_users.end(), Poseidon::Cbpp::Exception, Protocol::ERR_AUTHORIZATION_FAILURE,
		Poseidon::sslit("User not found"));
	boost::uint64_t timestamp_be;
	// TIMESTAMP: 8 bytes
	DEBUG_THROW_UNLESS(ciphertext.get(&timestamp_be, 8) == 8, Poseidon::Cbpp::Exception, Protocol::ERR_END_OF_STREAM,
		Poseidon::sslit("End of stream encountered, expecting TIMESTAMP"));
	const boost::uint64_t timestamp = Poseidon::load_be(timestamp_be);
	DEBUG_THROW_UNLESS(timestamp >= Poseidon::saturated_sub(utc_now, g_message_lifetime), Poseidon::Cbpp::Exception, Protocol::ERR_AUTHORIZATION_FAILURE,
		Poseidon::sslit("Request expired"));
	DEBUG_THROW_UNLESS(timestamp < Poseidon::saturated_add(utc_now, g_message_lifetime), Poseidon::Cbpp::Exception, Protocol::ERR_AUTHORIZATION_FAILURE,
		Poseidon::sslit("Timestamp too far in the future"));
	// KEY_CHECKSUM: 8 bytes
	boost::array<unsigned char, 8> checksum;
	DEBUG_THROW_UNLESS(ciphertext.get(checksum.data(), 8) == 8, Poseidon::Cbpp::Exception, Protocol::ERR_END_OF_STREAM,
		Poseidon::sslit("End of stream encountered, expecting KEY_CHECKSUM"));
	Poseidon::Sha256_ostream sha256_os;
	sha256_os <<timestamp <<'#' <<user_it->second <<'#';
	AUTO(sha256, sha256_os.finalize());
	DEBUG_THROW_UNLESS(std::memcmp(checksum.data(), sha256.data(), 8) == 0, Poseidon::Cbpp::Exception, Protocol::ERR_AUTHORIZATION_FAILURE,
		Poseidon::sslit("Incorrect key (checksum mismatch)"));
	const AUTO(aes_key, aes_key_init_192(sha256.data() + 8));
	// DATA_CHECKSUM: 8 bytes
	DEBUG_THROW_UNLESS(ciphertext.get(checksum.data(), 8) == 8, Poseidon::Cbpp::Exception, Protocol::ERR_END_OF_STREAM,
		Poseidon::sslit("End of stream encountered, expecting DATA_CHECKSUM"));
	// DATA: ? bytes
	aes_ctr_transform(plaintext, ciphertext, aes_key);
	sha256_os <<timestamp <<'#' <<plaintext <<'#';
	sha256 = sha256_os.finalize();
	DEBUG_THROW_UNLESS(std::memcmp(checksum.data(), sha256.data(), 8) == 0, Poseidon::Cbpp::Exception, Protocol::ERR_BAD_REQUEST,
		Poseidon::sslit("Request not recognized (checksum mismatch)"));
	return plaintext;
}

}
}
