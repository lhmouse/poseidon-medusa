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

	MODULE_RAII_PRIORITY(, 1000){
		LOG_MEDUSA2_INFO("Initialize global cipher...");

		const AUTO(users_v, get_config_v<std::string>("encryption_authorized_user"));
		for(AUTO(it, users_v.begin()); it != users_v.end(); ++it){
			const AUTO_REF(str, *it);
			LOG_MEDUSA2_TRACE("> Authorized user: ", str);
			const AUTO(pos, str.find(':'));
			if(pos == str.npos){
				LOG_MEDUSA2_FATAL("Invalid encryption_authorized_user: ", str,  "(Hint: encryption_authorized_user = USERNAME:PASSWORD)");
				DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Invalid encryption_authorized_user"));
			}
			if(pos == 0){
				LOG_MEDUSA2_FATAL("Username must not be empty: ", str);
				DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Username must not be empty"));
			}
			if(pos > 16){
				LOG_MEDUSA2_FATAL("Username must contain no more than 16 bytes: ", str);
				DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Username must contain no more than 16 bytes"));
			}
			boost::array<unsigned char, 16> username;
			std::memset(username.data(), 0, 16);
			std::memcpy(username.data(), str.data(), pos);
			const AUTO(result, g_authorized_users.emplace(username, str));
			if(!result.second){
				LOG_MEDUSA2_FATAL("Duplicate username: ", str);
				DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Duplicate username"));
			}
		}
		g_message_lifetime = get_config<boost::uint64_t>("encryption_message_lifetime", 60000);
	}

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

Poseidon::StreamBuffer encrypt(Poseidon::StreamBuffer plaintext){
	PROFILE_ME;

	Poseidon::StreamBuffer ciphertext;
	const AUTO(utc_now, Poseidon::get_utc_time());

	AUTO(user_it, g_authorized_users.begin());
	DEBUG_THROW_ASSERT(g_authorized_users.size() > 0);
	std::advance(user_it, static_cast<int>(Poseidon::random_uint32() % g_authorized_users.size()));
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
	if(ciphertext.get(&username, 16) < 16){
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_END_OF_STREAM, Poseidon::sslit("End of stream encountered, expecting USERNAME"));
	}
	const AUTO(user_it, g_authorized_users.find(username));
	if(user_it == g_authorized_users.end()){
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_AUTHORIZATION_FAILURE, Poseidon::sslit("User not found"));
	}
	boost::uint64_t timestamp_be;
	// TIMESTAMP: 8 bytes
	if(ciphertext.get(&timestamp_be, 8) < 8){
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_END_OF_STREAM, Poseidon::sslit("End of stream encountered, expecting TIMESTAMP"));
	}
	const boost::uint64_t timestamp = Poseidon::load_be(timestamp_be);
	if(timestamp < Poseidon::saturated_sub(utc_now, g_message_lifetime)){
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_AUTHORIZATION_FAILURE, Poseidon::sslit("Request expired"));
	}
	if(timestamp > Poseidon::saturated_add(utc_now, g_message_lifetime)){
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_AUTHORIZATION_FAILURE, Poseidon::sslit("Timestamp too far in the future"));
	}
	// KEY_CHECKSUM: 8 bytes
	boost::array<unsigned char, 8> checksum;
	if(ciphertext.get(checksum.data(), 8) < 8){
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_END_OF_STREAM, Poseidon::sslit("End of stream encountered, expecting KEY_CHECKSUM"));
	}
	Poseidon::Sha256_ostream sha256_os;
	sha256_os <<timestamp <<'#' <<user_it->second <<'#';
	AUTO(sha256, sha256_os.finalize());
	if(std::memcmp(checksum.data(), sha256.data(), 8) != 0){
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_AUTHORIZATION_FAILURE, Poseidon::sslit("Incorrect key (checksum mismatch)"));
	}
	const AUTO(aes_key, aes_key_init_192(sha256.data() + 8));
	// DATA_CHECKSUM: 8 bytes
	if(ciphertext.get(checksum.data(), 8) < 8){
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_END_OF_STREAM, Poseidon::sslit("End of stream encountered, expecting DATA_CHECKSUM"));
	}
	// DATA: ? bytes
	aes_ctr_transform(plaintext, ciphertext, aes_key);
	sha256_os <<timestamp <<'#' <<plaintext <<'#';
	sha256 = sha256_os.finalize();
	if(std::memcmp(checksum.data(), sha256.data(), 8) != 0){
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_DATA_CORRUPTED, Poseidon::sslit("Data corrupted (checksum mismatch)"));
	}
	return plaintext;
}

}
}
