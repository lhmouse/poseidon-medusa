#include "precompiled.hpp"
#include "secondary_client.hpp"
#include "mmain.hpp"
#include "common/encryption.hpp"
#include "protocol/messages.hpp"
#include "protocol/error_codes.hpp"
#include <poseidon/cbpp/exception.hpp>

namespace Medusa2 {
namespace Primary {

SecondaryClient::SecondaryClient(const Poseidon::SockAddr &sock_addr, bool use_ssl)
	: Poseidon::Cbpp::Client(sock_addr, use_ssl)
{
	LOG_MEDUSA2_INFO("SecondaryClient destructor: remote = ", sock_addr);
}
SecondaryClient::~SecondaryClient(){
	LOG_MEDUSA2_INFO("SecondaryClient destructor: remote = ", get_remote_info());
}

void SecondaryClient::on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload){
	PROFILE_ME;
	LOG_MEDUSA2_TRACE("Received data message: remote = ", get_remote_info(), ", message_id = ", message_id);

	AUTO(plaintext, Common::decrypt(STD_MOVE(payload)));
	LOG_MEDUSA2_TRACE("> message_id = ", message_id, ", plaintext.size() = ", plaintext.size());
	switch(message_id){
		{{
#define ON_MESSAGE(Msg_, msg_)	\
		}	\
		break; }	\
	case Msg_::ID: {	\
		PROFILE_ME;	\
		Msg_ msg_(STD_MOVE(plaintext));	\
		{
//=============================================================================
	ON_MESSAGE(Protocol::SP_Opened, msg){
		LOG_MEDUSA2_FATAL("OPENED: channel_uuid = ", Poseidon::Uuid(msg.channel_uuid));
	}
	ON_MESSAGE(Protocol::SP_Established, msg){
		LOG_MEDUSA2_FATAL("ESTABLISHED: channel_uuid = ", Poseidon::Uuid(msg.channel_uuid));
	}
	ON_MESSAGE(Protocol::SP_Received, msg){
		LOG_MEDUSA2_FATAL("RECEIVED: channel_uuid = ", Poseidon::Uuid(msg.channel_uuid), ", size = ", msg.segment.size());
		LOG_MEDUSA2_ERROR((const char *)msg.segment.c_str());
	}
	ON_MESSAGE(Protocol::SP_Closed, msg){
		LOG_MEDUSA2_FATAL("CLOSED: channel_uuid = ", Poseidon::Uuid(msg.channel_uuid), ", err_code = ", msg.err_code, ", err_msg = ", msg.err_msg);
	}
//=============================================================================
#undef ON_MESSAGE
		}
		break; }
	default:
		LOG_MEDUSA2_ERROR("Unknown message: remote = ", get_remote_info(), ", message_id = ", message_id);
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_NOT_FOUND, Poseidon::sslit("Unknown message"));
	}
}

bool SecondaryClient::send(const Poseidon::Cbpp::MessageBase &msg){
	PROFILE_ME;

	AUTO(ciphertext, Common::encrypt(msg));
	return Poseidon::Cbpp::Client::send(msg.get_id(), STD_MOVE(ciphertext));
}

}
}
