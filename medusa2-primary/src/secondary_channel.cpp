#include "precompiled.hpp"
#include "secondary_channel.hpp"
#include "singletons/secondary_connector.hpp"
#include "mmain.hpp"
#include "protocol/messages.hpp"
#include "protocol/error_codes.hpp"

namespace Medusa2 {
namespace Primary {

SecondaryChannel::SecondaryChannel(std::string host, unsigned port, bool use_ssl, bool no_delay)
	: m_channel_uuid(Poseidon::Uuid::random())
	, m_host(STD_MOVE(host)), m_port(port), m_use_ssl(use_ssl), m_no_delay(no_delay)
	, m_shutdown(false)
{
	LOG_MEDUSA2_DEBUG("SecondaryChannel constructor: channel_uuid = ", get_channel_uuid());
}
SecondaryChannel::~SecondaryChannel(){
	LOG_MEDUSA2_DEBUG("SecondaryChannel destructor: channel_uuid = ", get_channel_uuid());
}

bool SecondaryChannel::has_been_shutdown() const NOEXCEPT {
	return Poseidon::atomic_load(m_shutdown, Poseidon::ATOMIC_ACQUIRE);
}
bool SecondaryChannel::shutdown(bool no_linger) NOEXCEPT {
	PROFILE_ME;

	bool was_shutdown = Poseidon::atomic_load(m_shutdown, Poseidon::ATOMIC_ACQUIRE);
	if(!was_shutdown){
		was_shutdown = Poseidon::atomic_exchange(m_shutdown, true, Poseidon::ATOMIC_ACQ_REL);
	}
	if(was_shutdown){
		return false;
	}
	try {
		Protocol::PS_Shutdown msg;
		msg.channel_uuid = get_channel_uuid();
		msg.no_linger    = no_linger;
		SecondaryConnector::send(msg);
	} catch(std::exception &e){
		LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
		SecondaryConnector::shutdown(Protocol::ERR_INTERNAL_ERROR, e.what());
		return false;
	}
	return true;
}

bool SecondaryChannel::send(Poseidon::StreamBuffer data){
	PROFILE_ME;

	if(has_been_shutdown()){
		LOG_MEDUSA2_DEBUG("Channel is gone: channel_uuid = ", get_channel_uuid());
		return false;
	}
	try {
		Protocol::PS_Send msg;
		msg.channel_uuid = get_channel_uuid();
		do {
			const AUTO(fragmentation_size, get_config<std::size_t>("proxy_fragmentation_size", 8192));
			msg.segment.resize(fragmentation_size);
			msg.segment.resize(data.get(&msg.segment[0], msg.segment.size()));
		} while(!msg.segment.empty() && SecondaryConnector::send(msg));
	} catch(std::exception &e){
		LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
		SecondaryConnector::shutdown(Protocol::ERR_INTERNAL_ERROR, e.what());
		return false;
	}
	return true;
}

}
}
