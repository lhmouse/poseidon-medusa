// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#include "precompiled.hpp"
#include "secondary_channel.hpp"
#include "singletons/secondary_connector.hpp"
#include "mmain.hpp"
#include "protocol/messages.hpp"
#include "protocol/error_codes.hpp"

namespace Medusa2 {
namespace Primary {

Secondary_channel::Secondary_channel(std::string host, unsigned port, bool use_ssl, bool no_delay)
	: m_channel_uuid(Poseidon::Uuid::random())
	, m_host(STD_MOVE(host)), m_port(port), m_use_ssl(use_ssl), m_no_delay(no_delay)
	, m_shutdown(false)
{
	MEDUSA2_LOG_DEBUG("Secondary_channel constructor: channel_uuid = ", get_channel_uuid());
}
Secondary_channel::~Secondary_channel(){
	MEDUSA2_LOG_DEBUG("Secondary_channel destructor: channel_uuid = ", get_channel_uuid());
}

bool Secondary_channel::has_been_shutdown() const NOEXCEPT {
	return Poseidon::atomic_load(m_shutdown, Poseidon::memory_order_acquire);
}
bool Secondary_channel::shutdown(bool no_linger) NOEXCEPT {
	POSEIDON_PROFILE_ME;

	bool was_shutdown = Poseidon::atomic_load(m_shutdown, Poseidon::memory_order_acquire);
	if(!was_shutdown){
		was_shutdown = Poseidon::atomic_exchange(m_shutdown, true, Poseidon::memory_order_acq_rel);
	}
	if(was_shutdown){
		return false;
	}
	try {
		Protocol::PS_Shutdown msg;
		msg.channel_uuid = get_channel_uuid();
		msg.no_linger    = no_linger;
		Secondary_connector::send(msg);
	} catch(std::exception &e){
		MEDUSA2_LOG_ERROR("std::exception thrown: what = ", e.what());
		Secondary_connector::shutdown(Protocol::error_internal_error, e.what());
		return false;
	}
	return true;
}

bool Secondary_channel::send(Poseidon::Stream_buffer data){
	POSEIDON_PROFILE_ME;

	if(has_been_shutdown()){
		MEDUSA2_LOG_DEBUG("Channel is gone: channel_uuid = ", get_channel_uuid());
		return false;
	}
	try {
		const AUTO(fragmentation_size, get_config<std::size_t>("proxy_fragmentation_size", 8192));
		Protocol::PS_Send msg;
		msg.channel_uuid = get_channel_uuid();
		do {
			msg.segment = data.cut_off(fragmentation_size);
		} while(!msg.segment.empty() && Secondary_connector::send(msg));
	} catch(std::exception &e){
		MEDUSA2_LOG_ERROR("std::exception thrown: what = ", e.what());
		Secondary_connector::shutdown(Protocol::error_internal_error, e.what());
		return false;
	}
	return true;
}

}
}
