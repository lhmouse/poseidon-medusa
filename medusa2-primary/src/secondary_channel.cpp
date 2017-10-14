#include "precompiled.hpp"
#include "secondary_channel.hpp"
#include "secondary_client.hpp"
#include "mmain.hpp"
#include "protocol/messages.hpp"
#include "protocol/error_codes.hpp"

namespace Medusa2 {
namespace Primary {

SecondaryChannel::SecondaryChannel()
	: m_weak_parent(), m_channel_uuid()
{
	LOG_MEDUSA2_DEBUG("SecondaryChannel constructor: this = ", (void *)this);
}
SecondaryChannel::~SecondaryChannel(){
	LOG_MEDUSA2_DEBUG("SecondaryChannel destructor: this = ", (void *)this);
}

void SecondaryChannel::activate(const boost::shared_ptr<SecondaryClient> &parent, const Poseidon::Uuid &channel_uuid){
	DEBUG_THROW_ASSERT(!m_channel_uuid);

	m_weak_parent  = parent;
	m_channel_uuid = channel_uuid;
}

bool SecondaryChannel::send(Poseidon::StreamBuffer data){
	PROFILE_ME;

	const AUTO(parent, m_weak_parent.lock());
	if(!parent){
		return false;
	}

	Protocol::PS_Send msg;
	msg.channel_uuid = m_channel_uuid;
	for(;;){
		const AUTO(fragmentation_size, get_config<std::size_t>("proxy_fragmentation_size", 8192));
		msg.segment.resize(fragmentation_size);

		msg.segment.resize(data.get(&msg.segment[0], msg.segment.size()));
		if(msg.segment.empty()){
			break;
		}
		if(!parent->send(msg)){
			LOG_MEDUSA2_WARNING("Failed to send message to ", parent->get_remote_info());
			return false;
		}
	}
	return true;
}
void SecondaryChannel::shutdown(bool no_linger) NOEXCEPT {
	PROFILE_ME;

	const AUTO(parent, m_weak_parent.lock());
	if(!parent){
		return;
	}

	try {
		Protocol::PS_Shutdown msg;
		msg.channel_uuid = m_channel_uuid;
		msg.no_linger    = no_linger;
		if(!parent->send(msg)){
			LOG_MEDUSA2_WARNING("Failed to send message to ", parent->get_remote_info());
			return;
		}
	} catch(std::exception &e){
		LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
		parent->shutdown(Protocol::ERR_INTERNAL_ERROR, e.what());
	}
}

}
}
