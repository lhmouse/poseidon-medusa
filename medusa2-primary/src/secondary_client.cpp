#include "precompiled.hpp"
#include "secondary_client.hpp"
#include "mmain.hpp"
#include "common/encryption.hpp"
#include "protocol/messages.hpp"
#include "protocol/error_codes.hpp"
#include <poseidon/cbpp/exception.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/singletons/job_dispatcher.hpp>

namespace Medusa2 {
namespace Primary {

class SecondaryClient::CloseJob : public Poseidon::JobBase {
private:
	const boost::shared_ptr<SecondaryClient> m_client;

public:
	explicit CloseJob(const boost::shared_ptr<SecondaryClient> &client)
		: m_client(client)
	{ }

private:
	boost::weak_ptr<const void> get_category() const FINAL {
		return m_client;
	}
	void perform() FINAL {
		PROFILE_ME;

		const AUTO_REF(client, m_client);
		DEBUG_THROW_ASSERT(client);

		VALUE_TYPE(client->m_channels_pending) channels_pending;
		{
			const Poseidon::Mutex::UniqueLock lock(client->m_establishment_mutex);
			channels_pending.swap(client->m_channels_pending);
		}
		LOG_MEDUSA2_TRACE("Number of channels pending: ", channels_pending.size());

		VALUE_TYPE(client->m_channels_established) channels_established;
		channels_established.swap(client->m_channels_established);
		LOG_MEDUSA2_TRACE("Number of channels established: ", channels_established.size());

		for(AUTO(it, channels_pending.begin()); it != channels_pending.end(); ++it){
			const AUTO_REF(channel, it->second);
			try {
				channel->on_sync_closed(Protocol::ERR_SECONDARY_SERVER_CONNECTION_LOST, "Lost connection to secondary server");
			} catch(std::exception &e){
				LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
			}
		}
		for(AUTO(it, channels_established.begin()); it != channels_established.end(); ++it){
			const AUTO_REF(channel, it->second);
			try {
				channel->on_sync_closed(Protocol::ERR_SECONDARY_SERVER_CONNECTION_LOST, "Lost connection to secondary server");
			} catch(std::exception &e){
				LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
			}
		}
	}
};

SecondaryClient::SecondaryClient(const Poseidon::SockAddr &sock_addr, bool use_ssl)
	: Poseidon::Cbpp::Client(sock_addr, use_ssl)
{
	LOG_MEDUSA2_INFO("SecondaryClient destructor: remote = ", sock_addr);
}
SecondaryClient::~SecondaryClient(){
	LOG_MEDUSA2_INFO("SecondaryClient destructor: remote = ", get_remote_info());
}

void SecondaryClient::on_close(int err_code){
	PROFILE_ME;

	Poseidon::JobDispatcher::enqueue(
		boost::make_shared<CloseJob>(virtual_shared_from_this<SecondaryClient>()),
		VAL_INIT);

	return Poseidon::Cbpp::Client::on_close(err_code);
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
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Channel opened: channel_uuid = ", channel_uuid);

		boost::shared_ptr<ChannelBase> channel;
		{
			const Poseidon::Mutex::UniqueLock lock(m_establishment_mutex);
			const AUTO(it, m_channels_pending.find(channel_uuid));
			if(it != m_channels_pending.end()){
				channel = STD_MOVE(it->second);
				m_channels_pending.erase(it);
			}
		}
		if(!channel){
			LOG_MEDUSA2_WARNING("Dangling channel: channel_uuid = ", channel_uuid);
			send(Protocol::PS_Shutdown(channel_uuid, true));
			break;
		}
		const AUTO(it, m_channels_established.emplace(channel_uuid, channel));

		(void)it;
	}
	ON_MESSAGE(Protocol::SP_Established, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Channel established: channel_uuid = ", channel_uuid);

		const AUTO(it, m_channels_established.find(channel_uuid));
		if(it == m_channels_established.end()){
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		const AUTO(channel, it->second);

		try {
			channel->on_sync_established();
		} catch(std::exception &e){
			LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
			send(Protocol::PS_Shutdown(channel_uuid, true));
		}
	}
	ON_MESSAGE(Protocol::SP_Received, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Data received from channel: channel_uuid = ", channel_uuid, ", segment.size() = ", msg.segment.size());

		const AUTO(it, m_channels_established.find(channel_uuid));
		if(it == m_channels_established.end()){
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		const AUTO(channel, it->second);

		try {
			const AUTO(bytes_to_acknowledge, msg.segment.size());
			channel->on_sync_received(Poseidon::StreamBuffer(msg.segment));
			send(Protocol::PS_Acknowledge(channel_uuid, bytes_to_acknowledge));
		} catch(std::exception &e){
			LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
			send(Protocol::PS_Shutdown(channel_uuid, true));
		}
	}
	ON_MESSAGE(Protocol::SP_Closed, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Channel closed: channel_uuid = ", channel_uuid, ", err_code = ", msg.err_code, ", err_msg = ", msg.err_msg);

		const AUTO(it, m_channels_established.find(channel_uuid));
		if(it == m_channels_established.end()){
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		const AUTO(channel, STD_MOVE_IDN(it->second));
		m_channels_established.erase(it);

		try {
			channel->on_sync_closed(msg.err_code, STD_MOVE(msg.err_msg));
		} catch(std::exception &e){
			LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
		}
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

void SecondaryClient::attach_channel(const boost::shared_ptr<ChannelBase> &channel, std::string host, unsigned port, bool use_ssl, bool no_delay){
	PROFILE_ME;
	DEBUG_THROW_ASSERT(!channel->get_channel_uuid());

	const AUTO(shared_this, virtual_shared_from_this<SecondaryClient>());
	const AUTO(channel_uuid, Poseidon::Uuid::random());
	{
		const Poseidon::Mutex::UniqueLock lock(m_establishment_mutex);
		const AUTO(it, m_channels_pending.emplace(channel_uuid, channel));
		channel->m_weak_parent = shared_this;
		channel->m_channel_uuid = channel_uuid;
		(void)it;
	}
	LOG_MEDUSA2_DEBUG("Channel inserted: channel = ", channel.get(), ", channel_uuid = ", channel_uuid, ", remote = ", get_remote_info());

	Protocol::PS_Connect msg;
	msg.channel_uuid = channel_uuid;
	msg.host         = STD_MOVE(host);
	msg.port         = port;
	msg.use_ssl      = use_ssl;
	msg.no_delay     = no_delay;
	send(msg);
}

SecondaryClient::ChannelBase::ChannelBase()
	: m_weak_parent(), m_channel_uuid()
{
	LOG_MEDUSA2_DEBUG("SecondaryClient::ChannelBase constructor: this = ", this);
}
SecondaryClient::ChannelBase::~ChannelBase(){
	LOG_MEDUSA2_DEBUG("SecondaryClient::ChannelBase destructor: this = ", this);
}

bool SecondaryClient::ChannelBase::send(Poseidon::StreamBuffer data){
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
			LOG_MEDUSA2_WARNING("Failed to send data to ", parent->get_remote_info());
			return false;
		}
	}
	return true;
}
void SecondaryClient::ChannelBase::shutdown(bool no_linger) NOEXCEPT {
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
			LOG_MEDUSA2_WARNING("Failed to send data to ", parent->get_remote_info());
			return;
		}
	} catch(std::exception &e){
		LOG_MEDUSA2_WARNING("std::exception thrown: what = ", e.what());
		parent->shutdown(Protocol::ERR_INTERNAL_ERROR, e.what());
	}
}

}
}
