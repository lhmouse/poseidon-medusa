#include "precompiled.hpp"
#include "secondary_client.hpp"
#include "mmain.hpp"
#include "common/encryption.hpp"
#include "protocol/messages.hpp"
#include "protocol/error_codes.hpp"
#include "singletons/proxy_server.hpp"
#include <poseidon/cbpp/exception.hpp>

namespace Medusa2 {
namespace Primary {

class SecondaryClient::Channel : NONCOPYABLE {
private:
	const boost::weak_ptr<SecondaryClient> m_weak_parent;
	const Poseidon::Uuid m_channel_uuid;
	const boost::weak_ptr<ProxySession> m_weak_proxy_session;

public:
	Channel(const boost::shared_ptr<SecondaryClient> &parent, const Poseidon::Uuid &channel_uuid, const boost::shared_ptr<ProxySession> &proxy_session)
		: m_weak_parent(parent), m_channel_uuid(channel_uuid), m_weak_proxy_session(proxy_session)
	{ }
	~Channel(){ }

public:
	boost::shared_ptr<SecondaryClient> get_parent() const {
		return m_weak_parent.lock();
	}
	const Poseidon::Uuid &get_channel_uuid() const {
		return m_channel_uuid;
	}

	void on_opened(){
		PROFILE_ME;

		const AUTO(proxy_session, m_weak_proxy_session.lock());
		if(!proxy_session){
			return;
		}

		proxy_session->on_sync_opened(m_channel_uuid);
	}
	void on_established(){
		PROFILE_ME;

		const AUTO(proxy_session, m_weak_proxy_session.lock());
		if(!proxy_session){
			return;
		}

		proxy_session->on_sync_established(m_channel_uuid);
	}
	void on_received(Poseidon::Move<std::basic_string<unsigned char> > segment){
		PROFILE_ME;

		const AUTO(proxy_session, m_weak_proxy_session.lock());
		if(!proxy_session){
			return;
		}

		proxy_session->on_sync_received(m_channel_uuid, STD_MOVE(segment));
	}
	void on_closed(long err_code, Poseidon::Move<std::string> err_msg){
		PROFILE_ME;

		const AUTO(proxy_session, m_weak_proxy_session.lock());
		if(!proxy_session){
			return;
		}

		proxy_session->on_sync_closed(m_channel_uuid, err_code, STD_MOVE(err_msg));
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

		Poseidon::Uuid session_uuid;
		DEBUG_THROW_ASSERT(msg.opaque.copy(session_uuid.data(), 16, 0) == 16);
		const AUTO(proxy_session, ProxyServer::get_session(session_uuid));
		if(!proxy_session){
			LOG_MEDUSA2_DEBUG("ProxySession is gone: channel_uuid = ", channel_uuid, ", session_uuid = ", session_uuid);
			channel_shutdown(channel_uuid, true);
			break;
		}
		const AUTO(channel, boost::make_shared<Channel>(virtual_shared_from_this<SecondaryClient>(), channel_uuid, proxy_session));
		const AUTO(it, m_channels.emplace(channel_uuid, channel));

		channel->on_opened();
		(void)it;
	}
	ON_MESSAGE(Protocol::SP_Established, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Tunnel established in channel: channel_uuid = ", channel_uuid);

		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA2_WARNING("Channel not found: channel_uuid = ", channel_uuid);
			channel_shutdown(channel_uuid, true);
			break;
		}
		const AUTO(channel, it->second);

		channel->on_established();
	}
	ON_MESSAGE(Protocol::SP_Received, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Data received from channel: channel_uuid = ", channel_uuid, ", segment.size() = ", msg.segment.size());

		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA2_WARNING("Channel not found: channel_uuid = ", channel_uuid);
			m_channels.erase(it);
			channel_shutdown(channel_uuid, true);
			break;
		}
		const AUTO(channel, it->second);

		channel->on_received(STD_MOVE(msg.segment));
	}
	ON_MESSAGE(Protocol::SP_Closed, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Channel closed: channel_uuid = ", channel_uuid, ", err_code = ", msg.err_code, ", err_msg = ", msg.err_msg);

		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA2_WARNING("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		const AUTO(channel, STD_MOVE_IDN(it->second));
		m_channels.erase(it);

		channel->on_closed(msg.err_code, STD_MOVE(msg.err_msg));
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

Poseidon::Uuid SecondaryClient::channel_connect(const boost::shared_ptr<ProxySession> &proxy_session, std::string host, unsigned port, bool use_ssl){
	PROFILE_ME;

	const AUTO(channel_uuid, Poseidon::Uuid::random());

	std::basic_string<unsigned char> opaque;
	opaque.append(proxy_session->get_session_uuid().data(), 16);

	Protocol::PS_Connect msg;
	msg.channel_uuid = channel_uuid;
	msg.opaque       = STD_MOVE(opaque);
	msg.host         = STD_MOVE(host);
	msg.port         = port;
	msg.use_ssl      = use_ssl;
	send(msg);

	return channel_uuid;
}
void SecondaryClient::channel_send(const Poseidon::Uuid &channel_uuid, std::basic_string<unsigned char> segment){
	PROFILE_ME;

	Protocol::PS_Send msg;
	msg.channel_uuid = channel_uuid;
	msg.segment      = STD_MOVE(segment);
	send(msg);
}
void SecondaryClient::channel_acknowledge(const Poseidon::Uuid &channel_uuid, boost::uint64_t bytes_to_acknowledge){
	PROFILE_ME;

	Protocol::PS_Acknowledge msg;
	msg.channel_uuid         = channel_uuid;
	msg.bytes_to_acknowledge = bytes_to_acknowledge;
	send(msg);
}
void SecondaryClient::channel_shutdown(const Poseidon::Uuid &channel_uuid, bool no_linger) NOEXCEPT
try {
	PROFILE_ME;

	Protocol::PS_Shutdown msg;
	msg.channel_uuid = channel_uuid;
	msg.no_linger    = no_linger;
	send(msg);
} catch(std::exception &e){
	LOG_MEDUSA2_ERROR("std::exception thrown: remote = ", get_remote_info(), ", what = ", e.what());
	shutdown(Protocol::ERR_INTERNAL_ERROR, e.what());
}

}
}
