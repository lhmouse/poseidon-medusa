#include "precompiled.hpp"
#include "secondary_client.hpp"
#include "mmain.hpp"
#include "common/encryption.hpp"
#include "protocol/messages.hpp"
#include "protocol/error_codes.hpp"
#include "singletons/proxy_server.hpp"
#include <poseidon/cbpp/exception.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/singletons/job_dispatcher.hpp>

namespace Medusa2 {
namespace Primary {

class SecondaryClient::Channel : NONCOPYABLE {
private:
	const boost::weak_ptr<SecondaryClient> m_weak_parent;
	const Poseidon::Uuid m_channel_uuid;

	boost::weak_ptr<ProxySession> m_weak_proxy_session;

public:
	Channel(const boost::shared_ptr<SecondaryClient> &parent, const Poseidon::Uuid &channel_uuid, const boost::shared_ptr<ProxySession> &proxy_session)
		: m_weak_parent(parent), m_channel_uuid(channel_uuid), m_weak_proxy_session(proxy_session)
	{
		LOG_MEDUSA2_TRACE("Channel constructor: channel_uuid = ", m_channel_uuid);
	}
	~Channel(){
		LOG_MEDUSA2_TRACE("Channel destructor: channel_uuid = ", m_channel_uuid);

		const AUTO(proxy_session, m_weak_proxy_session.lock());
		if(proxy_session){
			LOG_MEDUSA2_WARNING("ProxySession was not shut down cleanly: channel_uuid = ", m_channel_uuid);
			proxy_session->force_shutdown();
		}
	}

public:
	void on_opened(const std::bitset<32> &options){
		PROFILE_ME;

		const AUTO(proxy_session, m_weak_proxy_session.lock());
		if(!proxy_session){
			return;
		}
		DEBUG_THROW_ASSERT(proxy_session->get_session_uuid() == m_channel_uuid);

		proxy_session->on_fetch_opened(options);
	}
	void on_established(){
		PROFILE_ME;

		const AUTO(proxy_session, m_weak_proxy_session.lock());
		if(!proxy_session){
			return;
		}
		DEBUG_THROW_ASSERT(proxy_session->get_session_uuid() == m_channel_uuid);

		proxy_session->on_fetch_established();
	}
	void on_received(std::basic_string<unsigned char> segment){
		PROFILE_ME;

		const AUTO(proxy_session, m_weak_proxy_session.lock());
		if(!proxy_session){
			return;
		}
		DEBUG_THROW_ASSERT(proxy_session->get_session_uuid() == m_channel_uuid);

		proxy_session->on_fetch_received(STD_MOVE(segment));
	}
	void on_closed(long err_code, std::string err_msg){
		PROFILE_ME;

		const AUTO(proxy_session, m_weak_proxy_session.lock());
		m_weak_proxy_session.reset();
		if(!proxy_session){
			return;
		}
		DEBUG_THROW_ASSERT(proxy_session->get_session_uuid() == m_channel_uuid);

		proxy_session->on_fetch_closed(err_code, STD_MOVE(err_msg));
	}
};

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

		for(AUTO(it, client->m_channels.begin()); it != client->m_channels.end(); ++it){
			const AUTO(channel, it->second);
			try {
				channel->on_closed(Protocol::ERR_SECONDARY_SERVER_CONNECTION_LOST, "Lost connection to secondary server");
			} catch(std::exception &e){
				LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
			}
		}
		client->m_channels.clear();
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
		const AUTO(options, std::bitset<32>(msg.opaque));
		LOG_MEDUSA2_DEBUG("Channel opened: channel_uuid = ", channel_uuid, ", options = ", options);

		const AUTO(proxy_session, ProxyServer::get_session(channel_uuid));
		if(!proxy_session){
			LOG_MEDUSA2_DEBUG("ProxySession is gone: channel_uuid = ", channel_uuid);
			channel_shutdown(channel_uuid, true);
			break;
		}
		const AUTO(channel, boost::make_shared<Channel>(virtual_shared_from_this<SecondaryClient>(), channel_uuid, proxy_session));
		const AUTO(it, m_channels.emplace(channel_uuid, channel));

		channel->on_opened(options);
		(void)it;
	}
	ON_MESSAGE(Protocol::SP_Established, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Tunnel established in channel: channel_uuid = ", channel_uuid);

		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
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
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
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
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
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

void SecondaryClient::channel_connect(const boost::shared_ptr<ProxySession> &proxy_session, const std::bitset<32> &options, std::string host, unsigned port, bool use_ssl, bool no_delay){
	PROFILE_ME;

	Protocol::PS_Connect msg;
	msg.channel_uuid = proxy_session->get_session_uuid();
	msg.opaque       = options.to_string<unsigned char>();
	msg.host         = STD_MOVE(host);
	msg.port         = port;
	msg.use_ssl      = use_ssl;
	msg.no_delay     = no_delay;
	send(msg);
}
void SecondaryClient::channel_send(const Poseidon::Uuid &session_uuid, std::basic_string<unsigned char> segment){
	PROFILE_ME;

	Protocol::PS_Send msg;
	msg.channel_uuid = session_uuid;
	msg.segment      = STD_MOVE(segment);
	send(msg);
}
void SecondaryClient::channel_acknowledge(const Poseidon::Uuid &session_uuid, boost::uint64_t bytes_to_acknowledge){
	PROFILE_ME;

	Protocol::PS_Acknowledge msg;
	msg.channel_uuid         = session_uuid;
	msg.bytes_to_acknowledge = bytes_to_acknowledge;
	send(msg);
}
void SecondaryClient::channel_shutdown(const Poseidon::Uuid &session_uuid, bool no_linger) NOEXCEPT
try {
	PROFILE_ME;

	Protocol::PS_Shutdown msg;
	msg.channel_uuid = session_uuid;
	msg.no_linger    = no_linger;
	send(msg);
} catch(std::exception &e){
	LOG_MEDUSA2_ERROR("std::exception thrown: remote = ", get_remote_info(), ", what = ", e.what());
	shutdown(Protocol::ERR_INTERNAL_ERROR, e.what());
}

}
}
