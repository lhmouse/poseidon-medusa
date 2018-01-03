// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#include "precompiled.hpp"
#include "secondary_connector.hpp"
#include "../mmain.hpp"
#include "common/encryption.hpp"
#include "protocol/error_codes.hpp"
#include "protocol/messages.hpp"
#include <poseidon/cbpp/client.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/sock_addr.hpp>
#include <poseidon/singletons/dns_daemon.hpp>

namespace Medusa2 {
namespace Primary {

namespace {
	boost::container::flat_map<Poseidon::Uuid, boost::shared_ptr<SecondaryChannel> > g_channels;

	class SecondaryClient : public Poseidon::Cbpp::Client {
	public:
		SecondaryClient(const Poseidon::SockAddr &sock_addr, bool use_ssl)
			: Poseidon::Cbpp::Client(sock_addr, use_ssl)
		{
			LOG_MEDUSA2_INFO("SecondaryClient constructor: remote = ", Poseidon::IpPort(sock_addr));
		}
		~SecondaryClient(){
			LOG_MEDUSA2_INFO("SecondaryClient destructor: remote = ", get_remote_info());
		}

	protected:
		void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE {
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

				const AUTO(it, g_channels.find(channel_uuid));
				if(it == g_channels.end()){
					LOG_MEDUSA2_WARNING("Dangling channel: channel_uuid = ", channel_uuid);
					break;
				}
				const AUTO(channel, it->second);

				channel->on_sync_opened();
			}
			ON_MESSAGE(Protocol::SP_Established, msg){
				const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
				LOG_MEDUSA2_DEBUG("Channel established: channel_uuid = ", channel_uuid);

				const AUTO(it, g_channels.find(channel_uuid));
				if(it == g_channels.end()){
					LOG_MEDUSA2_WARNING("Dangling channel: channel_uuid = ", channel_uuid);
					break;
				}
				const AUTO(channel, it->second);

				channel->on_sync_established();
			}
			ON_MESSAGE(Protocol::SP_Received, msg){
				const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
				LOG_MEDUSA2_DEBUG("Data received from channel: channel_uuid = ", channel_uuid, ", segment.size() = ", msg.segment.size());

				const AUTO(it, g_channels.find(channel_uuid));
				if(it == g_channels.end()){
					LOG_MEDUSA2_WARNING("Dangling channel: channel_uuid = ", channel_uuid);
					break;
				}
				const AUTO(channel, it->second);

				const AUTO(bytes_to_acknowledge, msg.segment.size());
				channel->on_sync_received(Poseidon::StreamBuffer(msg.segment));

				Protocol::PS_Acknowledge ack;
				ack.channel_uuid         = channel_uuid;
				ack.bytes_to_acknowledge = bytes_to_acknowledge;
				send(ack);
			}
			ON_MESSAGE(Protocol::SP_Closed, msg){
				const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
				LOG_MEDUSA2_DEBUG("Channel closed: channel_uuid = ", channel_uuid, ", err_code = ", msg.err_code, ", err_msg = ", msg.err_msg);

				const AUTO(it, g_channels.find(channel_uuid));
				if(it == g_channels.end()){
					LOG_MEDUSA2_WARNING("Dangling channel: channel_uuid = ", channel_uuid);
					break;
				}
				const AUTO(channel, it->second);
				g_channels.erase(it);

				channel->on_sync_closed(msg.err_code, STD_MOVE(msg.err_msg));
			}
			ON_MESSAGE(Protocol::SP_Pong, msg){
				LOG_MEDUSA2_INFO("Received PONG from ", get_remote_info(), ": ", msg);
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

	public:
		bool send(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE {
			PROFILE_ME;

			AUTO(ciphertext, Common::encrypt(STD_MOVE(payload)));
			return Poseidon::Cbpp::Client::send(message_id, STD_MOVE(ciphertext));
		}

		bool send(const Poseidon::Cbpp::MessageBase &msg){
			PROFILE_ME;

			return send(boost::numeric_cast<boost::uint16_t>(msg.get_id()), Poseidon::StreamBuffer(msg));
		}
	};

	boost::weak_ptr<SecondaryClient> g_weak_client;

	Protocol::PS_Ping create_dummy_ping_message(){
		PROFILE_ME;

		unsigned char data[256];
		std::size_t size = Poseidon::random_uint32() % 256;
		std::generate(data, data + size, Poseidon::RandomBitGenerator_uint32());

		Protocol::PS_Ping msg;
		msg.opaque.put(data, size);
		return msg;
	}

	void reconnect_timer_proc(){
		PROFILE_ME;

		AUTO(client, g_weak_client.lock());
		if(client){
			return;
		}

		for(AUTO(it, g_channels.begin()); it != g_channels.end(); ++it){
			const AUTO(channel, it->second);
			try {
				channel->on_sync_closed(Protocol::ERR_SECONDARY_SERVER_CONNECTION_LOST, "Lost connection to secondary server");
			} catch(std::exception &e){
				LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
			}
		}
		g_channels.clear();

		const AUTO(host, get_config<std::string>("secondary_connector_host", "127.0.0.1"));
		const AUTO(port, get_config<boost::uint16_t>("secondary_connector_port", 3805));
		const AUTO(use_ssl, get_config<bool>("secondary_connector_use_ssl"));
		LOG_MEDUSA2_INFO("Connecting to secondary server: host:port = ", host, ":", port, ", use_ssl = ", use_ssl);

		const AUTO(promised_sock_addr, Poseidon::DnsDaemon::enqueue_for_looking_up(host, port));
		Poseidon::yield(promised_sock_addr);
		const AUTO_REF(sock_addr, promised_sock_addr->get());

		client = g_weak_client.lock();
		if(client){
			return;
		}
		client = boost::make_shared<SecondaryClient>(sock_addr, use_ssl);
		client->send(create_dummy_ping_message());
		client->set_no_delay();
		Poseidon::EpollDaemon::add_socket(client, true);
		g_weak_client = client;
	}
}

MODULE_RAII_PRIORITY(handles, INIT_PRIORITY_LOW){
	const AUTO(reconnect_delay, get_config<boost::uint64_t>("secondary_connector_reconnect_delay", 5000));
	const AUTO(timer, Poseidon::TimerDaemon::register_timer(0, reconnect_delay, boost::bind(reconnect_timer_proc)));
	handles.push(timer);
}

boost::shared_ptr<SecondaryChannel> SecondaryConnector::get_attached_channel(const Poseidon::Uuid &channel_uuid){
	PROFILE_ME;

	const AUTO(it, g_channels.find(channel_uuid));
	if(it == g_channels.end()){
		return VAL_INIT;
	}
	return it->second;
}
void SecondaryConnector::attach_channel(const boost::shared_ptr<SecondaryChannel> &channel){
	PROFILE_ME;

	const AUTO(client, g_weak_client.lock());
	DEBUG_THROW_UNLESS(client, Poseidon::Exception, Poseidon::sslit("Connection to secondary server is not ready"));
	const AUTO(pair, g_channels.emplace(channel->get_channel_uuid(), channel));
	DEBUG_THROW_UNLESS(pair.second, Poseidon::Exception, Poseidon::sslit("Duplicate channel UUID"));

	Protocol::PS_Connect msg;
	msg.channel_uuid = channel->get_channel_uuid();
	msg.host         = channel->get_host();
	msg.port         = channel->get_port();
	msg.use_ssl      = channel->is_using_ssl();
	msg.no_delay     = channel->is_no_delay();
	client->send(msg);
}

const Poseidon::IpPort &SecondaryConnector::get_remote_info(){
	PROFILE_ME;

	const AUTO(client, g_weak_client.lock());
	if(!client){
		return Poseidon::unknown_ip_port();
	}
	return client->get_remote_info();
}
bool SecondaryConnector::send(const Poseidon::Cbpp::MessageBase &msg){
	PROFILE_ME;

	const AUTO(client, g_weak_client.lock());
	if(!client){
		return false;
	}
	return client->send(msg);
}
bool SecondaryConnector::shutdown(long err_code, const char *what) NOEXCEPT {
	PROFILE_ME;

	const AUTO(client, g_weak_client.lock());
	if(!client){
		return false;
	}
	return client->shutdown(err_code, what);
}

}
}
