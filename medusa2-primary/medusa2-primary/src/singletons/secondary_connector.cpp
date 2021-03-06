// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#include "precompiled.hpp"
#include "secondary_connector.hpp"
#include "../mmain.hpp"
#include "common/encryption.hpp"
#include "protocol/error_codes.hpp"
#include "protocol/messages.hpp"
#include <poseidon/cbpp/client.hpp>
#include <poseidon/cbpp/exception.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/sock_addr.hpp>
#include <poseidon/singletons/dns_daemon.hpp>

namespace Medusa2 {
namespace Primary {

namespace {
	boost::container::flat_map<Poseidon::Uuid, boost::shared_ptr<Secondary_channel> > g_channels;

	class Secondary_client : public Poseidon::Cbpp::Client {
	public:
		Secondary_client(const Poseidon::Sock_addr &sock_addr, bool use_ssl)
			: Poseidon::Cbpp::Client(sock_addr, use_ssl)
		{
			MEDUSA2_LOG_INFO("Secondary_client constructor: remote = ", Poseidon::Ip_port(sock_addr));
		}
		~Secondary_client(){
			MEDUSA2_LOG_INFO("Secondary_client destructor: remote = ", get_remote_info());
		}

	protected:
		void on_sync_data_message(boost::uint16_t message_id, Poseidon::Stream_buffer payload) OVERRIDE {
			POSEIDON_PROFILE_ME;
			MEDUSA2_LOG_TRACE("Received data message: remote = ", get_remote_info(), ", message_id = ", message_id);

			AUTO(plaintext, Common::decrypt(STD_MOVE(payload)));
			MEDUSA2_LOG_TRACE("> message_id = ", message_id, ", plaintext.size() = ", plaintext.size());
			switch(message_id){
				{{
#define ON_MESSAGE(Msg_, msg_)	\
				}	\
				break; }	\
			case Msg_::id: {	\
				POSEIDON_PROFILE_ME;	\
				Msg_ msg_;	\
				msg_.deserialize(plaintext);	\
				{
//=============================================================================
			ON_MESSAGE(Protocol::SP_Opened, msg){
				const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
				MEDUSA2_LOG_DEBUG("Channel opened: channel_uuid = ", channel_uuid);

				const AUTO(it, g_channels.find(channel_uuid));
				if(it == g_channels.end()){
					MEDUSA2_LOG_WARNING("Dangling channel: channel_uuid = ", channel_uuid);
					break;
				}
				const AUTO(channel, it->second);

				channel->on_sync_opened();
			}
			ON_MESSAGE(Protocol::SP_Established, msg){
				const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
				MEDUSA2_LOG_DEBUG("Channel established: channel_uuid = ", channel_uuid);

				const AUTO(it, g_channels.find(channel_uuid));
				if(it == g_channels.end()){
					MEDUSA2_LOG_WARNING("Dangling channel: channel_uuid = ", channel_uuid);
					break;
				}
				const AUTO(channel, it->second);

				channel->on_sync_established();
			}
			ON_MESSAGE(Protocol::SP_Received, msg){
				const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
				MEDUSA2_LOG_DEBUG("Data received from channel: channel_uuid = ", channel_uuid, ", segment.size() = ", msg.segment.size());

				const AUTO(it, g_channels.find(channel_uuid));
				if(it == g_channels.end()){
					MEDUSA2_LOG_WARNING("Dangling channel: channel_uuid = ", channel_uuid);
					break;
				}
				const AUTO(channel, it->second);

				const AUTO(bytes_to_acknowledge, msg.segment.size());
				channel->on_sync_received(Poseidon::Stream_buffer(msg.segment));

				Protocol::PS_Acknowledge ack;
				ack.channel_uuid         = channel_uuid;
				ack.bytes_to_acknowledge = bytes_to_acknowledge;
				send(ack);
			}
			ON_MESSAGE(Protocol::SP_Closed, msg){
				const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
				MEDUSA2_LOG_DEBUG("Channel closed: channel_uuid = ", channel_uuid, ", err_code = ", msg.err_code, ", err_msg = ", msg.err_msg);

				const AUTO(it, g_channels.find(channel_uuid));
				if(it == g_channels.end()){
					MEDUSA2_LOG_WARNING("Dangling channel: channel_uuid = ", channel_uuid);
					break;
				}
				const AUTO(channel, it->second);
				g_channels.erase(it);

				channel->on_sync_closed(msg.err_code, STD_MOVE(msg.err_msg));
			}
			ON_MESSAGE(Protocol::SP_Pong, msg){
				MEDUSA2_LOG_DEBUG("Received PONG from ", get_remote_info(), ": ", msg);
				boost::uint64_t timestamp_be;
				if(msg.opaque.peek(&timestamp_be, 8) < 8){
					MEDUSA2_LOG_WARNING("Invalid SP_Pong: size = ", msg.opaque.size());
					break;
				}
				const AUTO(log_pong, get_config<bool>("log_secondary_pong", false));
				if(log_pong) {
					const AUTO(now, Poseidon::get_fast_mono_clock());
					const AUTO(delay, Poseidon::saturated_sub(now, Poseidon::load_be(timestamp_be)));
					MEDUSA2_LOG_WARNING("Received PONG from secondary server: delay = ", delay, " ms");
				}
			}
//=============================================================================
#undef ON_MESSAGE
				}
				break; }
			default:
				MEDUSA2_LOG_ERROR("Unknown message: remote = ", get_remote_info(), ", message_id = ", message_id);
				POSEIDON_THROW(Poseidon::Cbpp::Exception, Protocol::error_not_found, Poseidon::Rcnts::view("Unknown message"));
			}
		}

	public:
		bool send(boost::uint16_t message_id, Poseidon::Stream_buffer payload) OVERRIDE {
			POSEIDON_PROFILE_ME;

			AUTO(ciphertext, Common::encrypt(STD_MOVE(payload)));
			return Poseidon::Cbpp::Client::send(message_id, STD_MOVE(ciphertext));
		}

		bool send(const Poseidon::Cbpp::Message_base &msg){
			POSEIDON_PROFILE_ME;

			return send(boost::numeric_cast<boost::uint16_t>(msg.get_id()), Poseidon::Stream_buffer(msg));
		}
	};

	boost::weak_ptr<Secondary_client> g_weak_client;

	Protocol::PS_Ping create_dummy_ping_message(){
		POSEIDON_PROFILE_ME;

		Protocol::PS_Ping msg;
		boost::uint64_t timestamp_be;
		const AUTO(now, Poseidon::get_fast_mono_clock());
		Poseidon::store_be(timestamp_be, now);
		msg.opaque.put(&timestamp_be, 8);
		const AUTO(rand_size, Poseidon::random_uint32() % 256);
		for(boost::uint32_t i = 0; i < rand_size; ++i){
			msg.opaque.put(static_cast<unsigned char>(Poseidon::random_uint32() >> 24));
		}
		return msg;
	}

	void reconnect_timer_proc(){
		POSEIDON_PROFILE_ME;

		AUTO(client, g_weak_client.lock());
		if(!client){
			for(AUTO(it, g_channels.begin()); it != g_channels.end(); ++it){
				const AUTO(channel, it->second);
				try {
					channel->on_sync_closed(Protocol::error_secondary_server_connection_lost, "Lost connection to secondary server");
				} catch(std::exception &e){
					MEDUSA2_LOG_ERROR("std::exception thrown: what = ", e.what());
				}
			}
			g_channels.clear();

			const AUTO(host, get_config<std::string>("secondary_connector_host", "127.0.0.1"));
			const AUTO(port, get_config<boost::uint16_t>("secondary_connector_port", 3805));
			const AUTO(use_ssl, get_config<bool>("secondary_connector_use_ssl"));
			MEDUSA2_LOG_INFO("Connecting to secondary server: host:port = ", host, ":", port, ", use_ssl = ", use_ssl);

			const AUTO(promised_sock_addr, Poseidon::Dns_daemon::enqueue_for_looking_up(host, port));
			Poseidon::yield(promised_sock_addr);
			const AUTO_REF(sock_addr, promised_sock_addr->get());

			client = g_weak_client.lock();
			if(!client){
				client = boost::make_shared<Secondary_client>(sock_addr, use_ssl);
				client->set_no_delay();
				Poseidon::Epoll_daemon::add_socket(client, true);
				g_weak_client = client;
			}
		}

		client->send(create_dummy_ping_message());
	}
}

POSEIDON_MODULE_RAII_PRIORITY(handles, Poseidon::module_init_priority_low){
	const AUTO(reconnect_delay, get_config<boost::uint64_t>("secondary_connector_reconnect_delay", 5000));
	const AUTO(timer, Poseidon::Timer_daemon::register_timer(0, reconnect_delay, boost::bind(reconnect_timer_proc)));
	handles.push(timer);
}

boost::shared_ptr<Secondary_channel> Secondary_connector::get_attached_channel(const Poseidon::Uuid &channel_uuid){
	POSEIDON_PROFILE_ME;

	const AUTO(it, g_channels.find(channel_uuid));
	if(it == g_channels.end()){
		return VAL_INIT;
	}
	return it->second;
}
void Secondary_connector::attach_channel(const boost::shared_ptr<Secondary_channel> &channel){
	POSEIDON_PROFILE_ME;

	const AUTO(client, g_weak_client.lock());
	POSEIDON_THROW_UNLESS(client, Poseidon::Exception, Poseidon::Rcnts::view("Connection to secondary server is not ready"));
	const AUTO(pair, g_channels.emplace(channel->get_channel_uuid(), channel));
	POSEIDON_THROW_UNLESS(pair.second, Poseidon::Exception, Poseidon::Rcnts::view("Duplicate channel UUID"));

	Protocol::PS_Connect msg;
	msg.channel_uuid = channel->get_channel_uuid();
	msg.host         = channel->get_host();
	msg.port         = channel->get_port();
	msg.use_ssl      = channel->is_using_ssl();
	msg.no_delay     = channel->is_no_delay();
	client->send(msg);
}

const Poseidon::Ip_port & Secondary_connector::get_remote_info(){
	POSEIDON_PROFILE_ME;

	const AUTO(client, g_weak_client.lock());
	if(!client){
		return Poseidon::unknown_ip_port();
	}
	return client->get_remote_info();
}
bool Secondary_connector::send(const Poseidon::Cbpp::Message_base &msg){
	POSEIDON_PROFILE_ME;

	const AUTO(client, g_weak_client.lock());
	if(!client){
		return false;
	}
	return client->send(msg);
}
bool Secondary_connector::shutdown(long err_code, const char *what) NOEXCEPT {
	POSEIDON_PROFILE_ME;

	const AUTO(client, g_weak_client.lock());
	if(!client){
		return false;
	}
	return client->shutdown(err_code, what);
}

}
}
