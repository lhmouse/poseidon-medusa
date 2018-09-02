// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#include "precompiled.hpp"
#include "primary_session.hpp"
#include "mmain.hpp"
#include "common/encryption.hpp"
#include "protocol/messages.hpp"
#include "protocol/error_codes.hpp"
#include <poseidon/cbpp/exception.hpp>
#include <poseidon/tcp_client_base.hpp>
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/sock_addr.hpp>
#include <poseidon/singletons/dns_daemon.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>

namespace Medusa2 {
namespace Secondary {

class Primary_session::Fetch_client : public Poseidon::Tcp_client_base {
private:
	mutable Poseidon::Mutex m_mutex;
	bool m_connected_or_closed;
	bool m_established_after_all;
	Poseidon::Stream_buffer m_recv_queue;
	boost::uint64_t m_queue_size;
	int m_syserrno;

public:
	Fetch_client(const Poseidon::Sock_addr &addr, bool use_ssl)
		: Poseidon::Tcp_client_base(addr, use_ssl, true)
		, m_connected_or_closed(false), m_established_after_all(false), m_recv_queue(), m_queue_size(0), m_syserrno(-1)
	{
		//
	}

protected:
	void on_connect() OVERRIDE {
		MEDUSA2_LOG_TRACE("Connection established: remote = ", get_remote_info());

		const Poseidon::Mutex::Unique_lock lock(m_mutex);
		m_connected_or_closed = true;
		m_established_after_all = true;
	}
	void on_read_hup() OVERRIDE {
		MEDUSA2_LOG_TRACE("Connection read hang up: remote = ", get_remote_info());

		shutdown_write();
	}
	void on_close(int err_code) OVERRIDE {
		MEDUSA2_LOG_TRACE("Connection closed: remote = ", get_remote_info(), ", err_code = ", err_code);

		const Poseidon::Mutex::Unique_lock lock(m_mutex);
		m_connected_or_closed = true;
		m_syserrno = err_code;
	}
	void on_receive(Poseidon::Stream_buffer data) OVERRIDE {
		const AUTO(max_queue_size, get_config<boost::uint64_t>("fetch_max_queue_size", 65536));
		const AUTO(bytes_received, static_cast<boost::uint64_t>(data.size()));
		MEDUSA2_LOG_TRACE("Receive: remote = ", get_remote_info(), ", max_queue_size = ", max_queue_size, ", bytes_received = ", bytes_received);

		const Poseidon::Mutex::Unique_lock lock(m_mutex);
		m_recv_queue.splice(data);
		m_queue_size = Poseidon::checked_add(m_queue_size, bytes_received);
		Poseidon::Tcp_client_base::set_throttled(m_queue_size >= max_queue_size);
	}

public:
	bool is_connected_or_closed() const {
		const Poseidon::Mutex::Unique_lock lock(m_mutex);
		return m_connected_or_closed;
	}
	bool was_established_after_all() const {
		const Poseidon::Mutex::Unique_lock lock(m_mutex);
		return m_established_after_all;
	}
	void cut_recv_queue(Poseidon::Stream_buffer *segment, bool *no_more_data, std::size_t fragmentation_size){
		const Poseidon::Mutex::Unique_lock lock(m_mutex);
		if(segment){
			*segment = m_recv_queue.cut_off(fragmentation_size);
		}
		if(no_more_data){
			*no_more_data = m_recv_queue.empty() && (m_syserrno >= 0);
		}
	}
	int get_syserrno() const {
		const Poseidon::Mutex::Unique_lock lock(m_mutex);
		return (m_syserrno < 0) ? 0 : m_syserrno;
	}

	void acknowledge(boost::uint64_t bytes_to_acknowledge){
		const AUTO(max_queue_size, get_config<boost::uint64_t>("fetch_max_queue_size", 65536));
		MEDUSA2_LOG_TRACE("Acknowledge: remote = ", get_remote_info(), ", max_queue_size = ", max_queue_size, ", bytes_to_acknowledge = ", bytes_to_acknowledge);

		const Poseidon::Mutex::Unique_lock lock(m_mutex);
		m_queue_size = Poseidon::checked_sub(m_queue_size, bytes_to_acknowledge);
		Poseidon::Tcp_client_base::set_throttled(m_queue_size >= max_queue_size);
	}
};

class Primary_session::Channel : NONCOPYABLE {
private:
	const Poseidon::Uuid m_channel_uuid;
	const boost::weak_ptr<Primary_session> m_weak_session;

	const std::string m_host;
	const boost::uint16_t m_port;
	const bool m_use_ssl;
	const bool m_no_delay;

	boost::shared_ptr<const Poseidon::Promise_container<Poseidon::Sock_addr> > m_promised_sock_addr;
	bool m_establishment_notified;
	Poseidon::Stream_buffer m_send_queue;
	bool m_shutdown_read;
	bool m_shutdown_write;
	bool m_no_linger;
	boost::shared_ptr<Fetch_client> m_fetch_client;

public:
	Channel(const Poseidon::Uuid &channel_uuid, const boost::shared_ptr<Primary_session> &session, std::string host, boost::uint16_t port, bool use_ssl, bool no_delay)
		: m_channel_uuid(channel_uuid), m_weak_session(session), m_host(STD_MOVE(host)), m_port(port), m_use_ssl(use_ssl), m_no_delay(no_delay)
		, m_promised_sock_addr(), m_establishment_notified(false), m_send_queue(), m_shutdown_read(false), m_shutdown_write(false), m_no_linger(false), m_fetch_client()
	{
		MEDUSA2_LOG_TRACE("Channel constructor: channel_uuid = ", get_channel_uuid());
	}
	~Channel(){
		MEDUSA2_LOG_TRACE("Channel destructor: channel_uuid = ", get_channel_uuid());

		const AUTO(fetch_client, m_fetch_client);
		if(fetch_client){
			MEDUSA2_LOG_DEBUG("Fetch_client was not shut down cleanly: channel_uuid = ", get_channel_uuid());
			fetch_client->force_shutdown();
		}
	}

public:
	const Poseidon::Uuid & get_channel_uuid() const {
		return m_channel_uuid;
	}

	void send(Poseidon::Stream_buffer segment){
		POSEIDON_PROFILE_ME;

		m_send_queue.splice(segment);
	}
	void acknowledge(boost::uint64_t bytes_to_acknowledge){
		POSEIDON_PROFILE_ME;

		const AUTO(fetch_client, m_fetch_client);
		POSEIDON_THROW_ASSERT(fetch_client);

		fetch_client->acknowledge(bytes_to_acknowledge);
	}
	void shutdown(bool no_linger){
		POSEIDON_PROFILE_ME;

		if(no_linger){
			m_shutdown_read = true;
		}
		m_shutdown_write = true;
		m_no_linger = no_linger;
	}

	bool update(){
		POSEIDON_PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		POSEIDON_THROW_ASSERT(session);

		AUTO(fetch_client, m_fetch_client);
		if(!fetch_client){
			if(m_shutdown_read){
				MEDUSA2_LOG_DEBUG("Connection was cancelled: host:port = ", m_host, ":", m_port);
				POSEIDON_THROW(Poseidon::Cbpp::Exception, Protocol::error_connection_cancelled, Poseidon::Rcnts::view("Connection was cancelled"));
			}

			// Perform DNS lookup.
			if(!m_promised_sock_addr){
				MEDUSA2_LOG_DEBUG("@@ DNS lookup: host:port = ", m_host, ":", m_port);
				m_promised_sock_addr = Poseidon::Dns_daemon::enqueue_for_looking_up(m_host, m_port);
			}
			if(!m_promised_sock_addr->is_satisfied()){
				MEDUSA2_LOG_TRACE("Waiting for DNS lookup: host:port = ", m_host, ":", m_port);
				return false;
			}
			Poseidon::Sock_addr sock_addr;
			try {
				sock_addr = m_promised_sock_addr->get();
			} catch(std::exception &e){
				MEDUSA2_LOG_DEBUG("DNS failure: what = ", e.what());
				POSEIDON_THROW(Poseidon::Cbpp::Exception, Protocol::error_dns_failure, Poseidon::Rcnts(e.what()));
			}
			if(sock_addr.is_private()){
				MEDUSA2_LOG_DEBUG("Connections to private addresses are disallowed: host:port = ", m_host, ":", m_port, ", ip:port = ", Poseidon::Ip_port(sock_addr));
				POSEIDON_THROW(Poseidon::Cbpp::Exception, Protocol::error_private_address_disallowed, Poseidon::Rcnts::view("Connections to private addresses are disallowed"));
			}
			MEDUSA2_LOG_DEBUG("@@ Creating Fetch_client: ip:port = ", Poseidon::Ip_port(sock_addr));

			// Create the TCP client.
			POSEIDON_THROW_ASSERT(!m_establishment_notified);
			fetch_client = boost::make_shared<Fetch_client>(sock_addr, m_use_ssl);
			if(m_no_delay){
				fetch_client->set_no_delay();
			}
			Poseidon::Epoll_daemon::add_socket(fetch_client, false);
			m_fetch_client = fetch_client;
		}

		if(!m_no_linger){
			// Send some data, if any.
			if(!m_send_queue.empty()){
				Poseidon::Stream_buffer send_queue;
				send_queue.swap(m_send_queue);
				fetch_client->send(STD_MOVE(send_queue));
			}
			// Shut down the write side if requested, after all data have been sent.
			if(m_shutdown_write){
				fetch_client->shutdown_write();
			}
			if(!fetch_client->is_connected_or_closed()){
				MEDUSA2_LOG_TRACE("Waiting for establishment: host:port = ", m_host, ":", m_port);
				return false;
			}

			// If a TCP connection was established, notify the primary server.
			if(!m_establishment_notified){
				if(fetch_client->was_established_after_all()){
					Protocol::SP_Established msg;
					msg.channel_uuid = get_channel_uuid();
					session->send(msg);
				}
				m_establishment_notified = true;
			}

			bool no_more_data;
			{
				const AUTO(fragmentation_size, get_config<std::size_t>("fetch_fragmentation_size", 8192));
				// Read some data, if any.
				Protocol::SP_Received msg;
				msg.channel_uuid = get_channel_uuid();
				do {
					fetch_client->cut_recv_queue(&msg.segment, &no_more_data, fragmentation_size);
				} while(!msg.segment.empty() && session->send(msg));
			}
			if(!no_more_data){
				return false;
			}
		}

		// Clear the client.
		const int syserrno = fetch_client->get_syserrno();
		m_shutdown_read = true;
		m_shutdown_write = true;
		fetch_client->force_shutdown();
		m_fetch_client.reset();

		switch(syserrno){
		case ECONNREFUSED:
			POSEIDON_THROW(Poseidon::Cbpp::Exception, Protocol::error_connection_refused, Poseidon::get_error_desc(syserrno));
		case ETIMEDOUT:
			POSEIDON_THROW(Poseidon::Cbpp::Exception, Protocol::error_connection_timed_out, Poseidon::get_error_desc(syserrno));
		case ECONNRESET:
			POSEIDON_THROW(Poseidon::Cbpp::Exception, Protocol::error_connection_reset_by_peer, Poseidon::get_error_desc(syserrno));
		default:
			POSEIDON_THROW(Poseidon::Cbpp::Exception, Protocol::error_connection_lost_unspecified, Poseidon::get_error_desc(syserrno));
		case 0:
			return true;
		}
	}
};

void Primary_session::sync_timer_proc(const boost::weak_ptr<Primary_session> &weak_session){
	POSEIDON_PROFILE_ME;

	const AUTO(session, weak_session.lock());
	if(!session){
		return;
	}
	session->on_sync_timer();
}

Primary_session::Primary_session(Poseidon::Move<Poseidon::Unique_file> socket)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
	, m_session_uuid(Poseidon::Uuid::random())
	, m_authenticated(false)
{
	MEDUSA2_LOG_INFO("Primary_session constructor: remote = ", get_remote_info());
}
Primary_session::~Primary_session(){
	MEDUSA2_LOG_INFO("Primary_session destructor: remote = ", get_remote_info());
}

void Primary_session::on_sync_timer()
try {
	POSEIDON_PROFILE_ME;
	MEDUSA2_LOG_TRACE("Timer: remote = ", get_remote_info());

	Protocol::SP_Closed closed_msg;
	bool erase_it;
	for(AUTO(it, m_channels.begin()); it != m_channels.end(); erase_it ? (it = m_channels.erase(it)) : ++it){
		const AUTO(channel_uuid, it->first);
		const AUTO(channel, it->second);
		MEDUSA2_LOG_TRACE("Updating channel: channel_uuid = ", channel_uuid);
		closed_msg.channel_uuid = channel_uuid;
		try {
			erase_it = channel->update();
			closed_msg.err_code = 0;
			closed_msg.err_msg  = VAL_INIT;
		} catch(Poseidon::Cbpp::Exception &e){
			MEDUSA2_LOG_DEBUG("Cbpp::Exception thrown: status_code = ", e.get_status_code(), ", what = ", e.what());
			erase_it = true;
			closed_msg.err_code = e.get_status_code();
			closed_msg.err_msg  = e.what();
		} catch(std::exception &e){
			MEDUSA2_LOG_WARNING("std::exception thrown: what = ", e.what());
			erase_it = true;
			closed_msg.err_code = Protocol::error_internal_error;
			closed_msg.err_msg  = e.what();
		}
		if(erase_it){
			send(closed_msg);
		}
	}

	if(m_channels.empty()){
		MEDUSA2_LOG_DEBUG("Destroying timer: remote = ", get_remote_info());
		m_timer.reset();
	}
} catch(Poseidon::Cbpp::Exception &e){
	MEDUSA2_LOG_ERROR("Cbpp::Exception thrown: remote = ", get_remote_info(), ", status_code = ", e.get_status_code(), ", what = ", e.what());
	shutdown(e.get_status_code(), e.what());
} catch(std::exception &e){
	MEDUSA2_LOG_ERROR("std::exception thrown: remote = ", get_remote_info(), ", what = ", e.what());
	shutdown(Protocol::error_internal_error, e.what());
}
void Primary_session::on_sync_data_message(boost::uint16_t message_id, Poseidon::Stream_buffer payload){
	POSEIDON_PROFILE_ME;
	MEDUSA2_LOG_TRACE("Received data message: remote = ", get_remote_info(), ", message_id = ", message_id);

	Poseidon::Stream_buffer plaintext;
	try {
		plaintext = Common::decrypt(STD_MOVE(payload));
	} catch(std::exception &e){
		MEDUSA2_LOG_ERROR("Failed to decrypt message: remote = ", get_remote_info(), ", what = ", e.what());
		force_shutdown();
		return;
	}
	MEDUSA2_LOG_TRACE("> message_id = ", message_id, ", plaintext.size() = ", plaintext.size());
	m_authenticated = true;

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
	ON_MESSAGE(Protocol::PS_Connect, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		MEDUSA2_LOG_DEBUG("Create channel and connect: channel_uuid = ", channel_uuid, ", host:port = ", msg.host, ":", msg.port, ", use_ssl = ", msg.use_ssl);

		if(!m_timer){
			MEDUSA2_LOG_DEBUG("Creating timer: remote = ", get_remote_info());
			m_timer = Poseidon::Timer_daemon::register_timer(0, 200, boost::bind(&sync_timer_proc, virtual_weak_from_this<Primary_session>()));
		}
		MEDUSA2_LOG_DEBUG("Creating channel: channel_uuid = ", channel_uuid);
		const AUTO(channel, boost::make_shared<Channel>(channel_uuid, virtual_shared_from_this<Primary_session>(), STD_MOVE(msg.host), msg.port, msg.use_ssl, msg.no_delay));
		const AUTO(it, m_channels.emplace(channel_uuid, channel));

		Protocol::SP_Opened open_msg;
		open_msg.channel_uuid = channel_uuid;
		open_msg.opaque       = STD_MOVE(msg.opaque);
		send(open_msg);

		(void)it;
	}
	ON_MESSAGE(Protocol::PS_Send, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		MEDUSA2_LOG_DEBUG("Send to channel: channel_uuid = ", channel_uuid, ", segment.size() = ", msg.segment.size());

		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			MEDUSA2_LOG_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		const AUTO(channel, it->second);

		channel->send(STD_MOVE(msg.segment));
	}
	ON_MESSAGE(Protocol::PS_Acknowledge, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		MEDUSA2_LOG_DEBUG("Acknowledge from channel: channel_uuid = ", channel_uuid, ", bytes_to_acknowledge = ", msg.bytes_to_acknowledge);

		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			MEDUSA2_LOG_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		const AUTO(channel, it->second);

		channel->acknowledge(msg.bytes_to_acknowledge);
	}
	ON_MESSAGE(Protocol::PS_Shutdown, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		MEDUSA2_LOG_DEBUG("Shutdown channel: channel_uuid = ", channel_uuid, ", no_linger = ", msg.no_linger);

		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			MEDUSA2_LOG_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		const AUTO(channel, it->second);

		channel->shutdown(msg.no_linger);
	}
	ON_MESSAGE(Protocol::PS_Ping, msg){
		MEDUSA2_LOG_DEBUG("Received PING from ", get_remote_info(), ": ", msg);

		Protocol::SP_Pong resp;
		resp.opaque = STD_MOVE(msg.opaque);
		send(resp);
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
void Primary_session::on_sync_control_message(Poseidon::Cbpp::Status_code status_code, Poseidon::Stream_buffer param){
	POSEIDON_PROFILE_ME;

	if(!m_authenticated){
		MEDUSA2_LOG_ERROR("Primary_session has not authenticated: remote = ", get_remote_info());
		force_shutdown();
		return;
	}

	return Poseidon::Cbpp::Session::on_sync_control_message(status_code, STD_MOVE(param));
}

bool Primary_session::send(boost::uint16_t message_id, Poseidon::Stream_buffer payload){
	POSEIDON_PROFILE_ME;

	AUTO(ciphertext, Common::encrypt(STD_MOVE(payload)));
	return Poseidon::Cbpp::Session::send(message_id, STD_MOVE(ciphertext));
}

bool Primary_session::send(const Poseidon::Cbpp::Message_base &msg){
	POSEIDON_PROFILE_ME;

	return send(boost::numeric_cast<boost::uint16_t>(msg.get_id()), Poseidon::Stream_buffer(msg));
}

}
}
