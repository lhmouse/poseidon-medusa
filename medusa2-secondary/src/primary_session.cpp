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

class PrimarySession::FetchClient : public Poseidon::TcpClientBase {
private:
	mutable Poseidon::Mutex m_mutex;
	bool m_connected_or_closed;
	bool m_established_after_all;
	Poseidon::StreamBuffer m_recv_queue;
	boost::uint64_t m_queue_size;
	int m_syserrno;

public:
	FetchClient(const Poseidon::SockAddr &addr, bool use_ssl)
		: Poseidon::TcpClientBase(addr, use_ssl, true)
		, m_connected_or_closed(false), m_established_after_all(false), m_recv_queue(), m_queue_size(0), m_syserrno(-1)
	{ }

protected:
	void on_connect() OVERRIDE {
		LOG_MEDUSA2_TRACE("Connection established: remote = ", get_remote_info());

		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		m_connected_or_closed = true;
		m_established_after_all = true;
	}
	void on_read_hup() OVERRIDE {
		LOG_MEDUSA2_TRACE("Connection read hang up: remote = ", get_remote_info());

		shutdown_write();
	}
	void on_close(int err_code) OVERRIDE {
		LOG_MEDUSA2_TRACE("Connection closed: remote = ", get_remote_info(), ", err_code = ", err_code);

		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		m_connected_or_closed = true;
		m_syserrno = err_code;
	}
	void on_receive(Poseidon::StreamBuffer data) OVERRIDE {
		const AUTO(max_queue_size, get_config<boost::uint64_t>("fetch_max_queue_size", 65536));
		const AUTO(bytes_received, static_cast<boost::uint64_t>(data.size()));
		LOG_MEDUSA2_TRACE("Receive: remote = ", get_remote_info(), ", max_queue_size = ", max_queue_size, ", bytes_received = ", bytes_received);

		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		m_recv_queue.splice(data);
		m_queue_size = Poseidon::checked_add(m_queue_size, bytes_received);
		Poseidon::TcpClientBase::set_throttled(m_queue_size >= max_queue_size);
	}

public:
	bool is_connected_or_closed() const {
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		return m_connected_or_closed;
	}
	bool was_established_after_all() const {
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		return m_established_after_all;
	}
	void cut_recv_queue(Poseidon::StreamBuffer *segment, bool *no_more_data, std::size_t fragmentation_size){
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		if(segment){
			*segment = m_recv_queue.cut_off(fragmentation_size);
		}
		if(no_more_data){
			*no_more_data = m_recv_queue.empty() && (m_syserrno >= 0);
		}
	}
	int get_syserrno() const {
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		return (m_syserrno < 0) ? 0 : m_syserrno;
	}

	void acknowledge(boost::uint64_t bytes_to_acknowledge){
		const AUTO(max_queue_size, get_config<boost::uint64_t>("fetch_max_queue_size", 65536));
		LOG_MEDUSA2_TRACE("Acknowledge: remote = ", get_remote_info(), ", max_queue_size = ", max_queue_size, ", bytes_to_acknowledge = ", bytes_to_acknowledge);

		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		m_queue_size = Poseidon::checked_sub(m_queue_size, bytes_to_acknowledge);
		Poseidon::TcpClientBase::set_throttled(m_queue_size >= max_queue_size);
	}
};

class PrimarySession::Channel : NONCOPYABLE {
private:
	const Poseidon::Uuid m_channel_uuid;
	const boost::weak_ptr<PrimarySession> m_weak_session;

	const std::string m_host;
	const boost::uint16_t m_port;
	const bool m_use_ssl;
	const bool m_no_delay;

	boost::shared_ptr<const Poseidon::PromiseContainer<Poseidon::SockAddr> > m_promised_sock_addr;
	bool m_establishment_notified;
	Poseidon::StreamBuffer m_send_queue;
	bool m_shutdown_read;
	bool m_shutdown_write;
	bool m_no_linger;
	boost::shared_ptr<FetchClient> m_fetch_client;

public:
	Channel(const Poseidon::Uuid &channel_uuid, const boost::shared_ptr<PrimarySession> &session, std::string host, boost::uint16_t port, bool use_ssl, bool no_delay)
		: m_channel_uuid(channel_uuid), m_weak_session(session), m_host(STD_MOVE(host)), m_port(port), m_use_ssl(use_ssl), m_no_delay(no_delay)
		, m_promised_sock_addr(), m_establishment_notified(false), m_send_queue(), m_shutdown_read(false), m_shutdown_write(false), m_no_linger(false), m_fetch_client()
	{
		LOG_MEDUSA2_TRACE("Channel constructor: channel_uuid = ", get_channel_uuid());
	}
	~Channel(){
		LOG_MEDUSA2_TRACE("Channel destructor: channel_uuid = ", get_channel_uuid());

		const AUTO(fetch_client, m_fetch_client);
		if(fetch_client){
			LOG_MEDUSA2_WARNING("FetchClient was not shut down cleanly: channel_uuid = ", get_channel_uuid());
			fetch_client->force_shutdown();
		}
	}

public:
	const Poseidon::Uuid &get_channel_uuid() const {
		return m_channel_uuid;
	}

	void send(Poseidon::StreamBuffer segment){
		PROFILE_ME;

		m_send_queue.splice(segment);
	}
	void acknowledge(boost::uint64_t bytes_to_acknowledge){
		PROFILE_ME;

		const AUTO(fetch_client, m_fetch_client);
		DEBUG_THROW_ASSERT(fetch_client);

		fetch_client->acknowledge(bytes_to_acknowledge);
	}
	void shutdown(bool no_linger){
		PROFILE_ME;

		if(no_linger){
			m_shutdown_read = true;
		}
		m_shutdown_write = true;
		m_no_linger = no_linger;
	}

	bool update(){
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		DEBUG_THROW_ASSERT(session);

		AUTO(fetch_client, m_fetch_client);
		if(!fetch_client){
			if(m_shutdown_read){
				LOG_MEDUSA2_DEBUG("Connection was cancelled: host:port = ", m_host, ":", m_port);
				DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_CONNECTION_CANCELLED, Poseidon::sslit("Connection was cancelled"));
			}

			// Perform DNS lookup.
			if(!m_promised_sock_addr){
				LOG_MEDUSA2_DEBUG("@@ DNS lookup: host:port = ", m_host, ":", m_port);
				m_promised_sock_addr = Poseidon::DnsDaemon::enqueue_for_looking_up(m_host, m_port);
			}
			if(!m_promised_sock_addr->is_satisfied()){
				LOG_MEDUSA2_TRACE("Waiting for DNS lookup: host:port = ", m_host, ":", m_port);
				return false;
			}
			Poseidon::SockAddr sock_addr;
			try {
				sock_addr = m_promised_sock_addr->get();
			} catch(std::exception &e){
				LOG_MEDUSA2_DEBUG("DNS failure: what = ", e.what());
				DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_DNS_FAILURE, Poseidon::SharedNts(e.what()));
			}
			if(sock_addr.is_private()){
				LOG_MEDUSA2_DEBUG("Connections to private addresses are disallowed: host:port = ", m_host, ":", m_port, ", ip:port = ", Poseidon::IpPort(sock_addr));
				DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_PRIVATE_ADDRESS_DISALLOWED, Poseidon::sslit("Connections to private addresses are disallowed"));
			}
			LOG_MEDUSA2_DEBUG("@@ Creating FetchClient: ip:port = ", Poseidon::IpPort(sock_addr));

			// Create the TCP client.
			DEBUG_THROW_ASSERT(!m_establishment_notified);
			fetch_client = boost::make_shared<FetchClient>(sock_addr, m_use_ssl);
			if(m_no_delay){
				fetch_client->set_no_delay();
			}
			Poseidon::EpollDaemon::add_socket(fetch_client, false);
			m_fetch_client = fetch_client;
		}

		if(!m_no_linger){
			// Send some data, if any.
			if(!m_send_queue.empty()){
				Poseidon::StreamBuffer send_queue;
				send_queue.swap(m_send_queue);
				fetch_client->send(STD_MOVE(send_queue));
			}
			// Shut down the write side if requested, after all data have been sent.
			if(m_shutdown_write){
				fetch_client->shutdown_write();
			}
			if(!fetch_client->is_connected_or_closed()){
				LOG_MEDUSA2_TRACE("Waiting for establishment: host:port = ", m_host, ":", m_port);
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
			DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_CONNECTION_REFUSED, Poseidon::get_error_desc(syserrno));
		case ETIMEDOUT:
			DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_CONNECTION_TIMED_OUT, Poseidon::get_error_desc(syserrno));
		case ECONNRESET:
			DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_CONNECTION_RESET_BY_PEER, Poseidon::get_error_desc(syserrno));
		default:
			DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_CONNECTION_LOST_UNSPECIFIED, Poseidon::get_error_desc(syserrno));
		case 0:
			return true;
		}
	}
};

void PrimarySession::sync_timer_proc(const boost::weak_ptr<PrimarySession> &weak_session){
	PROFILE_ME;

	const AUTO(session, weak_session.lock());
	if(!session){
		return;
	}
	session->on_sync_timer();
}

PrimarySession::PrimarySession(Poseidon::Move<Poseidon::UniqueFile> socket)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
	, m_session_uuid(Poseidon::Uuid::random())
	, m_authenticated(false)
{
	LOG_MEDUSA2_INFO("PrimarySession constructor: remote = ", get_remote_info());
}
PrimarySession::~PrimarySession(){
	LOG_MEDUSA2_INFO("PrimarySession destructor: remote = ", get_remote_info());
}

void PrimarySession::on_sync_timer()
try {
	PROFILE_ME;
	LOG_MEDUSA2_TRACE("Timer: remote = ", get_remote_info());

	Protocol::SP_Closed closed_msg;
	bool erase_it;
	for(AUTO(it, m_channels.begin()); it != m_channels.end(); erase_it ? (it = m_channels.erase(it)) : ++it){
		const AUTO(channel_uuid, it->first);
		const AUTO(channel, it->second);
		LOG_MEDUSA2_TRACE("Updating channel: channel_uuid = ", channel_uuid);
		closed_msg.channel_uuid = channel_uuid;
		try {
			erase_it = channel->update();
			closed_msg.err_code = 0;
			closed_msg.err_msg  = VAL_INIT;
		} catch(Poseidon::Cbpp::Exception &e){
			LOG_MEDUSA2_INFO("Cbpp::Exception thrown: status_code = ", e.get_status_code(), ", what = ", e.what());
			erase_it = true;
			closed_msg.err_code = e.get_status_code();
			closed_msg.err_msg  = e.what();
		} catch(std::exception &e){
			LOG_MEDUSA2_INFO("std::exception thrown: what = ", e.what());
			erase_it = true;
			closed_msg.err_code = Protocol::ERR_INTERNAL_ERROR;
			closed_msg.err_msg  = e.what();
		}
		if(erase_it){
			send(closed_msg);
		}
	}

	if(m_channels.empty()){
		LOG_MEDUSA2_DEBUG("Destroying timer: remote = ", get_remote_info());
		m_timer.reset();
	}
} catch(Poseidon::Cbpp::Exception &e){
	LOG_MEDUSA2_ERROR("Cbpp::Exception thrown: remote = ", get_remote_info(), ", status_code = ", e.get_status_code(), ", what = ", e.what());
	shutdown(e.get_status_code(), e.what());
} catch(std::exception &e){
	LOG_MEDUSA2_ERROR("std::exception thrown: remote = ", get_remote_info(), ", what = ", e.what());
	shutdown(Protocol::ERR_INTERNAL_ERROR, e.what());
}
void PrimarySession::on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload){
	PROFILE_ME;
	LOG_MEDUSA2_TRACE("Received data message: remote = ", get_remote_info(), ", message_id = ", message_id);

	Poseidon::StreamBuffer plaintext;
	try {
		plaintext = Common::decrypt(STD_MOVE(payload));
	} catch(std::exception &e){
		LOG_MEDUSA2_ERROR("Failed to decrypt message: remote = ", get_remote_info(), ", what = ", e.what());
		force_shutdown();
		return;
	}
	LOG_MEDUSA2_TRACE("> message_id = ", message_id, ", plaintext.size() = ", plaintext.size());
	m_authenticated = true;

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
	ON_MESSAGE(Protocol::PS_Connect, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Create channel and connect: channel_uuid = ", channel_uuid, ", host:port = ", msg.host, ":", msg.port, ", use_ssl = ", msg.use_ssl);

		if(!m_timer){
			LOG_MEDUSA2_DEBUG("Creating timer: remote = ", get_remote_info());
			m_timer = Poseidon::TimerDaemon::register_timer(0, 200, boost::bind(&sync_timer_proc, virtual_weak_from_this<PrimarySession>()));
		}
		LOG_MEDUSA2_DEBUG("Creating channel: channel_uuid = ", channel_uuid);
		const AUTO(channel, boost::make_shared<Channel>(channel_uuid, virtual_shared_from_this<PrimarySession>(), STD_MOVE(msg.host), msg.port, msg.use_ssl, msg.no_delay));
		const AUTO(it, m_channels.emplace(channel_uuid, channel));

		Protocol::SP_Opened open_msg;
		open_msg.channel_uuid = channel_uuid;
		open_msg.opaque       = STD_MOVE(msg.opaque);
		send(open_msg);

		(void)it;
	}
	ON_MESSAGE(Protocol::PS_Send, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Send to channel: channel_uuid = ", channel_uuid, ", segment.size() = ", msg.segment.size());

		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		const AUTO(channel, it->second);

		channel->send(STD_MOVE(msg.segment));
	}
	ON_MESSAGE(Protocol::PS_Acknowledge, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Acknowledge from channel: channel_uuid = ", channel_uuid, ", bytes_to_acknowledge = ", msg.bytes_to_acknowledge);

		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		const AUTO(channel, it->second);

		channel->acknowledge(msg.bytes_to_acknowledge);
	}
	ON_MESSAGE(Protocol::PS_Shutdown, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Shutdown channel: channel_uuid = ", channel_uuid, ", no_linger = ", msg.no_linger);

		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		const AUTO(channel, it->second);

		channel->shutdown(msg.no_linger);
	}
	ON_MESSAGE(Protocol::PS_Ping, msg){
		LOG_MEDUSA2_INFO("Received PING from ", get_remote_info(), ": ", msg);

		send(Protocol::SP_Pong(STD_MOVE(msg.opaque)));
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
void PrimarySession::on_sync_control_message(Poseidon::Cbpp::StatusCode status_code, Poseidon::StreamBuffer param){
	PROFILE_ME;

	if(!m_authenticated){
		LOG_MEDUSA2_ERROR("PrimarySession has not authenticated: remote = ", get_remote_info());
		force_shutdown();
		return;
	}

	return Poseidon::Cbpp::Session::on_sync_control_message(status_code, STD_MOVE(param));
}

bool PrimarySession::send(boost::uint16_t message_id, Poseidon::StreamBuffer payload){
	PROFILE_ME;

	AUTO(ciphertext, Common::encrypt(STD_MOVE(payload)));
	return Poseidon::Cbpp::Session::send(message_id, STD_MOVE(ciphertext));
}

bool PrimarySession::send(const Poseidon::Cbpp::MessageBase &msg){
	PROFILE_ME;

	return send(boost::numeric_cast<boost::uint16_t>(msg.get_id()), Poseidon::StreamBuffer(msg));
}

}
}
