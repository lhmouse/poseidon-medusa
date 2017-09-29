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
		, m_connected_or_closed(false), m_established_after_all(false), m_recv_queue(), m_queue_size(0), m_syserrno(ENOTCONN)
	{ }

protected:
	void on_connect() OVERRIDE {
		LOG_MEDUSA2_TRACE("Connection established: remote = ", get_remote_info());

		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		m_connected_or_closed = true;
		m_established_after_all = true;
		m_syserrno = EPIPE;
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
	std::basic_string<unsigned char> cut_recv_queue(){
		const AUTO(fragmentation_size, get_config<std::size_t>("fetch_fragmentation_size", 8192));

		std::basic_string<unsigned char> data;
		data.resize(fragmentation_size);

		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		data.resize(m_recv_queue.get(&data[0], data.size()));
		return data;
	}
	int get_syserrno() const {
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		return m_syserrno;
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
	const boost::weak_ptr<PrimarySession> m_weak_parent;
	const Poseidon::Uuid m_channel_uuid;

	const std::string m_host;
	const unsigned m_port;
	const bool m_use_ssl;
	const bool m_no_delay;

	long m_err_code;
	std::string m_err_msg;

	boost::shared_ptr<const Poseidon::JobPromiseContainer<Poseidon::SockAddr> > m_promised_sock_addr;
	bool m_establishment_notified;
	Poseidon::StreamBuffer m_send_queue;
	bool m_shutdown;
	boost::shared_ptr<FetchClient> m_fetch_client;

public:
	Channel(const boost::shared_ptr<PrimarySession> &parent, const Poseidon::Uuid &channel_uuid, std::string host, unsigned port, bool use_ssl, bool no_delay,
		std::basic_string<unsigned char> opaque)
		: m_weak_parent(parent), m_channel_uuid(channel_uuid), m_host(STD_MOVE(host)), m_port(port), m_use_ssl(use_ssl), m_no_delay(no_delay)
		, m_err_code(Protocol::ERR_CONNECTION_ABORTED), m_err_msg()
		, m_promised_sock_addr(), m_establishment_notified(false), m_send_queue(), m_shutdown(false), m_fetch_client()
	{
		LOG_MEDUSA2_TRACE("Channel constructor: channel_uuid = ", m_channel_uuid);

		Protocol::SP_Opened msg;
		msg.channel_uuid = m_channel_uuid;
		msg.opaque       = STD_MOVE(opaque);
		parent->send(msg);
	}
	~Channel(){
		LOG_MEDUSA2_TRACE("Channel destructor: channel_uuid = ", m_channel_uuid);

		const AUTO(fetch_client, m_fetch_client);
		if(fetch_client){
			LOG_MEDUSA2_WARNING("FetchClient was not shut down cleanly: channel_uuid = ", m_channel_uuid);
			fetch_client->force_shutdown();
		}

		const AUTO(parent, m_weak_parent.lock());
		if(parent){
			try {
				Protocol::SP_Closed msg;
				msg.channel_uuid = m_channel_uuid;
				msg.err_code     = m_err_code;
				msg.err_msg      = m_err_msg;
				parent->send(msg);
			} catch(std::exception &e){
				LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
				parent->shutdown(Protocol::ERR_INTERNAL_ERROR, e.what());
			}
		}
	}

public:
	void send(const void *data, std::size_t size){
		PROFILE_ME;

		m_send_queue.put(data, size);
	}
	void acknowledge(boost::uint64_t bytes_to_acknowledge){
		PROFILE_ME;

		const AUTO(fetch_client, m_fetch_client);
		DEBUG_THROW_ASSERT(fetch_client);

		fetch_client->acknowledge(bytes_to_acknowledge);
	}
	void shutdown(bool no_linger){
		PROFILE_ME;

		m_shutdown = true;

		const AUTO(fetch_client, m_fetch_client);
		if(fetch_client){
			if(no_linger){
				fetch_client->force_shutdown();
			} else {
				fetch_client->shutdown_write();
			}
		}
	}

	bool update(){
		PROFILE_ME;

		const AUTO(parent, m_weak_parent.lock());
		if(!parent){
			m_err_code = Protocol::ERR_CONNECTION_ABORTED;
			m_err_msg  = "Lost connection to primary server";
			return true;
		}

		AUTO(fetch_client, m_fetch_client);
		if(!fetch_client){
			if(m_shutdown){
				m_err_code = Protocol::ERR_CONNECTION_ABORTED;
				m_err_msg  = "Connection was shut down prematurely";
				return true;
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
				m_err_code = Protocol::ERR_DNS_FAILURE;
				m_err_msg  = e.what();
				return true;
			}
			if(sock_addr.is_private()){
				LOG_MEDUSA2_DEBUG("Connections to private addresses disallowed: host:port = ", m_host, ":", m_port, ", ip:port = ", Poseidon::IpPort(sock_addr));
				m_err_code = Protocol::ERR_PRIVATE_ADDRESS_DISALLOWED;
				m_err_msg  = "Connections to private addresses disallowed";
				return true;
			}
			LOG_MEDUSA2_DEBUG("@@ Creating FetchClient: ip:port = ", Poseidon::IpPort(sock_addr));

			// Create the TCP client.
			fetch_client = boost::make_shared<FetchClient>(sock_addr, m_use_ssl);
			if(m_no_delay){
				fetch_client->set_no_delay();
			}
			fetch_client->go_resident();
			m_fetch_client = fetch_client;
		}

		// Send some data, if any.
		if(!m_send_queue.empty()){
			Poseidon::StreamBuffer send_queue;
			send_queue.swap(m_send_queue);
			fetch_client->send(STD_MOVE(send_queue));
		}
		// Shut down the write side if requested, after all data have been sent.
		if(m_shutdown){
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
				msg.channel_uuid = m_channel_uuid;
				parent->send(msg);
			}
			m_establishment_notified = true;
		}

		// Read some data, if any.
		bool no_more_data;
		for(;;){
			// ** DO NOT SWAP THESE TWO LINES!! **
			no_more_data = fetch_client->has_been_shutdown_read(); // [1]
			AUTO(segment, fetch_client->cut_recv_queue());         // [2]
			if(segment.empty()){
				break;
			}
			Protocol::SP_Received msg;
			msg.channel_uuid = m_channel_uuid;
			msg.segment      = STD_MOVE(segment);
			parent->send(msg);
		}
		if(!no_more_data){
			LOG_MEDUSA2_TRACE("Waiting for more data: host:port = ", m_host, ":", m_port);
			return false;
		}
		// Clear the client.
		fetch_client->shutdown_write();
		m_shutdown = true;
		m_fetch_client.reset();

		const int syserrno = fetch_client->get_syserrno();
		switch(syserrno){
		case 0:
			m_err_code = Protocol::ERR_SUCCESS;
			break;
		default:
			m_err_code = Protocol::ERR_CONNECTION_LOST_UNSPECIFIED;
			break;
		case ECONNREFUSED:
			m_err_code = Protocol::ERR_CONNECTION_REFUSED;
			break;
		case ETIMEDOUT:
			m_err_code = Protocol::ERR_CONNECTION_TIMED_OUT;
			break;
		case ECONNRESET:
			m_err_code = Protocol::ERR_CONNECTION_RESET_BY_PEER;
			break;
		}
		m_err_msg = Poseidon::get_error_desc_as_string(syserrno);
		return true;
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

	bool erase_it;
	for(AUTO(it, m_channels.begin()); it != m_channels.end(); erase_it ? (it = m_channels.erase(it)) : ++it){
		const AUTO(channel_uuid, it->first);
		LOG_MEDUSA2_TRACE("Updating channel: channel_uuid = ", channel_uuid);
		const AUTO(channel, it->second);
		erase_it = channel->update();
	}

	if(m_channels.empty()){
		LOG_MEDUSA2_DEBUG("Destroying timer: remote = ", get_remote_info());
		m_timer.reset();
	}
} catch(Poseidon::Cbpp::Exception &e){
	LOG_MEDUSA2_ERROR("Cbpp::Exception thrown: remote = ", get_remote_info(), ", code = ", e.get_code(), ", what = ", e.what());
	shutdown(e.get_code(), e.what());
} catch(std::exception &e){
	LOG_MEDUSA2_ERROR("std::exception thrown: remote = ", get_remote_info(), ", what = ", e.what());
	shutdown(Protocol::ERR_INTERNAL_ERROR, e.what());
}
void PrimarySession::on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload){
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
	ON_MESSAGE(Protocol::PS_Connect, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		LOG_MEDUSA2_DEBUG("Create channel and connect: channel_uuid = ", channel_uuid, ", host:port = ", msg.host, ":", msg.port, ", use_ssl = ", msg.use_ssl);

		if(!m_timer){
			LOG_MEDUSA2_DEBUG("Creating timer: remote = ", get_remote_info());
			m_timer = Poseidon::TimerDaemon::register_timer(0, 200, boost::bind(&sync_timer_proc, virtual_weak_from_this<PrimarySession>()));
		}
		LOG_MEDUSA2_DEBUG("Creating channel: channel_uuid = ", channel_uuid);
		const AUTO(channel, boost::make_shared<Channel>(virtual_shared_from_this<PrimarySession>(), channel_uuid, STD_MOVE(msg.host), msg.port, msg.use_ssl, msg.no_delay, STD_MOVE(msg.opaque)));
		const AUTO(it, m_channels.emplace(channel_uuid, channel));

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

		channel->send(msg.segment.data(), msg.segment.size());
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
//=============================================================================
#undef ON_MESSAGE
		}
		break; }
	default:
		LOG_MEDUSA2_ERROR("Unknown message: remote = ", get_remote_info(), ", message_id = ", message_id);
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_NOT_FOUND, Poseidon::sslit("Unknown message"));
	}
}

bool PrimarySession::send(const Poseidon::Cbpp::MessageBase &msg){
	PROFILE_ME;

	AUTO(ciphertext, Common::encrypt(msg));
	return Poseidon::Cbpp::Session::send(msg.get_id(), STD_MOVE(ciphertext));
}

}
}
