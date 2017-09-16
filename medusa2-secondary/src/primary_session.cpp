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
	bool m_established_at_all;
	Poseidon::StreamBuffer m_recv_queue;
	boost::uint64_t m_queue_size;
	int m_syserrno;

public:
	FetchClient(const Poseidon::SockAddr &addr, bool use_ssl)
		: Poseidon::TcpClientBase(addr, use_ssl, true)
		, m_connected_or_closed(false), m_established_at_all(false), m_recv_queue(), m_queue_size(0), m_syserrno(ENOTCONN)
	{ }
	~FetchClient(){ }

protected:
	void on_connect() OVERRIDE {
		LOG_MEDUSA2_TRACE("Connection established: remote = ", get_remote_info());

		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		m_connected_or_closed = true;
		m_established_at_all = true;
		m_syserrno = EPIPE;
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

public:
	bool is_connected_or_closed() const {
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		return m_connected_or_closed;
	}
	bool was_established_at_all() const {
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		return m_established_at_all;
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
	static long translate_errno(int syserrno) NOEXCEPT {
		switch(syserrno){
		case 0:
			return Protocol::ERR_SUCCESS;
		default:
			return Protocol::ERR_CONNECTION_LOST_UNSPECIFIED;
		case ECONNREFUSED:
			return Protocol::ERR_CONNECTION_REFUSED;
		case ETIMEDOUT:
			return Protocol::ERR_CONNECTION_TIMED_OUT;
		case ECONNRESET:
			return Protocol::ERR_CONNECTION_RESET_BY_PEER;
		}
	}

private:
	const boost::weak_ptr<PrimarySession> m_weak_parent;
	const Poseidon::Uuid m_channel_uuid;
	const std::string m_opaque;

	const std::string m_host;
	const unsigned m_port;
	const bool m_use_ssl;

	long m_err_code;
	std::string m_err_msg;

	boost::shared_ptr<const Poseidon::JobPromiseContainer<Poseidon::SockAddr> > m_promised_sock_addr;
	bool m_establishment_notified;
	Poseidon::StreamBuffer m_send_queue;
	boost::shared_ptr<FetchClient> m_fetch_client;

public:
	Channel(const boost::shared_ptr<PrimarySession> &parent, const Poseidon::Uuid &channel_uuid, std::string opaque, std::string host, unsigned port, bool use_ssl)
		: m_weak_parent(parent), m_channel_uuid(channel_uuid), m_opaque(STD_MOVE(opaque)), m_host(STD_MOVE(host)), m_port(port), m_use_ssl(use_ssl)
		, m_err_code(Protocol::ERR_INTERNAL_ERROR), m_err_msg()
		, m_promised_sock_addr(), m_establishment_notified(false), m_send_queue(), m_fetch_client()
	{
		LOG_MEDUSA2_TRACE("Channel constructor: channel_uuid = ", m_channel_uuid);

		Protocol::SP_Opened msg;
		msg.channel_uuid = m_channel_uuid;
		msg.opaque       = m_opaque;
		parent->send(msg);
	}
	~Channel(){
		LOG_MEDUSA2_TRACE("Channel destructor: channel_uuid = ", m_channel_uuid);

		if(m_fetch_client){
			m_fetch_client->force_shutdown();
		}

		const AUTO(parent, m_weak_parent.lock());
		if(parent){
			try {
				Protocol::SP_Closed msg;
				msg.channel_uuid = m_channel_uuid;
				msg.err_code     = m_err_code;
				msg.err_msg      = STD_MOVE(m_err_msg);
				parent->send(msg);
			} catch(std::exception &e){
				LOG_MEDUSA2_WARNING("std::exception thrown: what = ", e.what());
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

		DEBUG_THROW_ASSERT(m_fetch_client);
		m_fetch_client->acknowledge(bytes_to_acknowledge);
	}
	void close(bool no_linger) NOEXCEPT {
		PROFILE_ME;

		if(m_fetch_client){
			if(no_linger){
				m_fetch_client->force_shutdown();
			} else {
				m_fetch_client->shutdown_write();
			}
		}
	}

	bool update(){
		PROFILE_ME;

		const AUTO(parent, m_weak_parent.lock());
		if(!parent){
			return true;
		}

		if(!m_promised_sock_addr){
			LOG_MEDUSA2_DEBUG("@@ DNS lookup: host:port = ", m_host, ":", m_port);
			m_promised_sock_addr = Poseidon::DnsDaemon::enqueue_for_looking_up(m_host, m_port);
		}
		if(!m_promised_sock_addr->is_satisfied()){
			LOG_MEDUSA2_TRACE("Waiting for DNS lookup: host:port = ", m_host, ":", m_port);
			return false;
		}

		if(!m_fetch_client){
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
				LOG_MEDUSA2_DEBUG("Connections to private addresses are disallowed: host:port = ", m_host, ":", m_port, ", ip:port = ", Poseidon::IpPort(sock_addr));
				m_err_code = Protocol::ERR_PRIVATE_ADDRESS_DISALLOWED;
				m_err_msg  = "Connection to private addresses are disallowed";
				return true;
			}
			LOG_MEDUSA2_DEBUG("@@ Creating FetchClient: ip:port = ", Poseidon::IpPort(sock_addr));
			m_fetch_client = boost::make_shared<FetchClient>(sock_addr, m_use_ssl);
			m_fetch_client->go_resident();
		}
		if(!m_send_queue.empty()){
			Poseidon::StreamBuffer send_queue;
			send_queue.swap(m_send_queue);
			m_fetch_client->send(STD_MOVE(send_queue));
		}
		if(!m_fetch_client->is_connected_or_closed()){
			LOG_MEDUSA2_TRACE("Waiting for establishment: host:port = ", m_host, ":", m_port);
			return false;
		}

		if(!m_establishment_notified && m_fetch_client->was_established_at_all()){
			m_establishment_notified = true;

			Protocol::SP_Established msg;
			msg.channel_uuid = m_channel_uuid;
			parent->send(msg);
		}

		bool no_more_data;
		for(;;){
			no_more_data = m_fetch_client->has_been_shutdown_read();
			AUTO(segment, m_fetch_client->cut_recv_queue());
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

		const int syserrno = m_fetch_client->get_syserrno();
		m_err_code = translate_errno(syserrno);
		m_err_msg = Poseidon::get_error_desc_as_string(syserrno);
		return true;
	}
};

void PrimarySession::timer_proc(const boost::weak_ptr<PrimarySession> &weak_session){
	PROFILE_ME;

	const AUTO(session, weak_session.lock());
	if(!session){
		return;
	}
	try {
		session->on_timer();
	} catch(Poseidon::Cbpp::Exception &e){
		LOG_MEDUSA2_ERROR("Cbpp::Exception thrown: remote = ", session->get_remote_info(), ", code = ", e.get_code(), ", what = ", e.what());
		session->shutdown(e.get_code(), e.what());
	} catch(std::exception &e){
		LOG_MEDUSA2_ERROR("std::exception thrown: remote = ", session->get_remote_info(), ", what = ", e.what());
		session->shutdown(Protocol::ERR_INTERNAL_ERROR, e.what());
	}
}

PrimarySession::PrimarySession(Poseidon::Move<Poseidon::UniqueFile> socket)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
{
	LOG_MEDUSA2_INFO("PrimarySession constructor: remote = ", get_remote_info());
}
PrimarySession::~PrimarySession(){
	LOG_MEDUSA2_INFO("PrimarySession destructor: remote = ", get_remote_info());
}

void PrimarySession::on_timer(){
	PROFILE_ME;
	LOG_MEDUSA2_TRACE("Timer: remote = ", get_remote_info());

	AUTO(it, m_channels.begin());
	while(it != m_channels.end()){
		const AUTO(channel_uuid, it->first);
		LOG_MEDUSA2_TRACE("Updating channel: channel_uuid = ", channel_uuid);
		const bool finished = it->second->update();
		if(finished){
			LOG_MEDUSA2_DEBUG("Destroying channel: channel_uuid = ", channel_uuid);
			it = m_channels.erase(it);
		} else {
			++it;
		}
	}
	if(m_channels.empty()){
		LOG_MEDUSA2_DEBUG("Destroying timer: remote = ", get_remote_info());
		m_timer.reset();
	}
}
void PrimarySession::on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload)
try {
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
	ON_MESSAGE(Protocol::PS_Open, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		if(!m_timer){
			LOG_MEDUSA2_DEBUG("Creating timer: remote = ", get_remote_info());
			m_timer = Poseidon::TimerDaemon::register_timer(0, 100, boost::bind(&timer_proc, virtual_weak_from_this<PrimarySession>()));
		}
		LOG_MEDUSA2_DEBUG("Creating channel: channel_uuid = ", channel_uuid);
		m_channels.emplace(channel_uuid, boost::make_shared<Channel>(virtual_shared_from_this<PrimarySession>(), channel_uuid, STD_MOVE(msg.opaque), STD_MOVE(msg.host), static_cast<boost::uint16_t>(msg.port), msg.use_ssl));
	}
	ON_MESSAGE(Protocol::PS_Send, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		it->second->send(msg.segment.data(), msg.segment.size());
	}
	ON_MESSAGE(Protocol::PS_Acknowledge, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		it->second->acknowledge(msg.bytes_to_acknowledge);
	}
	ON_MESSAGE(Protocol::PS_Close, msg){
		const AUTO(channel_uuid, Poseidon::Uuid(msg.channel_uuid));
		const AUTO(it, m_channels.find(channel_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA2_DEBUG("Channel not found: channel_uuid = ", channel_uuid);
			break;
		}
		it->second->close(msg.no_linger);
	}
//=============================================================================
#undef ON_MESSAGE
		}
		break; }
	default:
		LOG_MEDUSA2_ERROR("Unknown message: remote = ", get_remote_info(), ", message_id = ", message_id);
		DEBUG_THROW(Poseidon::Cbpp::Exception, Protocol::ERR_NOT_FOUND, Poseidon::sslit("Unknown message"));
	}
} catch(Poseidon::Cbpp::Exception &e){
	LOG_MEDUSA2_ERROR("Cbpp::Exception thrown: remote = ", get_remote_info(), ", code = ", e.get_code(), ", what = ", e.what());
	throw;
} catch(std::exception &e){
	LOG_MEDUSA2_ERROR("std::exception thrown: remote = ", get_remote_info(), ", what = ", e.what());
	throw;
}

bool PrimarySession::send(const Poseidon::Cbpp::MessageBase &msg){
	PROFILE_ME;

	AUTO(ciphertext, Common::encrypt(msg));
	return Poseidon::Cbpp::Session::send(msg.get_id(), STD_MOVE(ciphertext));
}

}
}
