#include "precompiled.hpp"
#include "proxy_session.hpp"
#include "singletons/secondary_connector.hpp"
#include "secondary_channel.hpp"
#include "mmain.hpp"
#include "protocol/error_codes.hpp"
#include <poseidon/http/authorization.hpp>
#include <poseidon/http/exception.hpp>
#include <poseidon/http/upgraded_session_base.hpp>
#include <poseidon/http/client_reader.hpp>
#include <poseidon/http/client_writer.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/singletons/job_dispatcher.hpp>

namespace Medusa2 {
namespace Primary {

class ProxySession::TunnelSession : public Poseidon::Http::UpgradedSessionBase {
public:
	explicit TunnelSession(const boost::shared_ptr<ProxySession> &session)
		: Poseidon::Http::UpgradedSessionBase(session)
	{ }

protected:
	void on_connect() OVERRIDE {
		LOG_MEDUSA2_DEBUG("TunnelSession::on_connect()");
	}
	void on_read_hup() OVERRIDE {
		LOG_MEDUSA2_DEBUG("TunnelSession::on_read_hup()");
	}
	void on_close(int err_code) OVERRIDE {
		LOG_MEDUSA2_DEBUG("TunnelSession::on_close(): err_code = ", err_code);
	}
	void on_receive(Poseidon::StreamBuffer data) OVERRIDE {
		LOG_MEDUSA2_DEBUG("TunnelSession::on_receive(): data.size() = ", data.size());

		const AUTO(session, boost::dynamic_pointer_cast<ProxySession>(get_parent()));
		if(!session){
			return;
		}
		session->low_level_enqueue_tunnel_data(STD_MOVE(data));
	}
};

class ProxySession::DeafSession : public Poseidon::Http::UpgradedSessionBase {
public:
	explicit DeafSession(const boost::shared_ptr<ProxySession> &session)
		: Poseidon::Http::UpgradedSessionBase(session)
	{ }

protected:
	void on_connect() OVERRIDE {
		LOG_MEDUSA2_DEBUG("DeafSession::on_connect()");
	}
	void on_read_hup() OVERRIDE {
		LOG_MEDUSA2_DEBUG("DeafSession::on_read_hup()");
	}
	void on_close(int err_code) OVERRIDE {
		LOG_MEDUSA2_DEBUG("DeafSession::on_close(): err_code = ", err_code);
	}
	void on_receive(Poseidon::StreamBuffer data) OVERRIDE {
		LOG_MEDUSA2_DEBUG("DeafSession::on_receive(): data.size() = ", data.size());
	}
};

class ProxySession::Channel : public SecondaryChannel, public Poseidon::Http::ClientWriter, public Poseidon::Http::ClientReader {
private:
	boost::weak_ptr<ProxySession> m_weak_session;

public:
	Channel(const boost::shared_ptr<ProxySession> &session, std::string host, unsigned port, bool use_ssl, bool no_delay)
		: SecondaryChannel(STD_MOVE(host), port, use_ssl, no_delay)
		, m_weak_session(session)
	{ }
	~Channel(){
		const AUTO(session, m_weak_session.lock());
		if(session){
			LOG_MEDUSA2_WARNING("Channel was not shut down cleanly: channel_uuid = ", get_channel_uuid());
			session->force_shutdown();
		}
	}

private:
	void unlink_and_shutdown(Poseidon::Http::StatusCode status_code, long err_code, const char *err_msg) NOEXCEPT {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}
		m_weak_session.reset();
		session->m_weak_channel.reset();
		session->sync_pretty_shutdown(status_code, err_code, err_msg, VAL_INIT);
	}

protected:
	// SecondaryChannel
	void on_sync_opened() OVERRIDE {
		LOG_POSEIDON_DEBUG("Channel::on_sync_opened()");
	}
	void on_sync_established() OVERRIDE {
		LOG_POSEIDON_DEBUG("Channel::on_sync_established()");

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}
		if(session->m_tunnel){
			const AUTO(tunnel_session, boost::dynamic_pointer_cast<TunnelSession>(session->get_upgraded_session()));
			DEBUG_THROW_ASSERT(tunnel_session);
			Poseidon::Http::ResponseHeaders response_headers;
			response_headers.version     = 10001;
			response_headers.status_code = Poseidon::Http::ST_OK;
			response_headers.reason      = "Connection Established";
			response_headers.headers.set(Poseidon::sslit("Proxy-Connection"), "Keep-Alive");
			session->put_response(STD_MOVE(response_headers), VAL_INIT, false);
			session->m_response_accepted = true;
		} else {
			// Do nothig.
		}
	}
	void on_sync_received(Poseidon::StreamBuffer data) OVERRIDE {
		LOG_POSEIDON_DEBUG("Channel::on_sync_received(): data.size() = ", data.size());

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}
		if(session->m_tunnel){
			const AUTO(tunnel_session, boost::dynamic_pointer_cast<TunnelSession>(session->get_upgraded_session()));
			DEBUG_THROW_ASSERT(tunnel_session);
			tunnel_session->send(STD_MOVE(data));
		} else {
			const AUTO(deaf_session, boost::dynamic_pointer_cast<DeafSession>(session->get_upgraded_session()));
			DEBUG_THROW_ASSERT(deaf_session);
			try {
				put_encoded_data(STD_MOVE(data));
			} catch(std::exception &e){
				LOG_POSEIDON_WARNING("std::exception thrown while parsing response from the origin server: what = ", e.what());
				unlink_and_shutdown(Poseidon::Http::ST_BAD_GATEWAY, Protocol::ERR_ORIGIN_INVALID_HTTP_RESPONSE, "The origin server sent no valid HTTP response");
			}
		}
	}
	void on_sync_closed(long err_code, std::string err_msg) OVERRIDE {
		LOG_POSEIDON_DEBUG("Channel::on_sync_closed(): err_code = ", err_code, ", err_msg = ", err_msg);

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}
		if(session->m_tunnel){
			const AUTO(tunnel_session, boost::dynamic_pointer_cast<TunnelSession>(session->get_upgraded_session()));
			DEBUG_THROW_ASSERT(tunnel_session);
			if(err_code == 0){
				tunnel_session->shutdown_read();
				tunnel_session->shutdown_write();
			} else {
				unlink_and_shutdown(Poseidon::Http::ST_BAD_GATEWAY, err_code, err_msg.c_str());
			}
		} else {
			const AUTO(deaf_session, boost::dynamic_pointer_cast<DeafSession>(session->get_upgraded_session()));
			DEBUG_THROW_ASSERT(deaf_session);
			if(is_content_till_eof()){
				terminate_content();
			}
			if(err_code == 0){
				unlink_and_shutdown(Poseidon::Http::ST_BAD_GATEWAY, Protocol::ERR_ORIGIN_EMPTY_RESPONSE, "The origin server sent no data");
			} else {
				unlink_and_shutdown(Poseidon::Http::ST_BAD_GATEWAY, err_code, err_msg.c_str());
			}
		}
	}

	// ClientWriter
	long on_encoded_data_avail(Poseidon::StreamBuffer encoded) OVERRIDE {
		PROFILE_ME;

		return send(STD_MOVE(encoded));
	}

	// ClientReader
	void on_response_headers(Poseidon::Http::ResponseHeaders response_headers, boost::uint64_t /*content_length*/) OVERRIDE {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}
		const AUTO(deaf_session, boost::dynamic_pointer_cast<DeafSession>(session->get_upgraded_session()));
		DEBUG_THROW_ASSERT(deaf_session);
		response_headers.headers.set(Poseidon::sslit("Proxy-Connection"), "Close");
		const AUTO_REF(transfer_encoding, response_headers.headers.get("Transfer-Encoding"));
		if(transfer_encoding.empty() || (::strcasecmp(transfer_encoding.c_str(), "identity") == 0)){
			response_headers.headers.set(Poseidon::sslit("Transfer-Encoding"), "chunked");
		}
		session->put_chunked_header(STD_MOVE(response_headers));
		session->m_response_accepted = true;
	}
	void on_response_entity(boost::uint64_t /*entity_offset*/, Poseidon::StreamBuffer entity) OVERRIDE {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}
		const AUTO(deaf_session, boost::dynamic_pointer_cast<DeafSession>(session->get_upgraded_session()));
		DEBUG_THROW_ASSERT(deaf_session);
		session->put_chunk(STD_MOVE(entity));
	}
	bool on_response_end(boost::uint64_t /*content_length*/, Poseidon::OptionalMap headers) OVERRIDE {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return false;
		}
		const AUTO(deaf_session, boost::dynamic_pointer_cast<DeafSession>(session->get_upgraded_session()));
		DEBUG_THROW_ASSERT(deaf_session);
		session->put_chunked_trailer(STD_MOVE(headers));
		unlink_and_shutdown(Poseidon::Http::ST_NO_CONTENT, 0, "");
		return false;
	}
};

class ProxySession::SyncJobBase : public Poseidon::JobBase {
private:
	const SocketBase::DelayedShutdownGuard m_guard;
	const boost::weak_ptr<ProxySession> m_weak_session;

public:
	explicit SyncJobBase(const boost::shared_ptr<ProxySession> &session)
		: m_guard(session), m_weak_session(session)
	{ }

protected:
	boost::weak_ptr<const void> get_category() const FINAL {
		return m_weak_session;
	}
	void perform() FINAL {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session || session->has_been_shutdown_write()){
			return;
		}
		try {
			really_perform(session);
		} catch(std::exception &e){
			LOG_POSEIDON_WARNING("std::exception thrown: remote = ", session->get_remote_info(), ", what = ", e.what());
			session->force_shutdown();
		}
	}

	virtual void really_perform(const boost::shared_ptr<ProxySession> &session) = 0;
};

class ProxySession::RequestHeadersJob : public ProxySession::SyncJobBase {
private:
	Poseidon::Http::RequestHeaders m_request_headers;
	bool m_chunked;
	bool m_tunnel;

public:
	RequestHeadersJob(const boost::shared_ptr<ProxySession> &session, Poseidon::Http::RequestHeaders request_headers, bool chunked, bool tunnel)
		: SyncJobBase(session)
		, m_request_headers(STD_MOVE(request_headers)), m_chunked(chunked), m_tunnel(tunnel)
	{ }

protected:
	void really_perform(const boost::shared_ptr<ProxySession> &session) FINAL {
		PROFILE_ME;

		AUTO_REF(verb, m_request_headers.verb);
		AUTO_REF(uri, m_request_headers.uri);
		AUTO_REF(headers, m_request_headers.headers);

		// XXX: If an exception is thrown, make sure its destructor does not shut the session down violently.
		//      This `shared_ptr` ensures that its destructor is run after any `catch` block.
		boost::shared_ptr<Channel> channel;

		try {
			if(uri.at(0) == '/'){
				// TODO: This could be useful.
				LOG_MEDUSA2_INFO("Relative URI not handled: remote = ", session->get_remote_info(), ", uri = ", uri);
				DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_FORBIDDEN);
			}

			LOG_MEDUSA2_INFO("New fetch request from ", session->get_remote_info());
			LOG_MEDUSA2_INFO(">> ", Poseidon::Http::get_string_from_verb(verb), " ", uri);
			LOG_MEDUSA2_DEBUG(">> Request headers: ", headers);
			LOG_MEDUSA2_INFO(">> Proxy-Authorization: ", headers.get("Proxy-Authorization"));
			LOG_MEDUSA2_INFO(">> User-Agent: ", headers.get("User-Agent"));

			if(session->m_auth_info){
				Poseidon::Http::check_and_throw_if_unauthorized(session->m_auth_info, session->get_remote_info(), m_request_headers, true);
			}

			std::string host;
			unsigned port = 80;
			bool use_ssl = false;
			bool no_delay = false;

			// uri = "http://www.example.com:80/foo/bar/page.html?param=value"
			AUTO(pos, uri.find("://"));
			if(pos != std::string::npos){
				uri.at(pos) = 0;
				LOG_MEDUSA2_TRACE("Request protocol = ", uri.c_str());
				if(::strcasecmp(uri.c_str(), "http") == 0){
					port = 80;
					use_ssl = false;
				} else if(::strcasecmp(uri.c_str(), "https") == 0){
					port = 443;
					use_ssl = true;
				} else {
					LOG_MEDUSA2_WARNING("Unsupported protocol: ", uri.c_str(), ", remote = ", session->get_remote_info());
					DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Unsupported protocol"));
				}
				uri.erase(0, pos + 3);
			}
			// uri = "www.example.com:80/foo/bar/page.html?param=value"
			pos = uri.find('/');
			if(pos != std::string::npos){
				host = uri.substr(0, pos);
				uri.erase(0, pos);
			} else {
				host = STD_MOVE(uri);
				uri = "/";
			}
			// host = "www.example.com:80"
			// uri = "/foo/bar/page.html?param=value"
			if(host[0] == '['){
				pos = host.find(']');
				if(pos == std::string::npos){
					LOG_MEDUSA2_WARNING("Invalid IPv6 address: host = ", host);
					DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Invalid IPv6 address"));
				}
				pos = host.find(':', pos + 1);
			} else {
				pos = host.find(':');
			}
			if(pos != std::string::npos){
				char *endptr;
				const AUTO(port_val, std::strtoul(host.c_str() + pos + 1, &endptr, 10));
				if(*endptr){
					LOG_MEDUSA2_WARNING("Invalid port string: host = ", host, ", remote = ", session->get_remote_info());
					DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Invalid port string"));
				}
				if((port_val == 0) || (port_val >= 65535)){
					LOG_MEDUSA2_WARNING("Invalid port number: host = ", host, ", remote = ", session->get_remote_info());
					DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Invalid port number"));
				}
				port = port_val;
				host.erase(pos);
			}
			// host = "www.example.com"
			// port = 80
			// uri = "/foo/bar/page.html?param=value"
			if(m_tunnel){
				no_delay = true;
			} else {
				headers.erase("Prxoy-Authenticate");
				headers.erase("Proxy-Connection");

				headers.set(Poseidon::sslit("Connection"), "Close");
				headers.set(Poseidon::sslit("X-Forwarded-Host"), host);

				AUTO(x_forwarded_for, headers.get("X-Forwarded-For"));
				if(!x_forwarded_for.empty()){
					x_forwarded_for += ", ";
				}
				x_forwarded_for += session->get_remote_info().ip();
				headers.set(Poseidon::sslit("X-Forwarded-For"), STD_MOVE(x_forwarded_for));
			}

			channel = boost::make_shared<Channel>(session, STD_MOVE(host), port, use_ssl, no_delay);
			SecondaryConnector::attach_channel(channel);
			session->m_weak_channel = channel;

			if(m_tunnel){
				// Do nothing.
			} else {
				Poseidon::Http::RequestHeaders rewritten_headers;
				rewritten_headers.verb    = verb;
				rewritten_headers.uri     = STD_MOVE(uri);
				rewritten_headers.version = 10001;
				rewritten_headers.headers = STD_MOVE(headers);
				if(!m_chunked){
					channel->put_request(STD_MOVE(rewritten_headers), VAL_INIT, false);
				} else {
					channel->put_chunked_header(STD_MOVE(rewritten_headers));
				}
			}

			const AUTO(timeout, get_config<boost::uint64_t>("proxy_session_timeout", 300000));
			session->set_timeout(timeout);
		} catch(Poseidon::Http::Exception &e){
			LOG_MEDUSA2_WARNING("Http::Exception thrown: status_code = ", e.get_status_code(), ", what = ", e.what());
			session->sync_pretty_shutdown(e.get_status_code(), Protocol::ERR_CONNECTION_CANCELLED, e.what(), e.get_headers());
		} catch(std::exception &e){
			LOG_MEDUSA2_WARNING("std::exception thrown: what = ", e.what());
			session->sync_pretty_shutdown(Poseidon::Http::ST_BAD_GATEWAY, Protocol::ERR_CONNECTION_CANCELLED, e.what(), VAL_INIT);
		}
	}
};

class ProxySession::RequestEntityJob : public ProxySession::SyncJobBase {
private:
	bool m_chunked;
	Poseidon::StreamBuffer m_entity;

public:
	RequestEntityJob(const boost::shared_ptr<ProxySession> &session, bool chunked, Poseidon::StreamBuffer entity)
		: SyncJobBase(session)
		, m_chunked(chunked), m_entity(STD_MOVE(entity))
	{ }

protected:
	void really_perform(const boost::shared_ptr<ProxySession> &session) FINAL {
		PROFILE_ME;

		const AUTO(channel, session->m_weak_channel.lock());
		if(channel){
			if(!m_chunked){
				channel->send(STD_MOVE(m_entity));
			} else {
				channel->put_chunk(STD_MOVE(m_entity));
			}
		}
	}
};

class ProxySession::RequestEndJob : public ProxySession::SyncJobBase {
private:
	bool m_chunked;
	Poseidon::OptionalMap m_headers;

public:
	RequestEndJob(const boost::shared_ptr<ProxySession> &session, bool chunked, Poseidon::OptionalMap headers)
		: SyncJobBase(session)
		, m_chunked(chunked), m_headers(STD_MOVE(headers))
	{ }

protected:
	void really_perform(const boost::shared_ptr<ProxySession> &session) FINAL {
		PROFILE_ME;

		const AUTO(channel, session->m_weak_channel.lock());
		if(channel){
			if(!m_chunked){
				// Do nothing
			} else {
				channel->put_chunked_trailer(STD_MOVE(m_headers));
			}
		}
	}
};

class ProxySession::ReadHupJob : public ProxySession::SyncJobBase {
public:
	explicit ReadHupJob(const boost::shared_ptr<ProxySession> &session)
		: SyncJobBase(session)
	{ }

protected:
	void really_perform(const boost::shared_ptr<ProxySession> &session) FINAL {
		PROFILE_ME;

		const AUTO(channel, session->m_weak_channel.lock());
		session->m_weak_channel.reset();
		if(channel){
			channel->shutdown(false);
		}

		session->shutdown_write();
	}
};

ProxySession::ProxySession(Poseidon::Move<Poseidon::UniqueFile> socket, boost::shared_ptr<const Poseidon::Http::AuthInfo> auth_info)
	: Poseidon::Http::LowLevelSession(STD_MOVE(socket))
	, m_auth_info(STD_MOVE(auth_info))
	, m_chunked(false), m_tunnel(false)
	, m_weak_channel(), m_response_accepted(false)
{
	LOG_MEDUSA2_INFO("ProxySession constructor: remote = ", get_remote_info());
}
ProxySession::~ProxySession(){
	LOG_MEDUSA2_INFO("ProxySession destructor: remote = ", get_remote_info());

	const AUTO(channel, m_weak_channel.lock());
	if(channel){
		LOG_MEDUSA2_WARNING("Channel was not shut down cleanly: channel_uuid = ", channel->get_channel_uuid());
		channel->shutdown(true);
	}
}

void ProxySession::sync_pretty_shutdown(unsigned status_code, long err_code, const char *err_msg, const Poseidon::OptionalMap &headers) NOEXCEPT
try {
	PROFILE_ME;

	if(!m_response_accepted){
		Poseidon::Http::ResponseHeaders response_headers;
		response_headers.version = 10001;
		response_headers.status_code = status_code;
		response_headers.reason = Poseidon::Http::get_status_code_desc(status_code).desc_short;
		response_headers.headers = headers;
		response_headers.headers.erase(Poseidon::sslit("Transfer-Encoding"));
		response_headers.headers.erase(Poseidon::sslit("Content-Encoding"));
		response_headers.headers.set(Poseidon::sslit("Connection"), "Close");
		response_headers.headers.set(Poseidon::sslit("Proxy-Connection"), "Close");
		response_headers.headers.set(Poseidon::sslit("Content-Type"), "text/html; charset=utf-8");

		Poseidon::Buffer_ostream entity_os;
		entity_os <<"<html>"
		          <<"<head>"
		          <<"  <title>" <<response_headers.status_code <<" " <<response_headers.reason <<"</title>"
		          <<"</head>"
		          <<"<body>"
		          <<"  <h1>" <<response_headers.status_code <<" " <<response_headers.reason <<"</h1>"
		          <<"  <hr />"
		          <<"  <p>Error " <<err_code <<": " <<err_msg <<".</p>"
		          <<"</body>"
		          <<"</html>";
		AUTO(entity, STD_MOVE(entity_os.get_buffer()));

		Poseidon::Http::ServerWriter::put_response(STD_MOVE(response_headers), STD_MOVE(entity), true);
		m_response_accepted = true;
	}

	shutdown_read();
	shutdown_write();
} catch(std::exception &e){
	LOG_MEDUSA2_ERROR("std::exception thrown: what = ", e.what());
	force_shutdown();
}
void ProxySession::low_level_enqueue_tunnel_data(Poseidon::StreamBuffer data){
	PROFILE_ME;

	Poseidon::JobDispatcher::enqueue(
		boost::make_shared<RequestEntityJob>(virtual_shared_from_this<ProxySession>(), false, STD_MOVE(data)),
		VAL_INIT);
}

void ProxySession::on_read_hup(){
	PROFILE_ME;

	Poseidon::JobDispatcher::enqueue(
		boost::make_shared<ReadHupJob>(virtual_shared_from_this<ProxySession>()),
		VAL_INIT);

	Poseidon::Http::LowLevelSession::on_read_hup();
}

void ProxySession::on_low_level_request_headers(Poseidon::Http::RequestHeaders request_headers, boost::uint64_t content_length){
	PROFILE_ME;

	m_chunked = content_length == Poseidon::Http::ServerReader::CONTENT_CHUNKED;
	m_tunnel = request_headers.verb == Poseidon::Http::V_CONNECT;

	Poseidon::JobDispatcher::enqueue(
		boost::make_shared<RequestHeadersJob>(virtual_shared_from_this<ProxySession>(), STD_MOVE(request_headers), m_chunked, m_tunnel),
		VAL_INIT);
}
void ProxySession::on_low_level_request_entity(boost::uint64_t /*entity_offset*/, Poseidon::StreamBuffer entity){
	PROFILE_ME;

	if(m_tunnel){
		// Do nothing.
	} else {
		Poseidon::JobDispatcher::enqueue(
			boost::make_shared<RequestEntityJob>(virtual_shared_from_this<ProxySession>(), m_chunked, STD_MOVE(entity)),
			VAL_INIT);
	}
}
boost::shared_ptr<Poseidon::Http::UpgradedSessionBase> ProxySession::on_low_level_request_end(boost::uint64_t /*content_length*/, Poseidon::OptionalMap headers){
	PROFILE_ME;

	if(m_tunnel){
		return boost::make_shared<TunnelSession>(virtual_shared_from_this<ProxySession>());
	} else {
		Poseidon::JobDispatcher::enqueue(
			boost::make_shared<RequestEndJob>(virtual_shared_from_this<ProxySession>(), m_chunked, STD_MOVE(headers)),
			VAL_INIT);
		return boost::make_shared<DeafSession>(virtual_shared_from_this<ProxySession>());
	}
}

}
}
