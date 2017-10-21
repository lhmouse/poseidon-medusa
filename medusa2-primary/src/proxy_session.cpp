#include "precompiled.hpp"
#include "proxy_session.hpp"
#include "singletons/secondary_connector.hpp"
#include "secondary_channel.hpp"
#include <poseidon/job_base.hpp>
#include <poseidon/singletons/job_dispatcher.hpp>
#include <poseidon/http/server_reader.hpp>
#include <poseidon/http/client_writer.hpp>
#include <poseidon/http/client_reader.hpp>
#include <poseidon/http/server_writer.hpp>
#include <poseidon/http/status_codes.hpp>
#include <poseidon/http/header_option.hpp>
#include <poseidon/http/authorization.hpp>
#include <poseidon/http/exception.hpp>
#include <boost/variant.hpp>

namespace Medusa2 {
namespace Primary {

class ProxySession::PipelineElement : NONCOPYABLE {
public:
	struct EndOfStream {
		enum { INDEX = 0 };
	};
	struct RequestHeaders {
		enum { INDEX = 1 };
		boost::weak_ptr<Channel> weak_channel;
		std::string uri;
		Poseidon::OptionalMap headers;
	};
	struct RequestEntity {
		enum { INDEX = 2 };
		boost::weak_ptr<Channel> weak_channel;
		bool tunnel;
		bool keep_alive;
		Poseidon::StreamBuffer data;
	};
	struct Error {
		enum { INDEX = 3 };
		Poseidon::Http::StatusCode status_code;
		Poseidon::OptionalMap headers;
		std::string what;
	};

private:
	boost::variant<EndOfStream, RequestHeaders, RequestEntity, Error> m_storage;

public:
	template<typename T>
	explicit PipelineElement(T t, typename boost::enable_if_c<!boost::is_same<T, PipelineElement>::value>::type * = 0)
		: m_storage(STD_MOVE(t))
	{ }

public:
	int which() const {
		return m_storage.which();
	}
	template<typename T>
	const T &get() const {
		return boost::get<const T &>(m_storage);
	}
	template<typename T>
	T &get(){
		return boost::get<T &>(m_storage);
	}
};

class ProxySession::Channel : public SecondaryChannel {
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

protected:
	void on_sync_opened() OVERRIDE {
		LOG_POSEIDON_FATAL("OPENED");
	}
	void on_sync_established() OVERRIDE {
		LOG_POSEIDON_FATAL("ESTABLISHED");
	}
	void on_sync_received(Poseidon::StreamBuffer data) OVERRIDE {
		LOG_POSEIDON_FATAL("RECEIVED: ", data);
	}
	void on_sync_closed(long err_code, std::string err_msg) OVERRIDE {
		LOG_POSEIDON_FATAL("CLOSED: ", err_code, ": ", err_msg);
		m_weak_session.reset();
	}
};

class ProxySession::RequestRewriter : NONCOPYABLE, public Poseidon::Http::ServerReader, public Poseidon::Http::ClientWriter {
private:
	ProxySession *const m_session;

public:
	explicit RequestRewriter(ProxySession *session)
		: m_session(session)
	{ }

public:
	// ServerReader
	void on_request_headers(Poseidon::Http::RequestHeaders request_headers, boost::uint64_t content_length) OVERRIDE {
		PROFILE_ME;

		const AUTO(session, m_session->virtual_shared_from_this<ProxySession>());
/*
		AUTO_REF(verb, request_headers.verb);
		AUTO_REF(uri, request_headers.uri);
		AUTO_REF(headers, request_headers.headers);

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
				Poseidon::Http::check_and_throw_if_unauthorized(session->m_auth_info, session->get_remote_info(), request_headers, true);
			}

			std::string host;
			unsigned port = 80;
			bool use_ssl = false;
			bool no_delay = false;

			bool tunnel = false;
			bool keep_alive = true;

			// uri = "http://www.example.com:80/foo/bar/page.html?param=value"
			AUTO(pos, uri.find("://"));
			if(pos != std::string::npos){
				uri.at(pos) = 0;
				LOG_MEDUSA2_TRACE("Request protocol = ", uri.c_str());
				if(::strcasecmp(uri.c_str(), "http") == 0){
					use_ssl = false;
				} else if(::strcasecmp(uri.c_str(), "https") == 0){
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
			if(verb == Poseidon::Http::V_CONNECT){
				no_delay = true;
				tunnel = true;
				keep_alive = true;
			} else {
				int keep_alive_disposal = -1; // -1 auto, 0 disabled, 1 enabled
				const AUTO_REF(proxy_connection, headers.get("Proxy-Connection"));
				Poseidon::Buffer_istream is;
				is.set_buffer(Poseidon::StreamBuffer(proxy_connection));
				Poseidon::Http::HeaderOption opt(is);
				if(is){
					if(::strcasecmp(opt.get_base().c_str(), "Keep-Alive") == 0){
						keep_alive_disposal = 1;
					} else if(::strcasecmp(opt.get_base().c_str(), "Close") == 0){
						keep_alive_disposal = 0;
					}
				}
				if(keep_alive_disposal == -1){
					keep_alive_disposal = request_headers.version >= 10001;
				}
				no_delay = false;
				tunnel = false;
				keep_alive = keep_alive_disposal;
			}

			headers.erase("Prxoy-Authenticate");
			headers.erase("Proxy-Connection");
			headers.erase("Upgrade");
			headers.erase("Connection");

			headers.set(Poseidon::sslit("X-Forwarded-Host"), host);
			headers.set(Poseidon::sslit("Connection"), "Close");

			AUTO(x_forwarded_for, headers.get("X-Forwarded-For"));
			if(!x_forwarded_for.empty()){
				x_forwarded_for += ", ";
			}
			x_forwarded_for += session->get_remote_info().ip();
			headers.set(Poseidon::sslit("X-Forwarded-For"), STD_MOVE(x_forwarded_for));

			const AUTO(channel, boost::make_shared<Channel>(session));
			PipelineElement::RequestHeaders elem = { channel, STD_MOVE(uri), STD_MOVE(headers) };
			session->m_pipeline.emplace_back(STD_MOVE(elem));
			secondary_client->attach_channel(channel, host, port, use_ssl, no_delay);
		} catch(Poseidon::Http::Exception &e){
			LOG_MEDUSA2_WARNING("Poseidon::Http::Exception thrown: status_code = ", e.get_status_code(), ", what = ", e.what());
			session->shutdown_read();
			PipelineElement::Error elem = { e.get_status_code(), e.get_headers(), e.what() };
			session->m_pipeline.emplace_back(STD_MOVE(elem));
		} catch(std::exception &e){
			LOG_MEDUSA2_WARNING("std::exception thrown: what = ", e.what());
			session->shutdown_read();
			PipelineElement::Error elem = { Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, e.what() };
			session->m_pipeline.emplace_back(STD_MOVE(elem));
		}
*/		session->update();
	}
	void on_request_entity(boost::uint64_t /*entity_offset*/, Poseidon::StreamBuffer entity) OVERRIDE {
		PROFILE_ME;

		
	}
	bool on_request_end(boost::uint64_t /*content_length*/, Poseidon::OptionalMap headers) OVERRIDE {
		PROFILE_ME;

		return true;
	}

	// ClientWriter
	long on_encoded_data_avail(Poseidon::StreamBuffer encoded) OVERRIDE {
		PROFILE_ME;

		return true;
	}
};

class ProxySession::ResponseRewriter : NONCOPYABLE, public Poseidon::Http::ClientReader, public Poseidon::Http::ServerWriter {
private:
	ProxySession *const m_session;

public:
	explicit ResponseRewriter(ProxySession *session)
		: m_session(session)
	{ }

public:
	// ClientReader
	void on_response_headers(Poseidon::Http::ResponseHeaders response_headers, boost::uint64_t /*content_length*/) OVERRIDE {
		PROFILE_ME;

		
	}
	void on_response_entity(boost::uint64_t /*entity_offset*/, Poseidon::StreamBuffer entity) OVERRIDE {
		PROFILE_ME;

		
	}
	bool on_response_end(boost::uint64_t /*content_length*/, Poseidon::OptionalMap headers) OVERRIDE {
		PROFILE_ME;

		return true;
	}

	// ServerWriter
	long on_encoded_data_avail(Poseidon::StreamBuffer encoded) OVERRIDE {
		PROFILE_ME;

		return true;
	}
};

class ProxySession::UpdateJob : public Poseidon::JobBase {
private:
	const Poseidon::SocketBase::DelayedShutdownGuard m_guard;
	const boost::weak_ptr<ProxySession> m_weak_session;

	Poseidon::StreamBuffer m_data;
	bool m_read_hup;

public:
	UpdateJob(const boost::shared_ptr<ProxySession> &session, Poseidon::StreamBuffer data, bool read_hup)
		: m_guard(session), m_weak_session(session)
		, m_data(STD_MOVE(data)), m_read_hup(read_hup)
	{ }

private:
	boost::weak_ptr<const void> get_category() const FINAL {
		return m_weak_session;
	}
	void perform() FINAL {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session || session->has_been_shutdown_write()){
			return;
		}

		const AUTO(channel, boost::make_shared<Channel>(session, "www.baidu.com", 443, true, true));
		SecondaryConnector::attach_channel(channel);
		channel->send(Poseidon::StreamBuffer("GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: Close\r\nUser-Agent: test program\r\n\r\n"));
/*		try {
			if(!m_data.empty()){
				AUTO_REF(rewriter, session->m_request_rewriter);
				if(!rewriter){
					rewriter.reset(new RequestRewriter(session.get()));
				}
				rewriter->put_encoded_data(STD_MOVE(m_data));
			}
			if(m_read_hup){
				PipelineElement::EndOfStream elem = { };
				session->m_pipeline.emplace_back(STD_MOVE(elem));
			}
			session->update();
		} catch(std::exception &e){
			LOG_POSEIDON_WARNING("std::exception thrown: remote = ", session->get_remote_info(), ", what = ", e.what());
			session->force_shutdown();
		}
*/	}
};

ProxySession::ProxySession(Poseidon::Move<Poseidon::UniqueFile> socket, boost::shared_ptr<const Poseidon::Http::AuthInfo> auth_info)
	: Poseidon::TcpSessionBase(STD_MOVE(socket))
	, m_session_uuid(Poseidon::Uuid::random()), m_auth_info(STD_MOVE(auth_info))
{
	LOG_MEDUSA2_INFO("ProxySession constructor: remote = ", get_remote_info());
}
ProxySession::~ProxySession(){
	LOG_MEDUSA2_INFO("ProxySession destructor: remote = ", get_remote_info());
}

void ProxySession::update(){
	PROFILE_ME;
	LOG_MEDUSA2_TRACE("Update ProxySession: remote = ", get_remote_info());

	//
}

void ProxySession::on_connect(){
	PROFILE_ME;
	LOG_MEDUSA2_INFO("ProxySession connection established: remote = ", get_remote_info());

	// TODO: blacklist
}
void ProxySession::on_read_hup(){
	PROFILE_ME;
	LOG_MEDUSA2_DEBUG("ProxySession read hung up: remote = ", get_remote_info());

	Poseidon::JobDispatcher::enqueue(
		boost::make_shared<UpdateJob>(virtual_shared_from_this<ProxySession>(), Poseidon::StreamBuffer(), true),
		VAL_INIT);
}
void ProxySession::on_close(int err_code){
	PROFILE_ME;
	LOG_MEDUSA2_INFO("ProxySession connection closed: remote = ", get_remote_info(), ", err_code = ", err_code);

	//
}
void ProxySession::on_receive(Poseidon::StreamBuffer data){
	PROFILE_ME;
	LOG_MEDUSA2_TRACE("ProxySession received data: remote = ", get_remote_info(), ", data.size() = ", data.size());

	Poseidon::JobDispatcher::enqueue(
		boost::make_shared<UpdateJob>(virtual_shared_from_this<ProxySession>(), STD_MOVE(data), false),
		VAL_INIT);
}

}
}
