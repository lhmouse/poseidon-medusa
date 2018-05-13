// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#include "precompiled.hpp"
#include "proxy_session.hpp"
#include "singletons/secondary_connector.hpp"
#include "secondary_channel.hpp"
#include "mmain.hpp"
#include "protocol/error_codes.hpp"
#include <poseidon/http/authentication.hpp>
#include <poseidon/http/exception.hpp>
#include <poseidon/http/upgraded_session_base.hpp>
#include <poseidon/http/client_reader.hpp>
#include <poseidon/http/client_writer.hpp>
#include <poseidon/job_base.hpp>

namespace Medusa2 {
namespace Primary {

class Proxy_session::Tunnel_session : public Poseidon::Http::Upgraded_session_base {
public:
	explicit Tunnel_session(const boost::shared_ptr<Proxy_session> &session)
		: Poseidon::Http::Upgraded_session_base(session)
	{
		//
	}

protected:
	void on_connect() OVERRIDE {
		LOG_MEDUSA2_DEBUG("Tunnel_session::on_connect()");
	}
	void on_read_hup() OVERRIDE {
		LOG_MEDUSA2_DEBUG("Tunnel_session::on_read_hup()");
	}
	void on_close(int err_code) OVERRIDE {
		LOG_MEDUSA2_DEBUG("Tunnel_session::on_close(): err_code = ", err_code);
	}
	void on_receive(Poseidon::Stream_buffer data) OVERRIDE {
		LOG_MEDUSA2_DEBUG("Tunnel_session::on_receive(): data.size() = ", data.size());

		const AUTO(session, boost::dynamic_pointer_cast<Proxy_session>(get_parent()));
		if(!session){
			return;
		}

		session->low_level_enqueue_tunnel_data(STD_MOVE(data));
	}
};

class Proxy_session::Deaf_session : public Poseidon::Http::Upgraded_session_base {
public:
	explicit Deaf_session(const boost::shared_ptr<Proxy_session> &session)
		: Poseidon::Http::Upgraded_session_base(session)
	{
		//
	}

protected:
	void on_connect() OVERRIDE {
		LOG_MEDUSA2_DEBUG("Deaf_session::on_connect()");
	}
	void on_read_hup() OVERRIDE {
		LOG_MEDUSA2_DEBUG("Deaf_session::on_read_hup()");
	}
	void on_close(int err_code) OVERRIDE {
		LOG_MEDUSA2_DEBUG("Deaf_session::on_close(): err_code = ", err_code);
	}
	void on_receive(Poseidon::Stream_buffer data) OVERRIDE {
		LOG_MEDUSA2_DEBUG("Deaf_session::on_receive(): data.size() = ", data.size());
	}
};

class Proxy_session::Channel : public Secondary_channel, public Poseidon::Http::Client_writer, public Poseidon::Http::Client_reader {
private:
	boost::weak_ptr<Proxy_session> m_weak_session;
	bool m_tunnel;
	bool m_chunked;

public:
	Channel(const boost::shared_ptr<Proxy_session> &session, std::string host, unsigned port, bool use_ssl, bool no_delay, bool tunnel)
		: Secondary_channel(STD_MOVE(host), port, use_ssl, no_delay)
		, m_weak_session(session), m_tunnel(tunnel), m_chunked(false)
	{
		//
	}
	~Channel(){
		const AUTO(session, m_weak_session.lock());
		if(session){
			LOG_MEDUSA2_DEBUG("Channel was not shut down cleanly: channel_uuid = ", get_channel_uuid());
			session->force_shutdown();
		}
	}

private:
	void sync_unlink_and_shutdown(bool no_linger) NOEXCEPT {
		PROFILE_ME;

		m_weak_session.reset();

		shutdown(no_linger);
	}

protected:
	// Secondary_channel
	void on_sync_opened() OVERRIDE {
		LOG_MEDUSA2_DEBUG("Channel::on_sync_opened()");
	}
	void on_sync_established() OVERRIDE {
		LOG_MEDUSA2_DEBUG("Channel::on_sync_established()");

		const AUTO(session, m_weak_session.lock());
		if(!session){
			LOG_MEDUSA2_DEBUG("Proxy client had disconnected before the connection to the origin server could be established.");
			shutdown(true);
			return;
		}

		if(m_tunnel){
			const AUTO(tunnel_session, boost::dynamic_pointer_cast<Tunnel_session>(session->get_upgraded_session()));
			DEBUG_THROW_ASSERT(tunnel_session);
			Poseidon::Http::Response_headers response_headers;
			response_headers.version     = 10001;
			response_headers.status_code = Poseidon::Http::status_ok;
			response_headers.reason      = "Connection Established";
			response_headers.headers.set(Poseidon::Rcnts::view("Proxy-Connection"), "Keep-Alive");
			if(!session->sync_get_response_token()){
				sync_unlink_and_shutdown(true);
				return;
			}
			session->send(STD_MOVE(response_headers));
		} else {
			// Do nothing.
		}
	}
	void on_sync_received(Poseidon::Stream_buffer data) OVERRIDE {
		LOG_MEDUSA2_DEBUG("Channel::on_sync_received(): data.size() = ", data.size());

		const AUTO(session, m_weak_session.lock());
		if(!session){
			LOG_MEDUSA2_DEBUG("Proxy client had disconnected while there are still some data to be transmitted.");
			shutdown(true);
			return;
		}

		if(m_tunnel){
			const AUTO(tunnel_session, boost::dynamic_pointer_cast<Tunnel_session>(session->get_upgraded_session()));
			DEBUG_THROW_ASSERT(tunnel_session);
			tunnel_session->send(STD_MOVE(data));
		} else {
			const AUTO(deaf_session, boost::dynamic_pointer_cast<Deaf_session>(session->get_upgraded_session()));
			DEBUG_THROW_ASSERT(deaf_session);
			try {
				put_encoded_data(STD_MOVE(data));
			} catch(std::exception &e){
				LOG_MEDUSA2_WARNING("std::exception thrown while parsing response from the origin server: what = ", e.what());
				sync_unlink_and_shutdown(true);
				session->sync_pretty_shutdown(Poseidon::Http::status_bad_gateway, Protocol::error_origin_invalid_http_response, "The origin server sent no valid HTTP response");
			}
		}

		const AUTO(timeout, get_config<boost::uint64_t>("proxy_session_timeout", 300000));
		session->set_timeout(timeout);
	}
	void on_sync_closed(long err_code, std::string err_msg) OVERRIDE {
		LOG_MEDUSA2_DEBUG("Channel::on_sync_closed(): err_code = ", err_code, ", err_msg = ", err_msg);

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}

		if(m_tunnel){
			const AUTO(tunnel_session, boost::dynamic_pointer_cast<Tunnel_session>(session->get_upgraded_session()));
			DEBUG_THROW_ASSERT(tunnel_session);
			session->sync_pretty_shutdown(Poseidon::Http::status_bad_gateway, err_code, err_msg.c_str());
		} else {
			const AUTO(deaf_session, boost::dynamic_pointer_cast<Deaf_session>(session->get_upgraded_session()));
			DEBUG_THROW_ASSERT(deaf_session);
			if(is_content_till_eof()){
				terminate_content();
			}
			session->sync_pretty_shutdown(Poseidon::Http::status_bad_gateway, (err_code == 0) ? static_cast<long>(Protocol::error_origin_empty_response) : err_code, (err_code == 0) ? "The origin server sent no data" : err_msg.c_str());
		}
	}

	// Client_writer
	long on_encoded_data_avail(Poseidon::Stream_buffer encoded) OVERRIDE {
		PROFILE_ME;

		return send(STD_MOVE(encoded));
	}

	// Client_reader
	void on_response_headers(Poseidon::Http::Response_headers response_headers, boost::uint64_t /*content_length*/) OVERRIDE {
		PROFILE_ME;

		m_chunked = response_headers.status_code / 100 >= 2;

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}
		DEBUG_THROW_ASSERT(!m_tunnel);

		const AUTO(deaf_session, boost::dynamic_pointer_cast<Deaf_session>(session->get_upgraded_session()));
		DEBUG_THROW_ASSERT(deaf_session);
		if(!session->sync_get_response_token()){
			sync_unlink_and_shutdown(true);
			return;
		}
		response_headers.headers.erase("Prxoy-Authenticate");
		response_headers.headers.erase("Proxy-Connection");
		response_headers.headers.erase("Proxy-Authentication-Info");
		response_headers.headers.set(Poseidon::Rcnts::view("Connection"), "Close");
		response_headers.headers.set(Poseidon::Rcnts::view("Proxy-Connection"), "Close");
		if(m_chunked){
			const AUTO_REF(transfer_encoding, response_headers.headers.get("Transfer-Encoding"));
			if(transfer_encoding.empty() || (::strcasecmp(transfer_encoding.c_str(), "identity") == 0)){
				response_headers.headers.set(Poseidon::Rcnts::view("Transfer-Encoding"), "chunked");
			}
			session->send_chunked_header(STD_MOVE(response_headers));
		} else {
			session->send(STD_MOVE(response_headers));
		}
	}
	void on_response_entity(boost::uint64_t /*entity_offset*/, Poseidon::Stream_buffer entity) OVERRIDE {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}
		DEBUG_THROW_ASSERT(!m_tunnel);

		const AUTO(deaf_session, boost::dynamic_pointer_cast<Deaf_session>(session->get_upgraded_session()));
		DEBUG_THROW_ASSERT(deaf_session);
		if(m_chunked){
			if(!entity.empty()){
				session->send_chunk(STD_MOVE(entity));
			}
		} else {
			// Do nothing.
		}
	}
	bool on_response_end(boost::uint64_t /*content_length*/, Poseidon::Option_map headers) OVERRIDE {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return false;
		}
		DEBUG_THROW_ASSERT(!m_tunnel);

		const AUTO(deaf_session, boost::dynamic_pointer_cast<Deaf_session>(session->get_upgraded_session()));
		DEBUG_THROW_ASSERT(deaf_session);
		if(m_chunked){
			session->send_chunked_trailer(STD_MOVE(headers));
		} else {
			// Do nothing.
		}
		sync_unlink_and_shutdown(false);
		return false;
	}
};

class Proxy_session::Sync_job_base : public Poseidon::Job_base {
private:
	const Poseidon::Socket_base::Delayed_shutdown_guard m_guard;
	const boost::weak_ptr<Proxy_session> m_weak_session;

public:
	explicit Sync_job_base(const boost::shared_ptr<Proxy_session> &session)
		: m_guard(session), m_weak_session(session)
	{
		//
	}

protected:
	boost::weak_ptr<const void> get_category() const FINAL {
		return m_weak_session;
	}
	void perform() FINAL {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}

		try {
			really_perform(session);
		} catch(std::exception &e){
			LOG_MEDUSA2_WARNING("std::exception thrown: remote = ", session->get_remote_info(), ", what = ", e.what());
			session->force_shutdown();
		}
	}

	virtual void really_perform(const boost::shared_ptr<Proxy_session> &session) = 0;
};

class Proxy_session::Request_headers_job : public Proxy_session::Sync_job_base {
private:
	Poseidon::Http::Request_headers m_request_headers;
	bool m_tunnel;
	bool m_chunked;

public:
	Request_headers_job(const boost::shared_ptr<Proxy_session> &session, Poseidon::Http::Request_headers request_headers, bool tunnel, bool chunked)
		: Sync_job_base(session)
		, m_request_headers(STD_MOVE(request_headers)), m_tunnel(tunnel), m_chunked(chunked)
	{
		//
	}

protected:
	void really_perform(const boost::shared_ptr<Proxy_session> &session) FINAL {
		PROFILE_ME;

		if(session->has_been_shutdown_write()){
			return;
		}

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
				DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::status_forbidden);
			}

			LOG_MEDUSA2_INFO("New fetch request from ", session->get_remote_info());
			LOG_MEDUSA2_INFO(">> ", Poseidon::Http::get_string_from_verb(verb), " ", uri);
			LOG_MEDUSA2_INFO(">> Request headers: ", headers);

			const AUTO_REF(proxy_authorization_str, headers.get("Proxy-Authorization"));
			const AUTO(result, Poseidon::Http::check_authentication_digest(session->m_auth_ctx, session->get_remote_info(), verb, proxy_authorization_str));
			if(result.first != Poseidon::Http::auth_succeeded){
				LOG_MEDUSA2_DEBUG("Authentication failed: ", proxy_authorization_str);
				Poseidon::Http::throw_authentication_failure_digest(session->m_auth_ctx, true, session->get_remote_info(), result.first);
			}

			std::string host;
			boost::uint16_t port = 80;
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
					DEBUG_THROW(Poseidon::Exception, Poseidon::Rcnts::view("Unsupported protocol"));
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
				DEBUG_THROW_UNLESS(pos != std::string::npos, Poseidon::Exception, Poseidon::Rcnts::view("Invalid IPv6 address"));
				pos = host.find(':', pos + 1);
			} else {
				pos = host.find(':');
			}
			if(pos != std::string::npos){
				char *endptr;
				const unsigned long port_val = std::strtoul(host.c_str() + pos + 1, &endptr, 10);
				DEBUG_THROW_UNLESS(*endptr == 0, Poseidon::Exception, Poseidon::Rcnts::view("Invalid port string"));
				DEBUG_THROW_UNLESS((1 <= port_val) && (port_val <= 65534), Poseidon::Exception, Poseidon::Rcnts::view("Invalid port number"));
				port = boost::numeric_cast<boost::uint16_t>(port_val);
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
				headers.erase("Proxy-Authentication-Info");
				headers.set(Poseidon::Rcnts::view("Connection"), "Close");
				headers.set(Poseidon::Rcnts::view("X-Forwarded-Host"), host);

				AUTO(x_forwarded_for, headers.get("X-Forwarded-For"));
				if(!x_forwarded_for.empty()){
					x_forwarded_for += ", ";
				}
				x_forwarded_for += session->get_remote_info().ip();
				headers.set(Poseidon::Rcnts::view("X-Forwarded-For"), STD_MOVE(x_forwarded_for));
			}

			channel = boost::make_shared<Channel>(session, STD_MOVE(host), port, use_ssl, no_delay, m_tunnel);
			Secondary_connector::attach_channel(channel);
			session->m_weak_channel = channel;

			if(m_tunnel){
				// Do nothing.
			} else {
				Poseidon::Http::Request_headers rewritten_headers;
				rewritten_headers.verb    = verb;
				rewritten_headers.uri     = STD_MOVE(uri);
				rewritten_headers.version = 10001;
				rewritten_headers.headers = STD_MOVE(headers);
				if(m_chunked){
					channel->put_chunked_header(STD_MOVE(rewritten_headers));
				} else {
					channel->put_request(STD_MOVE(rewritten_headers), VAL_INIT, false);
				}
			}

			const AUTO(timeout, get_config<boost::uint64_t>("proxy_session_timeout", 300000));
			session->set_timeout(timeout);
		} catch(Poseidon::Http::Exception &e){
			LOG_MEDUSA2_WARNING("Http::Exception thrown: remote = ", session->get_remote_info(), ", status_code = ", e.get_status_code(), ", what = ", e.what());
			session->sync_pretty_shutdown(e.get_status_code(), Protocol::error_connection_cancelled, e.what(), e.get_headers());
		} catch(std::exception &e){
			LOG_MEDUSA2_WARNING("std::exception thrown: remote = ", session->get_remote_info(), ", what = ", e.what());
			session->sync_pretty_shutdown(Poseidon::Http::status_bad_gateway, Protocol::error_connection_cancelled, e.what(), VAL_INIT);
		}
	}
};

class Proxy_session::Request_entity_job : public Proxy_session::Sync_job_base {
private:
	bool m_chunked;
	Poseidon::Stream_buffer m_entity;

public:
	Request_entity_job(const boost::shared_ptr<Proxy_session> &session, bool chunked, Poseidon::Stream_buffer entity)
		: Sync_job_base(session)
		, m_chunked(chunked), m_entity(STD_MOVE(entity))
	{
		//
	}

protected:
	void really_perform(const boost::shared_ptr<Proxy_session> &session) FINAL {
		PROFILE_ME;

		if(session->has_been_shutdown_write()){
			return;
		}
		const AUTO(channel, session->m_weak_channel.lock());
		if(!channel){
			return;
		}
		if(!m_entity.empty()){
			if(m_chunked){
				channel->put_chunk(STD_MOVE(m_entity));
			} else {
				channel->send(STD_MOVE(m_entity));
			}
		}
	}
};

class Proxy_session::Request_end_job : public Proxy_session::Sync_job_base {
private:
	bool m_chunked;
	Poseidon::Option_map m_headers;

public:
	Request_end_job(const boost::shared_ptr<Proxy_session> &session, bool chunked, Poseidon::Option_map headers)
		: Sync_job_base(session)
		, m_chunked(chunked), m_headers(STD_MOVE(headers))
	{
		//
	}

protected:
	void really_perform(const boost::shared_ptr<Proxy_session> &session) FINAL {
		PROFILE_ME;

		if(session->has_been_shutdown_write()){
			return;
		}
		const AUTO(channel, session->m_weak_channel.lock());
		if(!channel){
			return;
		}
		if(m_chunked){
			channel->put_chunked_trailer(STD_MOVE(m_headers));
		} else {
			// Do nothing
		}
	}
};

class Proxy_session::Read_hup_job : public Proxy_session::Sync_job_base {
private:
	const boost::shared_ptr<Proxy_session> m_session;

public:
	explicit Read_hup_job(const boost::shared_ptr<Proxy_session> &session)
		: Sync_job_base(session)
		, m_session(session)
	{
		//
	}

protected:
	void really_perform(const boost::shared_ptr<Proxy_session> &session) FINAL {
		PROFILE_ME;

		session->shutdown_write();

		const AUTO(channel, session->m_weak_channel.lock());
		if(channel){
			channel->shutdown(false);
		}
	}
};

class Proxy_session::Close_job : public Proxy_session::Sync_job_base {
private:
	const boost::shared_ptr<Proxy_session> m_session;
	const int m_err_code;

public:
	Close_job(const boost::shared_ptr<Proxy_session> &session, int err_code)
		: Sync_job_base(session)
		, m_session(session), m_err_code(err_code)
	{
		//
	}

protected:
	void really_perform(const boost::shared_ptr<Proxy_session> &session) FINAL {
		PROFILE_ME;

		const AUTO(channel, session->m_weak_channel.lock());
		if(channel){
			channel->shutdown(true);
		}
		session->m_weak_channel.reset();
	}
};

Proxy_session::Proxy_session(Poseidon::Move<Poseidon::Unique_file> socket, boost::shared_ptr<const Poseidon::Http::Authentication_context> auth_ctx)
	: Poseidon::Http::Low_level_session(STD_MOVE(socket))
	, m_auth_ctx(STD_MOVE(auth_ctx))
	, m_tunnel(false), m_chunked(false)
	, m_weak_channel(), m_response_token(false)
{
	LOG_MEDUSA2_INFO("Proxy_session constructor: remote = ", get_remote_info());
}
Proxy_session::~Proxy_session(){
	LOG_MEDUSA2_INFO("Proxy_session destructor: remote = ", get_remote_info());

	const AUTO(channel, m_weak_channel.lock());
	if(channel){
		LOG_MEDUSA2_DEBUG("Channel was not shut down cleanly: channel_uuid = ", channel->get_channel_uuid());
		channel->shutdown(true);
	}
}

bool Proxy_session::sync_get_response_token() NOEXCEPT {
	PROFILE_ME;

	if(m_response_token){
		return false;
	}
	m_response_token = true;
	return true;
}
void Proxy_session::sync_pretty_shutdown(unsigned status_code, long err_code, const char *err_msg, const Poseidon::Option_map &headers) NOEXCEPT
try {
	PROFILE_ME;

	if(sync_get_response_token()){
		Poseidon::Http::Response_headers response_headers;
		response_headers.version = 10001;
		response_headers.status_code = status_code;
		response_headers.reason = Poseidon::Http::get_status_code_desc(status_code).desc_short;
		response_headers.headers = headers;
		response_headers.headers.erase("Transfer-Encoding");
		response_headers.headers.erase("Content-Encoding");
		response_headers.headers.set(Poseidon::Rcnts::view("Connection"), "Close");
		response_headers.headers.set(Poseidon::Rcnts::view("Proxy-Connection"), "Close");
		response_headers.headers.set(Poseidon::Rcnts::view("Content-Type"), "text/html; charset=utf-8");
		Poseidon::Buffer_ostream entity_os;
		entity_os <<"<html>"
		          <<  "<head>"
		          <<    "<title>" <<response_headers.status_code <<" " <<response_headers.reason <<"</title>"
		          <<  "</head>"
		          <<  "<body>"
		          <<    "<h1>" <<response_headers.status_code <<" " <<response_headers.reason <<"</h1>"
		          <<    "<hr />"
		          <<    "<p>Error " <<err_code <<": ";
		if(!err_msg || !*err_msg){
			err_msg = "No reason given";
		}
		const char *read = err_msg;
		int last = -1;
		for(;;){
			const int ch = static_cast<unsigned char>(*(read++));
			if(ch == 0){
				break;
			}
			switch(ch){
			case '<':
				entity_os <<"&lt;";
				break;
			case '>':
				entity_os <<"&gt;";
				break;
			case '&':
				entity_os <<"&amp;";
				break;
			case '\"':
				entity_os <<"&quot;";
				break;
			case '\'':
				entity_os <<"&apos;";
				break;
			default:
				entity_os <<static_cast<char>(ch);
				break;
			}
			last = ch;
		}
		if(std::isalnum(last)){
			entity_os <<'.';
		}
		entity_os <<    "</p>"
		          <<  "</body>"
		          <<"</html>";
		Poseidon::Http::Server_writer::put_response(STD_MOVE(response_headers), STD_MOVE(entity_os.get_buffer()), true);
	}
	shutdown_read();
	shutdown_write();
} catch(std::exception &e){
	LOG_MEDUSA2_ERROR("std::exception remote = ", get_remote_info(), ", thrown: what = ", e.what());
	force_shutdown();
}
void Proxy_session::low_level_enqueue_tunnel_data(Poseidon::Stream_buffer data){
	PROFILE_ME;

	Poseidon::enqueue(boost::make_shared<Request_entity_job>(virtual_shared_from_this<Proxy_session>(), false, STD_MOVE(data)));
}

void Proxy_session::on_read_hup(){
	PROFILE_ME;

	Poseidon::enqueue(boost::make_shared<Read_hup_job>(virtual_shared_from_this<Proxy_session>()));

	Poseidon::Http::Low_level_session::on_read_hup();
}
void Proxy_session::on_close(int err_code){
	PROFILE_ME;

	Poseidon::enqueue(boost::make_shared<Close_job>(virtual_shared_from_this<Proxy_session>(), err_code));

	Poseidon::Http::Low_level_session::on_close(err_code);
}

void Proxy_session::on_low_level_request_headers(Poseidon::Http::Request_headers request_headers, boost::uint64_t content_length){
	PROFILE_ME;

	m_tunnel = request_headers.verb == Poseidon::Http::verb_connect;
	m_chunked = content_length == Poseidon::Http::Server_reader::content_length_chunked;

	Poseidon::enqueue(boost::make_shared<Request_headers_job>(virtual_shared_from_this<Proxy_session>(), STD_MOVE(request_headers), m_tunnel, m_chunked));
}
void Proxy_session::on_low_level_request_entity(boost::uint64_t /*entity_offset*/, Poseidon::Stream_buffer entity){
	PROFILE_ME;

	if(m_tunnel){
		// Do nothing.
	} else {
		Poseidon::enqueue(boost::make_shared<Request_entity_job>(virtual_shared_from_this<Proxy_session>(), m_chunked, STD_MOVE(entity)));
	}
}
boost::shared_ptr<Poseidon::Http::Upgraded_session_base> Proxy_session::on_low_level_request_end(boost::uint64_t /*content_length*/, Poseidon::Option_map headers){
	PROFILE_ME;

	if(m_tunnel){
		return boost::make_shared<Tunnel_session>(virtual_shared_from_this<Proxy_session>());
	} else {
		Poseidon::enqueue(boost::make_shared<Request_end_job>(virtual_shared_from_this<Proxy_session>(), m_chunked, STD_MOVE(headers)));
		return boost::make_shared<Deaf_session>(virtual_shared_from_this<Proxy_session>());
	}
}

}
}
