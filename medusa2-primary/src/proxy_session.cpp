#include "precompiled.hpp"
#include "proxy_session.hpp"
#include "singletons/proxy_server.hpp"
#include "singletons/secondary_connector.hpp"
#include <poseidon/job_base.hpp>
#include <poseidon/singletons/job_dispatcher.hpp>
#include <poseidon/http/status_codes.hpp>
#include <poseidon/http/exception.hpp>
#include <poseidon/http/server_reader.hpp>
#include <poseidon/http/client_writer.hpp>
#include <poseidon/http/client_reader.hpp>
#include <poseidon/http/server_writer.hpp>

namespace Medusa2 {
namespace Primary {

struct ProxySession::RequestPending {
	enum {
		STATUS_EARLY_FAILURE    = 0,
		STATUS_CHANNEL_OPENED   = 1,
		STATUS_CHANNEL_CLOSED   = 2,
		STATUS_REQUEST_CHUNKED  = 3,
		STATUS_RESPONSE_CHUNKED = 4,
		STATUS_REQUEST_ENDED    = 5,
		STATUS_RESPONSE_ENDED   = 6,
	};

	enum {
		OPTION_KEEP_ALIVE = 0,
		OPTION_TUNNEL     = 1,
		OPTION_USE_SSL    = 2,
		OPTION_NO_DELAY   = 3,
	};

	std::bitset<32> status;
	Poseidon::Uuid channel_uuid;
	Poseidon::Http::ResponseHeaders failure_headers;

	std::bitset<32> options;
	std::string host;
	unsigned port;
	Poseidon::Http::RequestHeaders request_headers;
	Poseidon::StreamBuffer entity;
	Poseidon::OptionalMap chunked_trailer;
};

class ProxySession::RequestRewriter : public Poseidon::Http::ServerReader, public Poseidon::Http::ClientWriter {
private:
	const boost::weak_ptr<ProxySession> m_weak_session;

public:
	explicit RequestRewriter(const boost::shared_ptr<ProxySession> &session)
		: m_weak_session(session)
	{ }

protected:
	// ServerReader
	void on_request_headers(Poseidon::Http::RequestHeaders request_headers, boost::uint64_t /*content_length*/) OVERRIDE {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		DEBUG_THROW_ASSERT(session);

		
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

class ProxySession::ResponseRewriter : public Poseidon::Http::ClientReader, public Poseidon::Http::ServerWriter {
private:
	const boost::weak_ptr<ProxySession> m_weak_session;

public:
	explicit ResponseRewriter(const boost::shared_ptr<ProxySession> &session)
		: m_weak_session(session)
	{ }

protected:
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

class ProxySession::RequestJobBase : public Poseidon::JobBase {
private:
	const Poseidon::SocketBase::DelayedShutdownGuard m_guard;
	const boost::weak_ptr<ProxySession> m_weak_session;

protected:
	explicit RequestJobBase(const boost::shared_ptr<ProxySession> &session)
		: m_guard(session), m_weak_session(session)
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

		try {
			really_perform(session);
		} catch(std::exception &e){
			LOG_POSEIDON_WARNING("std::exception thrown: remote = ", session->get_remote_info(), ", what = ", e.what());
			session->force_shutdown();
		}
	}

protected:
	virtual void really_perform(const boost::shared_ptr<ProxySession> &session) = 0;
};

class ProxySession::DataReceivedJob : public ProxySession::RequestJobBase {
private:
	Poseidon::StreamBuffer m_data;

public:
	DataReceivedJob(const boost::shared_ptr<ProxySession> &session, Poseidon::StreamBuffer data)
		: RequestJobBase(session)
		, m_data(STD_MOVE(data))
	{ }

protected:
	void really_perform(const boost::shared_ptr<ProxySession> &session) OVERRIDE {
		PROFILE_ME;
/*
		AUTO(request_rewriter, session->m_request_rewriter);
		if(!request_rewriter){
			request_rewriter = boost::make_shared<RequestRewriter>(session);
			session->m_request_rewriter = request_rewriter;
		}
		
		proxy_fragmentation_size = 15360
		proxy_max_queue_size = 1048576
		proxy_max_pipelined_request_count = 16




		
		if(!(session->m_request_rewriter)){
			session->m_request_rewriter = boost::make_shared<RequestRewriter>(session);
		}
		session->m_request_rewriter->put_encoded_data(STD_MOVE(m_data));
	} catch(Poseidon::Http::Exception &e){
		LOG_MEDUSA2_WARNING("Http::Exception thrown: remote = ", session->get_remote_info(), ", status_code = ", e.get_status_code(), ", what = ", e.what());

		AUTO_REF(requests_pending, session->m_requests_pending);
		RequestPending req = { };
		req.status.set(RequestPending::STATUS_EARLY_FAILURE);
		req.failure_headers.status_code = e.get_status_code();
		req.failure_headers.headers = e.get_headers();
		req.entity.put(e.what());
		if(!requests_pending.empty() && !requests_pending.back().status.test(RequestPending::STATUS_REQUEST_ENDED)){
			requests_pending.pop_back();
		}
		requests_pending.push_back(STD_MOVE(req));

		session->shutdown_read();
		session->update();
	} catch(std::exception &e){
		LOG_MEDUSA2_ERROR("std::exception thrown: remote = ", session->get_remote_info(), ", what = ", e.what());

		AUTO_REF(requests_pending, session->m_requests_pending);
		RequestPending req = { };
		req.status.set(RequestPending::STATUS_EARLY_FAILURE);
		req.failure_headers.status_code = Poseidon::Http::ST_BAD_GATEWAY;
		req.entity.put(e.what());
		if(!requests_pending.empty() && !requests_pending.back().status.test(RequestPending::STATUS_REQUEST_ENDED)){
			requests_pending.pop_back();
		}
		requests_pending.push_back(STD_MOVE(req));

		session->shutdown_read();
		session->update();
*/
	}
};

class ProxySession::ReadHupJob : public ProxySession::RequestJobBase {
public:
	explicit ReadHupJob(const boost::shared_ptr<ProxySession> &session)
		: RequestJobBase(session)
	{ }

protected:
	void really_perform(const boost::shared_ptr<ProxySession> &session) OVERRIDE {
		PROFILE_ME;

		session->m_request_rewriter.reset();
		session->shutdown_write();
	}
};

ProxySession::ProxySession(Poseidon::Move<Poseidon::UniqueFile> socket, boost::shared_ptr<const Poseidon::Http::AuthInfo> auth_info)
	: Poseidon::TcpSessionBase(STD_MOVE(socket))
	, m_session_uuid(Poseidon::Uuid::random()), m_auth_info(STD_MOVE(auth_info))
{
	LOG_MEDUSA2_INFO("ProxySession constructor: remote = ", get_remote_info());
}
ProxySession::~ProxySession(){
	LOG_MEDUSA2_INFO("ProxySession destructor: remote = ", get_remote_info());
	ProxyServer::remove_session(this);
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
		boost::make_shared<ReadHupJob>(virtual_shared_from_this<ProxySession>()),
		VAL_INIT);
}
void ProxySession::on_close(int err_code){
	PROFILE_ME;
	LOG_MEDUSA2_INFO("ProxySession connection closed: remote = ", get_remote_info(), ", err_code = ", err_code);

	m_request_rewriter.reset();
}
void ProxySession::on_receive(Poseidon::StreamBuffer data){
	PROFILE_ME;
	LOG_MEDUSA2_TRACE("ProxySession received data: remote = ", get_remote_info(), ", data.size() = ", data.size());

	Poseidon::JobDispatcher::enqueue(
		boost::make_shared<DataReceivedJob>(virtual_shared_from_this<ProxySession>(), STD_MOVE(data)),
		VAL_INIT);
}

void ProxySession::on_fetch_opened(const std::bitset<32> &options){
	PROFILE_ME;

	LOG_POSEIDON_FATAL("OPENED: ", get_session_uuid(), ": ", options);
}
void ProxySession::on_fetch_established(){
	PROFILE_ME;

	LOG_POSEIDON_FATAL("ESTABLISHED: ", get_session_uuid());
}
void ProxySession::on_fetch_received(std::basic_string<unsigned char> segment){
	PROFILE_ME;

	LOG_POSEIDON_ERROR("RECEIVED: ", get_session_uuid(), ": ", (const char *)segment.c_str());
}
void ProxySession::on_fetch_closed(long err_code, std::string err_msg){
	PROFILE_ME;

	LOG_POSEIDON_FATAL("CLOSED: ", get_session_uuid(), ": ", err_code, " (", err_msg, ")");
}

}
}
