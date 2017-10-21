#ifndef MEDUSA2_PRIMARY_PROXY_SESSION_HPP_
#define MEDUSA2_PRIMARY_PROXY_SESSION_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/tcp_session_base.hpp>
#include <poseidon/uuid.hpp>
#include <poseidon/http/fwd.hpp>
#include <boost/container/deque.hpp>

namespace Medusa2 {
namespace Primary {

class SecondaryClient;

class ProxySession : public Poseidon::TcpSessionBase {
private:
	class PipelineElement;
	class Channel;

	class RequestRewriter;
	class ResponseRewriter;
	class UpdateJob;

private:
	const Poseidon::Uuid m_session_uuid;
	const boost::shared_ptr<const Poseidon::Http::AuthInfo> m_auth_info;
	const boost::weak_ptr<SecondaryClient> m_weak_secondary_client;

	boost::container::deque<PipelineElement> m_pipeline;
	boost::scoped_ptr<RequestRewriter> m_request_rewriter;
	boost::scoped_ptr<ResponseRewriter> m_response_rewriter;

public:
	ProxySession(Poseidon::Move<Poseidon::UniqueFile> socket, boost::shared_ptr<const Poseidon::Http::AuthInfo> auth_info);
	~ProxySession();

private:
	void update();

protected:
	void on_connect() OVERRIDE;
	void on_read_hup() OVERRIDE;
	void on_close(int err_code) OVERRIDE;
	void on_receive(Poseidon::StreamBuffer data) OVERRIDE;

public:
	const Poseidon::Uuid &get_session_uuid() const NOEXCEPT {
		return m_session_uuid;
	}
};

}
}

#endif
