#ifndef MEDUSA2_PRIMARY_PROXY_SESSION_HPP_
#define MEDUSA2_PRIMARY_PROXY_SESSION_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/tcp_session_base.hpp>
#include <poseidon/uuid.hpp>
#include <poseidon/http/fwd.hpp>

namespace Medusa2 {
namespace Primary {

class ProxySession : public Poseidon::TcpSessionBase {
private:
	class RequestJobBase;
	class HttpRequestHeaderJob;
	class HttpRequestEntityJob;
	class HttpRequestEndJob;
	class HttpRequestErrorJob;
	class HttpTunnelDataJob;

	class RequestRewriter;
	class ResponseRewriter;

private:
	const Poseidon::Uuid m_session_uuid;
	const boost::shared_ptr<const Poseidon::Http::AuthInfo> m_auth_info;

	boost::scoped_ptr<RequestRewriter> m_request_rewriter;
	boost::scoped_ptr<ResponseRewriter> m_response_rewriter;

public:
	ProxySession(Poseidon::Move<Poseidon::UniqueFile> socket, boost::shared_ptr<const Poseidon::Http::AuthInfo> auth_info);
	~ProxySession();

protected:
	void on_connect() OVERRIDE;
	void on_read_hup() OVERRIDE;
	void on_close(int err_code) OVERRIDE;
	void on_receive(Poseidon::StreamBuffer data) OVERRIDE;

public:
	const Poseidon::Uuid &get_session_uuid() const NOEXCEPT {
		return m_session_uuid;
	}

	void on_sync_opened(const Poseidon::Uuid &channel_uuid);
	void on_sync_established(const Poseidon::Uuid &channel_uuid);
	void on_sync_received(const Poseidon::Uuid &channel_uuid, std::basic_string<unsigned char> segment);
	void on_sync_closed(const Poseidon::Uuid &channel_uuid, long err_code, std::string err_msg);
};

}
}

#endif
