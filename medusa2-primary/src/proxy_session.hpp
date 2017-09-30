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
	class RequestRewriter;
	class ResponseRewriter;

	class RequestJobBase;
	class DataReceivedJob;
	class ReadHupJob;

private:
	const Poseidon::Uuid m_session_uuid;
	const boost::shared_ptr<const Poseidon::Http::AuthInfo> m_auth_info;

	boost::shared_ptr<RequestRewriter> m_request_rewriter;
	boost::shared_ptr<ResponseRewriter> m_response_rewriter;

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

	void on_fetch_opened(std::basic_string<unsigned char> opaque);
	void on_fetch_established();
	void on_fetch_received(std::basic_string<unsigned char> segment);
	void on_fetch_closed(long err_code, std::string err_msg);
};

}
}

#endif
