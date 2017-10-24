#ifndef MEDUSA2_PRIMARY_PROXY_SESSION_HPP_
#define MEDUSA2_PRIMARY_PROXY_SESSION_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/http/fwd.hpp>
#include <poseidon/http/low_level_session.hpp>

namespace Medusa2 {
namespace Primary {

class ProxySession : public Poseidon::Http::LowLevelSession {
private:
	class TunnelSession;
	class DeafSession;
	class Channel;

	class SyncJobBase;
	class RequestHeadersJob;
	class RequestEntityJob;
	class RequestEndJob;
	class ReadHupJob;

private:
	const boost::shared_ptr<const Poseidon::Http::AuthInfo> m_auth_info;

	// low level
	bool m_tunnel;
	bool m_chunked;

	// sync
	boost::weak_ptr<Channel> m_weak_channel;
	bool m_response_token;

public:
	ProxySession(Poseidon::Move<Poseidon::UniqueFile> socket, boost::shared_ptr<const Poseidon::Http::AuthInfo> auth_info);
	~ProxySession();

private:
	bool sync_get_response_token() NOEXCEPT;
	void sync_pretty_shutdown(unsigned status_code, long err_code, const char *err_msg, const Poseidon::OptionalMap &headers = Poseidon::OptionalMap()) NOEXCEPT;
	void low_level_enqueue_tunnel_data(Poseidon::StreamBuffer data);

protected:
	void on_read_hup() OVERRIDE;
	//void on_close(int err_code) OVERRIDE;

	void on_low_level_request_headers(Poseidon::Http::RequestHeaders request_headers, boost::uint64_t content_length) OVERRIDE;
	void on_low_level_request_entity(boost::uint64_t entity_offset, Poseidon::StreamBuffer entity) OVERRIDE;
	boost::shared_ptr<Poseidon::Http::UpgradedSessionBase> on_low_level_request_end(boost::uint64_t content_length, Poseidon::OptionalMap headers) OVERRIDE;
};

}
}

#endif
