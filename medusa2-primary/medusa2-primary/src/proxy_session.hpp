// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#ifndef MEDUSA2_PRIMARY_PROXY_SESSION_HPP_
#define MEDUSA2_PRIMARY_PROXY_SESSION_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/http/fwd.hpp>
#include <poseidon/http/low_level_session.hpp>

namespace Medusa2 {
namespace Primary {

class Proxy_session : public Poseidon::Http::Low_level_session {
private:
	class Tunnel_session;
	class Deaf_session;
	class Channel;

	class Sync_job_base;
	class Request_headers_job;
	class Request_entity_job;
	class Request_end_job;
	class Read_hup_job;
	class Close_job;

private:
	const boost::shared_ptr<const Poseidon::Http::Authentication_context> m_auth_ctx;

	// low level
	bool m_tunnel;
	bool m_chunked;

	// sync
	boost::weak_ptr<Channel> m_weak_channel;
	bool m_response_token;

public:
	Proxy_session(Poseidon::Move<Poseidon::Unique_file> socket, boost::shared_ptr<const Poseidon::Http::Authentication_context> auth_ctx);
	~Proxy_session();

private:
	bool sync_get_response_token() NOEXCEPT;
	void sync_pretty_shutdown(unsigned status_code, long err_code, const char *err_msg, const Poseidon::Optional_map &headers = Poseidon::Optional_map()) NOEXCEPT;
	void low_level_enqueue_tunnel_data(Poseidon::Stream_buffer data);

protected:
	void on_read_hup() OVERRIDE;
	void on_close(int err_code) OVERRIDE;

	void on_low_level_request_headers(Poseidon::Http::Request_headers request_headers, boost::uint64_t content_length) OVERRIDE;
	void on_low_level_request_entity(boost::uint64_t entity_offset, Poseidon::Stream_buffer entity) OVERRIDE;
	boost::shared_ptr<Poseidon::Http::Upgraded_session_base> on_low_level_request_end(boost::uint64_t content_length, Poseidon::Optional_map headers) OVERRIDE;
};

}
}

#endif
