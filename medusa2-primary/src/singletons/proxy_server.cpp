#include "precompiled.hpp"
#include "proxy_server.hpp"
#include "../mmain.hpp"
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>
#include <poseidon/http/authentication.hpp>

namespace Medusa2 {
namespace Primary {

namespace {
	inline boost::shared_ptr<const Poseidon::Http::AuthenticationContext> create_auth_ctx_optional(const std::string &realm, const std::vector<std::string> &auth){
		if(auth.empty()){
			return VAL_INIT;
		}
		return Poseidon::Http::create_authentication_context(realm, auth);
	}

	class ProxyTcpServer : public Poseidon::TcpServerBase {
	private:
		const boost::shared_ptr<const Poseidon::Http::AuthenticationContext> m_auth_ctx;

	public:
		ProxyTcpServer(const std::string &bind, unsigned port, const std::string &certificate, const std::string &private_key, const std::string &realm, const std::vector<std::string> &auth)
			: Poseidon::TcpServerBase(Poseidon::IpPort(bind.c_str(), port), certificate.c_str(), private_key.c_str())
			, m_auth_ctx(create_auth_ctx_optional(realm, auth))
		{ }

	protected:
		boost::shared_ptr<Poseidon::TcpSessionBase> on_client_connect(Poseidon::Move<Poseidon::UniqueFile> socket) const OVERRIDE {
			AUTO(session, boost::make_shared<ProxySession>(STD_MOVE(socket), m_auth_ctx));
			session->set_no_delay();
			return STD_MOVE_IDN(session);
		}
	};

	boost::weak_ptr<ProxyTcpServer> g_weak_tcp_server;

	MODULE_RAII(handles){
		const AUTO(bind, get_config<std::string>("proxy_server_bind", "127.0.0.1"));
		const AUTO(port, get_config<boost::uint16_t>("proxy_server_port", 3808));
		const AUTO(cert, get_config<std::string>("proxy_server_certificate"));
		const AUTO(pkey, get_config<std::string>("proxy_server_private_key"));
		const AUTO(relm, get_config<std::string>("proxy_server_realm"));
		const AUTO(auth, get_config_v<std::string>("proxy_server_auth"));
		LOG_MEDUSA2_INFO("Secondary server: Creating ProxyTcpServer: bind:port = ", bind, ":", port);
		const AUTO(tcp_server, boost::make_shared<ProxyTcpServer>(bind, port, cert, pkey, relm, auth));
		Poseidon::EpollDaemon::add_socket(tcp_server);
		handles.push(tcp_server);
		g_weak_tcp_server = tcp_server;
	}
}

}
}
