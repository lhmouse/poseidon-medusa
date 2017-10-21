#include "precompiled.hpp"
#include "proxy_server.hpp"
#include "../mmain.hpp"
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>
#include <poseidon/http/authorization.hpp>

namespace Medusa2 {
namespace Primary {

namespace {
	inline boost::shared_ptr<const Poseidon::Http::AuthInfo> create_auth_info_optional(const std::vector<std::string> &auth){
		if(auth.empty()){
			return VAL_INIT;
		}
		return Poseidon::Http::create_auth_info(auth);
	}

	class ProxyTcpServer : public Poseidon::TcpServerBase {
	private:
		const boost::shared_ptr<const Poseidon::Http::AuthInfo> m_auth_info;

	public:
		ProxyTcpServer(const std::string &bind, unsigned port, const std::string &cert, const std::string &pkey, const std::vector<std::string> &auth)
			: Poseidon::TcpServerBase(Poseidon::IpPort(bind.c_str(), port), cert.c_str(), pkey.c_str())
			, m_auth_info(create_auth_info_optional(auth))
		{ }
		~ProxyTcpServer(){ }

	protected:
		boost::shared_ptr<Poseidon::TcpSessionBase> on_client_connect(Poseidon::Move<Poseidon::UniqueFile> socket) const OVERRIDE {
			AUTO(session, boost::make_shared<ProxySession>(STD_MOVE(socket), m_auth_info));
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
		const AUTO(auth, get_config_v<std::string>("proxy_server_auth"));
		LOG_MEDUSA2_INFO("Secondary server: Creating ProxyTcpServer: bind:port = ", bind, ":", port);
		const AUTO(tcp_server, boost::make_shared<ProxyTcpServer>(bind, port, cert, pkey, auth));
		Poseidon::EpollDaemon::add_socket(tcp_server);
		handles.push(tcp_server);
		g_weak_tcp_server = tcp_server;
	}
}

}
}
