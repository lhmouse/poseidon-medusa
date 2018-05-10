// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#include "precompiled.hpp"
#include "proxy_server.hpp"
#include "../mmain.hpp"
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>
#include <poseidon/http/authentication.hpp>

namespace Medusa2 {
namespace Primary {

namespace {
	class Proxy_tcp_server : public Poseidon::Tcp_server_base {
	private:
		const boost::shared_ptr<const Poseidon::Http::Authentication_context> m_auth_ctx;

	public:
		Proxy_tcp_server(const std::string &bind, boost::uint16_t port, const std::string &cert, const std::string &pkey, boost::shared_ptr<const Poseidon::Http::Authentication_context> auth_ctx)
			: Poseidon::Tcp_server_base(Poseidon::Ip_port(bind.c_str(), port), cert.c_str(), pkey.c_str())
			, m_auth_ctx(STD_MOVE(auth_ctx))
		{
			//
		}

	protected:
		boost::shared_ptr<Poseidon::Tcp_session_base> on_client_connect(Poseidon::Move<Poseidon::Unique_file> socket) OVERRIDE {
			AUTO(session, boost::make_shared<Proxy_session>(STD_MOVE(socket), m_auth_ctx));
			session->set_no_delay();
			return STD_MOVE_IDN(session);
		}
	};

	boost::weak_ptr<Proxy_tcp_server> g_weak_tcp_server;
}

MODULE_RAII_PRIORITY(handles, INIT_PRIORITY_LOW){
	const AUTO(bind, get_config<std::string>("proxy_server_bind", "127.0.0.1"));
	const AUTO(port, get_config<boost::uint16_t>("proxy_server_port", 3808));
	const AUTO(cert, get_config<std::string>("proxy_server_certificate"));
	const AUTO(pkey, get_config<std::string>("proxy_server_private_key"));
	const AUTO(relm, get_config<std::string>("proxy_server_realm"));
	const AUTO(auth, get_config_all<std::string>("proxy_server_auth"));
	LOG_MEDUSA2_INFO("Secondary server: Creating Proxy_tcp_server: bind:port = ", bind, ":", port);
	boost::shared_ptr<const Poseidon::Http::Authentication_context> auth_ctx;
	if(!auth.empty()){
		auth_ctx = Poseidon::Http::create_authentication_context(relm, auth);
	}
	const AUTO(tcp_server, boost::make_shared<Proxy_tcp_server>(bind, port, cert, pkey, auth_ctx));
	Poseidon::Epoll_daemon::add_socket(tcp_server, false);
	handles.push(tcp_server);
	g_weak_tcp_server = tcp_server;
}

}
}
