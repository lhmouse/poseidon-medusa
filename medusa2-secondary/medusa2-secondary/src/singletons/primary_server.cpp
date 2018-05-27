// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#include "precompiled.hpp"
#include "primary_server.hpp"
#include "../mmain.hpp"
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>

namespace Medusa2 {
namespace Secondary {

namespace {
	class Primary_tcp_server : public Poseidon::Tcp_server_base {
	public:
		Primary_tcp_server(const std::string &bind, boost::uint16_t port, const std::string &cert, const std::string &pkey)
			: Poseidon::Tcp_server_base(Poseidon::Ip_port(bind.c_str(), port), cert.c_str(), pkey.c_str())
		{
			//
		}

	protected:
		boost::shared_ptr<Poseidon::Tcp_session_base> on_client_connect(Poseidon::Move<Poseidon::Unique_file> socket) OVERRIDE {
			AUTO(session, boost::make_shared<Primary_session>(STD_MOVE(socket)));
			session->set_no_delay();
			return STD_MOVE_IDN(session);
		}
	};

	boost::weak_ptr<Primary_tcp_server> g_weak_tcp_server;
}

POSEIDON_MODULE_RAII_PRIORITY(handles, Poseidon::module_init_priority_low){
	const AUTO(bind, get_config<std::string>("primary_server_bind", "127.0.0.1"));
	const AUTO(port, get_config<boost::uint16_t>("primary_server_port", 3805));
	const AUTO(cert, get_config<std::string>("primary_server_certificate"));
	const AUTO(pkey, get_config<std::string>("primary_server_private_key"));
	MEDUSA2_LOG_INFO("Secondary server: Creating Primary_tcp_server: bind:port = ", bind, ":", port);
	const AUTO(tcp_server, boost::make_shared<Primary_tcp_server>(bind, port, cert, pkey));
	Poseidon::Epoll_daemon::add_socket(tcp_server, false);
	handles.push(tcp_server);
	g_weak_tcp_server = tcp_server;
}

}
}
