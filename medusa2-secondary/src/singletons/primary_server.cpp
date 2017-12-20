#include "precompiled.hpp"
#include "primary_server.hpp"
#include "../mmain.hpp"
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>

namespace Medusa2 {
namespace Secondary {

namespace {
	class PrimaryTcpServer : public Poseidon::TcpServerBase {
	public:
		PrimaryTcpServer(const std::string &bind, unsigned port, const std::string &cert, const std::string &pkey)
			: Poseidon::TcpServerBase(Poseidon::IpPort(bind.c_str(), port), cert.c_str(), pkey.c_str())
		{ }
		~PrimaryTcpServer(){ }

	protected:
		boost::shared_ptr<Poseidon::TcpSessionBase> on_client_connect(Poseidon::Move<Poseidon::UniqueFile> socket) OVERRIDE {
			AUTO(session, boost::make_shared<PrimarySession>(STD_MOVE(socket)));
			session->set_no_delay();
			return STD_MOVE_IDN(session);
		}
	};

	boost::weak_ptr<PrimaryTcpServer> g_weak_tcp_server;

	MODULE_RAII(handles){
		const AUTO(bind, get_config<std::string>("primary_server_bind", "127.0.0.1"));
		const AUTO(port, get_config<boost::uint16_t>("primary_server_port", 3805));
		const AUTO(cert, get_config<std::string>("primary_server_certificate"));
		const AUTO(pkey, get_config<std::string>("primary_server_private_key"));
		LOG_MEDUSA2_INFO("Secondary server: Creating PrimaryTcpServer: bind:port = ", bind, ":", port);
		const AUTO(tcp_server, boost::make_shared<PrimaryTcpServer>(bind, port, cert, pkey));
		Poseidon::EpollDaemon::add_socket(tcp_server, false);
		handles.push(tcp_server);
		g_weak_tcp_server = tcp_server;
	}
}

}
}
