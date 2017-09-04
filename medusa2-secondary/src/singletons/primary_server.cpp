#include "precompiled.hpp"
#include "primary_server.hpp"
#include "../mmain.hpp"
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>

namespace Medusa2 {
namespace Secondary {

namespace {
	class PrimaryServerTcp : public Poseidon::TcpServerBase {
	public:
		PrimaryServerTcp(const std::string &bind, unsigned port, const std::string &cert, const std::string &pkey)
			: Poseidon::TcpServerBase(Poseidon::IpPort(bind.c_str(), port), cert.c_str(), pkey.c_str())
		{ }
		~PrimaryServerTcp(){ }

	protected:
		boost::shared_ptr<Poseidon::TcpSessionBase> on_client_connect(Poseidon::Move<Poseidon::UniqueFile> socket) const OVERRIDE {
			return boost::make_shared<PrimarySession>(STD_MOVE(socket));
		}
	};

	MODULE_RAII(handles){
		const auto bind = get_config<std::string>("primary_server_bind", "127.0.0.1");
		const auto port = get_config<std::uint16_t>("primary_server_port", 3805);
		const auto cert = get_config<std::string>("primary_server_certificate");
		const auto pkey = get_config<std::string>("primary_server_private_key");
		LOG_MEDUSA2_INFO("Secondary server: Creating PrimaryServerTcp: bind:port = ", bind, ":", port);
		const auto server = boost::make_shared<PrimaryServerTcp>(bind, port, cert, pkey);
		Poseidon::EpollDaemon::add_socket(server);
		handles.push(server);
	}
}

}
}
