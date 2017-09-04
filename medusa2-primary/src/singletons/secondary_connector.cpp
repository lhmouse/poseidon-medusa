#include "precompiled.hpp"
#include "secondary_connector.hpp"
#include "../mmain.hpp"
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/sock_addr.hpp>
#include <poseidon/singletons/dns_daemon.hpp>

#include "protocol/messages.hpp"

namespace Medusa2 {
namespace Primary {

namespace {
	boost::weak_ptr<SecondaryClient> g_client;

	void reconnect_timer_proc(){
		PROFILE_ME;

		AUTO(client, g_client.lock());
		if(client){
			return;
		}

		const auto host = get_config<std::string>("secondary_connector_host", "127.0.0.1");
		const auto port = get_config<std::uint16_t>("secondary_connector_port", 3805);
		const auto use_ssl = get_config<bool>("secondary_connector_use_ssl");
		LOG_MEDUSA2_INFO("Connecting to secondary server: host:port = ", host, ":", port, ", use_ssl = ", use_ssl);
		const auto promised_sock_addr = Poseidon::DnsDaemon::enqueue_for_looking_up(host, port);
		Poseidon::yield(promised_sock_addr);
		client = boost::make_shared<SecondaryClient>(promised_sock_addr->get(), use_ssl);
		client->go_resident();
		client->send_control(Poseidon::Cbpp::ST_PING, VAL_INIT);

auto uuid = Poseidon::Uuid::random();
client->send(Protocol::PS_Open(uuid, "www.baidu.com", 443, true));
client->send(Protocol::PS_Send(uuid, (const unsigned char *)"GET / HTTP/1.0\r\nHost: www.baidu.com\r\nConnection: Close\r\n\r\n"));

		g_client = client;
	}

	MODULE_RAII(handles){
		const auto reconnect_delay = get_config<std::uint64_t>("secondary_connector_reconnect_delay", 5000);
		const auto timer = Poseidon::TimerDaemon::register_timer(0, reconnect_delay, std::bind(reconnect_timer_proc));
		handles.push(std::move(timer));
	}
}

boost::shared_ptr<SecondaryClient> SecondaryConnector::get(){
	return g_client.lock();
}

}
}
