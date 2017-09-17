#include "precompiled.hpp"
#include "secondary_connector.hpp"
#include "../mmain.hpp"
#include <poseidon/mutex.hpp>
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/sock_addr.hpp>
#include <poseidon/singletons/dns_daemon.hpp>

namespace Medusa2 {
namespace Primary {

namespace {
	Poseidon::Mutex g_mutex;
	boost::weak_ptr<const Poseidon::JobPromiseContainer<Poseidon::SockAddr> > g_weak_promised_sock_addr;
	boost::weak_ptr<SecondaryClient> g_weak_client;

	void reconnect_timer_proc(){
		PROFILE_ME;

		Poseidon::Mutex::UniqueLock lock(g_mutex);
		AUTO(client, g_weak_client.lock());
		if(client){
			return;
		}
		AUTO(promised_sock_addr, g_weak_promised_sock_addr.lock());
		if(!promised_sock_addr){
			const AUTO(host, get_config<std::string>("secondary_connector_host", "127.0.0.1"));
			const AUTO(port, get_config<boost::uint16_t>("secondary_connector_port", 3805));
			LOG_MEDUSA2_INFO("Connecting to secondary server: host:port = ", host, ":", port);
			promised_sock_addr = Poseidon::DnsDaemon::enqueue_for_looking_up(host, port);
			g_weak_promised_sock_addr = promised_sock_addr;
		}
		lock.unlock();

		Poseidon::yield(promised_sock_addr);

		lock.lock();
		client = g_weak_client.lock();
		if(!client){
			const AUTO(use_ssl, get_config<bool>("secondary_connector_use_ssl"));
			LOG_MEDUSA2_INFO(">> use_ssl = ", use_ssl);
			client = boost::make_shared<SecondaryClient>(promised_sock_addr->get(), use_ssl);
			client->go_resident();
			client->send_control(Poseidon::Cbpp::ST_PING, VAL_INIT);
			g_weak_client = client;
		}
	}

	MODULE_RAII(handles){
		const AUTO(reconnect_delay, get_config<boost::uint64_t>("secondary_connector_reconnect_delay", 5000));
		const AUTO(timer, Poseidon::TimerDaemon::register_timer(0, reconnect_delay, boost::bind(reconnect_timer_proc)));
		handles.push(timer);
	}
}

boost::shared_ptr<SecondaryClient> SecondaryConnector::get_client(){
	const Poseidon::Mutex::UniqueLock lock(g_mutex);
	return g_weak_client.lock();
}

}
}
