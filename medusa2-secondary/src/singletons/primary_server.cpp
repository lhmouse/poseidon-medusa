#include "precompiled.hpp"
#include "primary_server.hpp"
#include "../mmain.hpp"
#include <poseidon/mutex.hpp>
#include <poseidon/multi_index_map.hpp>
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>

namespace Medusa2 {
namespace Secondary {

namespace {
	struct SessionElement {
		boost::weak_ptr<PrimarySession> weak_session;

		volatile PrimarySession *ptr;
		Poseidon::Uuid session_uuid;

		explicit SessionElement(const boost::shared_ptr<PrimarySession> &session)
			: weak_session(session), ptr(session.get()), session_uuid(session->get_session_uuid())
		{ }
	};
	MULTI_INDEX_MAP(SessionMap, SessionElement,
		UNIQUE_MEMBER_INDEX(ptr)
		UNIQUE_MEMBER_INDEX(session_uuid)
	)
	Poseidon::Mutex g_session_map_mutex;
	boost::weak_ptr<SessionMap> g_weak_session_map;

	MODULE_RAII_PRIORITY(handles, 1000){
		const AUTO(session_map, boost::make_shared<SessionMap>());
		handles.push(session_map);
		g_weak_session_map = session_map;
	}
}

boost::shared_ptr<PrimarySession> PrimaryServer::get_session(const Poseidon::Uuid &session_uuid){
	PROFILE_ME;

	const AUTO(session_map, g_weak_session_map.lock());
	if(!session_map){
		LOG_MEDUSA2_WARNING("SessionMap is gone.");
		return VAL_INIT;
	}

	const Poseidon::Mutex::UniqueLock lock(g_session_map_mutex);
	const AUTO(it, session_map->find<1>(session_uuid));
	if(it == session_map->end<1>()){
		LOG_MEDUSA2_DEBUG("PrimarySession not found: session_uuid = ", session_uuid);
		return VAL_INIT;
	}
	return it->weak_session.lock();
}
void PrimaryServer::insert_session(const boost::shared_ptr<PrimarySession> &session){
	PROFILE_ME;

	const AUTO(session_map, g_weak_session_map.lock());
	if(!session_map){
		LOG_MEDUSA2_ERROR("SessionMap is gone.");
		DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("SessionMap is gone"));
	}

	const Poseidon::Mutex::UniqueLock lock(g_session_map_mutex);
	const AUTO(pair, session_map->insert(SessionElement(session)));
	if(!pair.second){
		LOG_MEDUSA2_ERROR("Duplicate PrimarySession: session = ", session, ", session_uuid = ", session->get_session_uuid());
		DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Duplicate PrimarySession"));
	}
}
bool PrimaryServer::remove_session(volatile PrimarySession *ptr) NOEXCEPT {
	PROFILE_ME;

	const AUTO(session_map, g_weak_session_map.lock());
	if(!session_map){
		LOG_MEDUSA2_WARNING("SessionMap is gone.");
		return false;
	}

	const Poseidon::Mutex::UniqueLock lock(g_session_map_mutex);
	const AUTO(it, session_map->find<0>(ptr));
	if(it == session_map->end<0>()){
		LOG_MEDUSA2_DEBUG("PrimarySession not found: ptr = ", (void *)ptr);
		return false;
	}
	session_map->erase<0>(it);
	return true;
}

namespace {
	class PrimaryTcpServer : public Poseidon::TcpServerBase {
	public:
		PrimaryTcpServer(const std::string &bind, unsigned port, const std::string &cert, const std::string &pkey)
			: Poseidon::TcpServerBase(Poseidon::IpPort(bind.c_str(), port), cert.c_str(), pkey.c_str())
		{ }
		~PrimaryTcpServer(){ }

	protected:
		boost::shared_ptr<Poseidon::TcpSessionBase> on_client_connect(Poseidon::Move<Poseidon::UniqueFile> socket) const OVERRIDE {
			AUTO(session, boost::make_shared<PrimarySession>(STD_MOVE(socket)));
			session->set_no_delay();
			PrimaryServer::insert_session(session);
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
		Poseidon::EpollDaemon::add_socket(tcp_server);
		handles.push(tcp_server);
		g_weak_tcp_server = tcp_server;
	}
}

}
}
