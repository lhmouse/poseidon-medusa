#ifndef MEDUSA2_PRIMARY_SINGLETONS_PROXY_SERVER_HPP_
#define MEDUSA2_PRIMARY_SINGLETONS_PROXY_SERVER_HPP_

#include "../proxy_session.hpp"

namespace Medusa2 {
namespace Primary {

class ProxyServer {
public:
	static boost::shared_ptr<ProxySession> get_session(const Poseidon::Uuid &session_uuid);
	static void insert_session(const boost::shared_ptr<ProxySession> &session);
	static bool remove_session(volatile ProxySession *ptr) NOEXCEPT;

private:
	ProxyServer();
};

}
}

#endif
