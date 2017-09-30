#ifndef MEDUSA2_SECONDARY_SINGLETONS_PRIMARY_SERVER_HPP_
#define MEDUSA2_SECONDARY_SINGLETONS_PRIMARY_SERVER_HPP_

#include "../primary_session.hpp"

namespace Medusa2 {
namespace Secondary {

class PrimaryServer {
public:
	static boost::shared_ptr<PrimarySession> get_session(const Poseidon::Uuid &session_uuid);
	static void insert_session(const boost::shared_ptr<PrimarySession> &session);
	static bool remove_session(volatile PrimarySession *ptr) NOEXCEPT;

private:
	PrimaryServer();
};

}
}

#endif
