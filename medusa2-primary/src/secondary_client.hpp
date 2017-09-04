#ifndef MEDUSA2_PRIMARY_SECONDARY_CLIENT_HPP_
#define MEDUSA2_PRIMARY_SECONDARY_CLIENT_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/client.hpp>
#include <poseidon/uuid.hpp>
#include <boost/container/map.hpp>

namespace Medusa2 {
namespace Primary {

class SecondaryClient : public Poseidon::Cbpp::Client {
private:
	class Channel;

private:
	//

public:
	SecondaryClient(const Poseidon::SockAddr &sock_addr, bool use_ssl);
	~SecondaryClient();

protected:
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;

public:
	bool send(const Poseidon::Cbpp::MessageBase &msg);
};

}
}

#endif
