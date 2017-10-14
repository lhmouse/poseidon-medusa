#ifndef MEDUSA2_PRIMARY_SECONDARY_CLIENT_HPP_
#define MEDUSA2_PRIMARY_SECONDARY_CLIENT_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/client.hpp>
#include <poseidon/uuid.hpp>
#include <boost/container/flat_map.hpp>

namespace Medusa2 {
namespace Primary {

class SecondaryChannel;

class SecondaryClient : public Poseidon::Cbpp::Client {
	friend SecondaryChannel;

private:
	class CloseJob;

private:
	mutable Poseidon::Mutex m_establishment_mutex;
	boost::container::flat_multimap<Poseidon::Uuid, boost::shared_ptr<SecondaryChannel> > m_channels_pending;

	boost::container::flat_multimap<Poseidon::Uuid, boost::shared_ptr<SecondaryChannel> > m_channels_established;

public:
	SecondaryClient(const Poseidon::SockAddr &sock_addr, bool use_ssl);
	~SecondaryClient();

protected:
	void on_close(int err_code) OVERRIDE;
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;

	bool send(const Poseidon::Cbpp::MessageBase &msg);

public:
	void attach_channel(const boost::shared_ptr<SecondaryChannel> &channel, std::string host, unsigned port, bool use_ssl, bool no_delay);
};

}
}

#endif
