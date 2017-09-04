#ifndef MEDUSA2_SECONDARY_PRIMARY_SESSION_HPP_
#define MEDUSA2_SECONDARY_PRIMARY_SESSION_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/session.hpp>
#include <poseidon/uuid.hpp>
#include <boost/container/map.hpp>

namespace Medusa2 {
namespace Secondary {

class PrimarySession : public Poseidon::Cbpp::Session {
private:
	class FetchClient;
	class Channel;

private:
	static void timer_proc(const boost::weak_ptr<PrimarySession> &weak_session);

private:
	boost::shared_ptr<Poseidon::TimerItem> m_timer;
	boost::container::multimap<Poseidon::Uuid, Channel> m_channels;

public:
	explicit PrimarySession(Poseidon::Move<Poseidon::UniqueFile> socket);
	~PrimarySession();

protected:
	void on_timer();
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;

public:
	bool send(const Poseidon::Cbpp::MessageBase &msg);
};

}
}

#endif
