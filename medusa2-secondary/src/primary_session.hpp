#ifndef MEDUSA2_SECONDARY_PRIMARY_SESSION_HPP_
#define MEDUSA2_SECONDARY_PRIMARY_SESSION_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/session.hpp>
#include <poseidon/uuid.hpp>
#include <boost/container/flat_map.hpp>

namespace Medusa2 {
namespace Secondary {

class PrimarySession : public Poseidon::Cbpp::Session {
private:
	class FetchClient;
	class Channel;

private:
	static void sync_timer_proc(const boost::weak_ptr<PrimarySession> &weak_session);

private:
	const Poseidon::Uuid m_session_uuid;

	boost::shared_ptr<Poseidon::TimerItem> m_timer;
	boost::container::flat_multimap<Poseidon::Uuid, boost::shared_ptr<Channel> > m_channels;

public:
	explicit PrimarySession(Poseidon::Move<Poseidon::UniqueFile> socket);
	~PrimarySession();

protected:
	void on_sync_timer();
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;

public:
	const Poseidon::Uuid &get_session_uuid() const NOEXCEPT {
		return m_session_uuid;
	}

	bool send(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;

	bool send(const Poseidon::Cbpp::MessageBase &msg);
};

}
}

#endif
