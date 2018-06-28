// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#ifndef MEDUSA2_SECONDARY_PRIMARY_SESSION_HPP_
#define MEDUSA2_SECONDARY_PRIMARY_SESSION_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/session.hpp>
#include <poseidon/uuid.hpp>
#include <boost/container/flat_map.hpp>

namespace Medusa2 {
namespace Secondary {

class Primary_session : public Poseidon::Cbpp::Session {
private:
	class Fetch_client;
	class Channel;

private:
	static void sync_timer_proc(const boost::weak_ptr<Primary_session> &weak_session);

private:
	const Poseidon::Uuid m_session_uuid;

	boost::shared_ptr<Poseidon::Timer> m_timer;
	boost::container::flat_multimap<Poseidon::Uuid, boost::shared_ptr<Channel> > m_channels;
	bool m_authenticated;

public:
	explicit Primary_session(Poseidon::Move<Poseidon::Unique_file> socket);
	~Primary_session();

protected:
	void on_sync_timer();
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::Stream_buffer payload) OVERRIDE;
	void on_sync_control_message(Poseidon::Cbpp::Status_code status_code, Poseidon::Stream_buffer param) OVERRIDE;

public:
	const Poseidon::Uuid & get_session_uuid() const NOEXCEPT {
		return m_session_uuid;
	}

	bool send(boost::uint16_t message_id, Poseidon::Stream_buffer payload) OVERRIDE;

	bool send(const Poseidon::Cbpp::Message_base &msg);
};

}
}

#endif
