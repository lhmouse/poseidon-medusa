#ifndef MEDUSA2_SECONDARY_PRIMARY_SESSION_HPP_
#define MEDUSA2_SECONDARY_PRIMARY_SESSION_HPP_

#include <poseidon/cbpp/session.hpp>

namespace Medusa2 {
namespace Secondary {

class PrimarySession : public Poseidon::Cbpp::Session {
public:
	explicit PrimarySession(Poseidon::Move<UniqueFile> socket);
	~PrimarySession();

protected:
	void on_close(int err_code) OVERRIDE;

	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;
	void on_sync_control_message(Poseidon::Cbpp::StatusCode status_code, Poseidon::StreamBuffer param) OVERRIDE;
};

}
}

#endif
