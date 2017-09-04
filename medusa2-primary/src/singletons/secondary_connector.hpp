#ifndef MEDUSA2_PRIMARY_SECONDARY_CONNECTOR_HPP_
#define MEDUSA2_PRIMARY_SECONDARY_CONNECTOR_HPP_

#include "../secondary_client.hpp"

namespace Medusa2 {
namespace Primary {

class SecondaryConnector {
	static boost::shared_ptr<SecondaryClient> get();

private:
	SecondaryConnector();
};

}
}

#endif
