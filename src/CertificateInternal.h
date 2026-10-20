#pragma once
#include <iiNetwork/Security.h>
#include <openssl/x509.h>

namespace ii::network::detail
{
Result<CertificateInfo> certificate_info(X509*);
}
