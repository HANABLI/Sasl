/**
 * @file Scram.cpp
 * @brief this is the implemetation of the Sasl::Client::Scram class.
 * @copyright © 2026 by Hatem Nabli.
 */
#include <Sasl/Scram.hpp>
#include <Sha1/Sha1.hpp>

namespace Sasl::Client
{
    struct Scram::Impl
    {
        bool isCredentialWasSent = false;

        SystemUtils::DiagnosticsSender diagnosticSender;
        Impl() : diagnosticSender("Sasl::Client::Scram") {}
        ~Impl() noexcept = default;
    };

    Scram::Scram() : impl_(std::make_unique<Impl>()) {}

    Scram::~Scram() noexcept = default;
    Scram::Scram(Scram&& other) noexcept = default;
    Scram& Scram::operator=(Scram&& other) noexcept = default;

    SystemUtils::DiagnosticsSender::UnsubscribeDelegate Scram::SubscribeToDiagnosticsSender(
        SystemUtils::DiagnosticsSender::DiagnosticMessageDelegate messageDelegate, size_t level) {
        return impl_->diagnosticSender.SubscribeToDiagnostics(messageDelegate, level);
    }

    void Scram::Reset() { impl_->isCredentialWasSent = false; }

    bool Scram::Succeeded() { return false; }

    std::string Scram::InitialResponse() { return ""; }

    void Scram::SetCredentials(const std::string& credentials,
                               const std::string& authenticationIdentity,
                               const std::string& authorizationIdentity) {}

    std::string Scram::ExchangeAuthentication(const std::string& message) { return ""; }

    /**
     * This function is used to create the client's proof for the SCRAM
     * algorithm given the required input.
     *
     * @param[in] password
     *          The password of the client.
     * @param[in] clientNonce
     *          This is the nonce to use to hash the client's password.
     * @param[in] salt
     *          This is the number of iterations to use in the algorithm.
     * @param[in] hashFunction
     *          The function to use to hash SCRAM algorithm.
     */
    static std::string ComputeClientProof(
        std::string& password, std::string& clientNonce, std::string& salt,
        std::function<std::vector<uint8_t>(const std::string&)> hashFunction) {}
}  // namespace Sasl::Client