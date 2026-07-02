#ifndef SASL_CLIENT_PLAIN_HPP
#define SASL_CLIENT_PLAIN_HPP

/**
 * @file Plain.hpp
 * @brief This id the declaration of Sasl::Client::Plain Mechanism.
 * @copyright © 2026 by Hatem Nabli
 */
#include <Sasl/Mechanism.hpp>
#include <memory>
namespace Sasl::Client
{
    class Plain : public Mechanism
    {
    public:
        // Rule of 5
        ~Plain() noexcept;
        Plain(const Plain&) = delete;
        Plain(Plain&&) noexcept;
        Plain& operator=(const Plain&) = delete;
        Plain& operator=(Plain&&) noexcept;

    public:
        // Methods
        /** Default constructor */
        Plain();

    public:
        SystemUtils::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnosticsSender(
            SystemUtils::DiagnosticsSender::DiagnosticMessageDelegate messageDelegate,
            size_t level = 0) override;

        void Reset() override;

        bool Succeeded() override;

        std::string InitialResponse() override;

        void SetCredentials(const std::string& credentials,
                            const std::string& authenticationIdentity,
                            const std::string& authorizationIdentity = "") override;

        std::string ExchangeAuthentication(const std::string& message) override;

    private:
        struct Impl;

        std::unique_ptr<Impl> impl_;
    };
}  // namespace Sasl::Client

#endif /* SASL_CLIENT_PLAIN_HPP */