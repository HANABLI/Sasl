#ifndef SASL_CLINET_SCRAM_HPP
#    define SASL_CLIENT_SCRAM_HPP

/**
 * @file Scram.hpp
 * @brief This is the declaration of the Sasl::Client::Scram Mechanism.
 * @copyright © 2026 by Hatem Nabli
 */
#    include <Sasl/Mechanism.hpp>
#    include <Sha1/Sha1.hpp>
#    include <memory>
#    include <functional>

namespace Sasl::Client
{
    class Scram : public Mechanism
    {
    public:
        // Types
        typedef std::function<std::vector<uint8_t>(const std::vector<uint8_t>& data)> HashFunction;

    public:
        // Rule of 5
        ~Scram() noexcept;
        Scram(const Scram&) = delete;
        Scram(Scram&&) noexcept;
        Scram& operator=(const Scram&) = delete;
        Scram& operator=(Scram&&) noexcept;

    public:
        // Methods
        /** default constructor */
        Scram();

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

    public:
        /**
         * This is used to setup the hash function needed to compute the scram algorithm.
         *
         * @param[in] fn
         *      This is the Hash function to use in the scram algorithm.
         * @param[in] blockSize
         *      This is the block size of the given hash function in byte.
         * @param[in] digestSize
         *      This is the  bit size of the digest produced by the hash function.
         */
        void SetHashFunction(HashFunction fn, size_t blockSize, size_t digestSize) const;

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
            std::function<std::vector<uint8_t>(const std::string&)> hashFunction);

    private:
        // Pimpl idiom
        struct Impl;

        std::unique_ptr<Impl> impl_;
    };
}  // namespace Sasl::Client

#endif /* SASL_CLIENT_SCRAM_HPP */