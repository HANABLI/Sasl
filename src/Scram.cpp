/**
 * @file Scram.cpp
 * @brief this is the implemetation of the Sasl::Client::Scram class.
 * @copyright © 2026 by Hatem Nabli.
 */
#include <sstream>
#include <Base64/Base64.hpp>
#include <Sasl/Scram.hpp>
#include <Sha1/Sha1.hpp>
#include <Hmac/Hmac.hpp>
#include <SystemUtils/CryptoRandom.hpp>

namespace
{
    /**
     * This is the number of characters to generate for nonce values.
     *
     */
    constexpr size_t NONCE_LENGTH = 224;

    /**
     * This is the dictionary of characters that are allowed in nonce value.
     */
    const std::vector<char> PRINTABLE = {
        '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+',  '-', '.', '/', '0', '1',
        '2', '3', '4', '5', '6', '7', '8',  '9', ':', ';', '<',  '=', '>', '?', '@', 'A',
        'B', 'C', 'D', 'E', 'F', 'G', 'H',  'I', 'J', 'K', 'L',  'M', 'N', 'O', 'P', 'Q',
        'R', 'S', 'T', 'U', 'V', 'W', 'X',  'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a',
        'b', 'c', 'd', 'e', 'f', 'g', 'h',  'i', 'j', 'k', 'l',  'm', 'n', 'o', 'p', 'q',
        'r', 's', 't', 'u', 'v', 'w', 'x',  'y', 'z', '{', '|',  '}', '~',
    };
    /**
     * Convert a string into the equivalent byte vector.
     *
     * @param[in] str
     *      This is the string to convert to a vector of byte.
     *
     * @return
     *      This is the byte vector equivalent to the given string.
     */
    std::vector<uint8_t> StringToBytes(const std::string& str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }

    /**
     * This function implement the SASLprep profile of the stringprep
     * algorithm to normalize the given str.
     *
     * @param[in] str
     *      This is the given str to normalize.
     * @return
     *      The normalized str is return.
     */

    std::string Normalize(const std::string& str) {
        // TODO: this will be implemented to handle non ascii characters.
        return str;
    }

    /**
     * This function generate a random sequence of ASCII
     * characters not including comma.
     */
    std::string MakeNonce() {
        static SystemUtils::CryptoRandom rnd;
        std::vector<uint8_t> randomByte(NONCE_LENGTH);
        rnd.Generate(randomByte.data(), randomByte.size());
        std::ostringstream builder;
        for (auto byte : randomByte)
        { builder << PRINTABLE[byte % PRINTABLE.size()]; }
        return builder.str();
    }
}  // namespace
namespace Sasl::Client
{
    struct Scram::Impl
    {
        bool isCredentialWasSent = false;

        /**
         * This flag indicate whether the authentication succeeded or not.
         */
        bool succeeded = false;

        /**
         * This is the client nonce to use in the scram algorithm to
         * further protect the client's credentials.
         */
        std::string clientNonce;
        /**
         * This is the normalized client's password.
         */
        std::vector<uint8_t> normalizedPassword;
        /**
         * This is the bar of the client's first message.
         */
        std::string clientFirstMessageBare;

        /**
         * This is the first message sent by the client to the server .
         */
        std::string clientFirstMessage;
        /**
         * This is the Base64 encoding of the GS2 Header provided by the client.
         */
        std::string encodedChannelBinding;

        /**
         * This is the hash function to use to compute sasl algorithm.
         */
        HashFunction hashFunction;

        /**
         * This is the HMAC function, derived from the hush function to use
         * to compute sasl algorithm.
         */
        std::function<std::vector<uint8_t>(const std::vector<uint8_t>&,
                                           const std::vector<uint8_t>&)>
            hmacFunction;

        /**
         * This is the bits size of the digest produced by the hash function.
         */
        size_t digestSize;

        /**
         * This is the name provided by the client that provides the authentication
         * identity.
         */
        std::string username;

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

    std::string Scram::InitialResponse() {
        impl_->diagnosticSender.SendDiagnosticInformationString(
            SystemUtils::DiagnosticsSender::INFO, "C: AUTH SCRAM* " + impl_->clientFirstMessage);

        return impl_->clientFirstMessage;
    }

    void Scram::SetCredentials(const std::string& credentials,
                               const std::string& authenticationIdentity,
                               const std::string& authorizationIdentity) {
        impl_->username = authenticationIdentity;
        impl_->normalizedPassword = StringToBytes(Normalize(credentials));
        impl_->clientNonce = MakeNonce();
        impl_->clientFirstMessageBare =
            ("n=" + authenticationIdentity + ",r=" + impl_->clientNonce);
        const std::string gs2Header = "n," + authorizationIdentity + ",";
        impl_->clientFirstMessage = gs2Header + impl_->clientFirstMessageBare;
        impl_->encodedChannelBinding = Base64::EncodeToBase64(gs2Header);
    }

    std::string Scram::ExchangeAuthentication(const std::string& message) { return ""; }

    void Scram::SetHashFunction(HashFunction fn, size_t blockSize, size_t digestSize) const {
        impl_->hashFunction = fn;
        impl_->hmacFunction = Hmac::HmacBytesToBytesFunction(fn, blockSize);
        impl_->digestSize = digestSize;
    }
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