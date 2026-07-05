/**
 * @file ScramTests.cpp
 * @brief This module contains the unit test of the Sasl::Client::Scram class.
 * @copyright © 2026 by Hatem Nabli.
 */

#include <gtest/gtest.h>
#include <StringUtils/StringUtils.hpp>
#include <Base64/Base64.hpp>
#include <Sasl/Scram.hpp>
#include <Sha1/Sha1.hpp>
#include <Hmac/Hmac.hpp>
#include <Pbkdf2/Pbkdf2.hpp>
#include <functional>
#include <stdint.h>
#include <string>
#include <vector>

namespace
{
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

    struct ClientProofServerSignature
    {
        std::string clientProof;

        std::string serverSignature;
    };
    /**
     * This function Compute the Client Proof and the server signature.
     *
     * @param[in] userName
     *      This is the client's user name to use to implement sadl algorithm.
     *
     * @param[in] password
     *      This is the client's password to use to compute the Proof.
     *
     * @param[in] salt
     *      This is salt to use in hashing the client's password.
     *
     * @param[in] clientNonce
     *      This is the nonce to use to compute the client's proof.
     *
     * @param[in] serverNonce
     *      This is the nonce to use to ccompute the server's signature.
     *
     * @param[in] iterations
     *      This is the number of iteration to use in the Proof computation.
     *
     * @param[in] hashFunction
     *      This is the hash function to use in the SCRAM algorithm.
     *
     * @param[in] blockSize
     *      This is the bytes block size of the given hash function.
     *
     * @param[in] digestSize
     *      This is the bits size of the digest produced by the hash function.
     */
    ClientProofServerSignature ComputeClientProofServerSignature(
        const std::string& userName, const std::string& password, const std::string& salt,
        const std::string& clientNonce, const std::string& serverNonce, int iterations,
        const std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> hashFunction,
        size_t blockSize, size_t degestSize) {
        const auto saltedPassword = Pbkdf2::Pbkdf2(
            Hmac::HmacBytesToBytesFunction(hashFunction, blockSize),
            StringToBytes(Normalize(password)), StringToBytes(Base64::DecodeFromBase64(salt)),
            iterations, degestSize / 8);
        const auto clientKey = Hmac::HmacBytesToBytesFunction(hashFunction, blockSize)(
            saltedPassword, StringToBytes("Client Key"));
        const auto storedKey = hashFunction(clientKey);
        const auto clientFirstMessageBar = "n=" + userName + ",r=" + clientNonce;
        const auto serverFirstMessage = StringUtils::sprintf(
            ("r=" + serverNonce + ",s=" + salt + ",i=%zu").c_str(), iterations);
        const auto clientFirstMessageWithoutProof = "c=biws,r=" + serverNonce;
        const auto authMessage = StringToBytes(clientFirstMessageBar + "," + serverFirstMessage +
                                               "," + clientFirstMessageWithoutProof);
        const auto clientSignature =
            Hmac::HmacBytesToBytesFunction(hashFunction, blockSize)(storedKey, authMessage);
        std::vector<uint8_t> clientProof(storedKey.size());
        for (size_t i = 0; i < clientProof.size(); ++i)
        { clientProof[i] = clientKey[i] ^ clientSignature[i]; }
        const auto serverKey = Hmac::HmacBytesToBytesFunction(hashFunction, blockSize)(
            saltedPassword, StringToBytes("Server Key"));
        const auto serverSignature =
            Hmac::HmacBytesToBytesFunction(hashFunction, blockSize)(serverKey, authMessage);
        ClientProofServerSignature clientProofServerSignature;
        clientProofServerSignature.clientProof =
            Base64::EncodeToBase64(std::string(clientProof.begin(), clientProof.end()));
        clientProofServerSignature.serverSignature =
            Base64::EncodeToBase64(std::string(serverSignature.begin(), serverSignature.end()));
        return clientProofServerSignature;
    }

}  // namespace

TEST(SaslTests, SaslTests_Scram_ComputeClientProofAndServerSignature__Test) {
    const std::string username = "user";
    const std::string password = "pencil";
    const std::string clientNonce = "fyko+d2lbbFgONRv9qkxdawL";
    const std::string serverNonce = clientNonce + "3rfcNHYJY1ZVvWVs7j";
    const std::string salt = "QSXCR+Q6sek8bf92";
    const size_t numIterations = 4096;
    const size_t digestSize = 160;
    const auto hashFunction =
        static_cast<std::vector<uint8_t> (*)(const std::vector<uint8_t>&)>(Sha1::Sha1Bytes);
    const auto blockSize = Sha1::SHA1_BLOCK_SIZE;
    const std::string expectedClientProof = "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=";
    const std::string expectedServerSignature = "rmF9pqV8S7suAoZWja4dJRkFsKQ=";
    const auto clientProofServerSignature =
        ComputeClientProofServerSignature(username, password, salt, clientNonce, serverNonce,
                                          numIterations, hashFunction, blockSize, digestSize);
    EXPECT_EQ(expectedClientProof, clientProofServerSignature.clientProof);
    EXPECT_EQ(expectedServerSignature, clientProofServerSignature.serverSignature);
}

TEST(SaslTests, SaslTests_Scram_CredentialInitialResponseWithoutAuthorizationIdentity__Test) {
    Sasl::Client::Scram mechanism;
    mechanism.SetHashFunction(
        static_cast<std::vector<uint8_t> (*)(const std::vector<uint8_t>&)>(Sha1::Sha1Bytes),
        Sha1::SHA1_BLOCK_SIZE, 160);
    mechanism.SetCredentials("hunter2", "bob");

    const auto clientFirstMessage = mechanism.InitialResponse();
    ASSERT_GT(clientFirstMessage.length(), 11);
    const auto clientNonce = clientFirstMessage.substr(11);
    EXPECT_EQ("n,,n=bob,r=", clientFirstMessage.substr(0, 11));
    EXPECT_FALSE(clientNonce.empty());
}