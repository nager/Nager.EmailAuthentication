using Nager.EmailAuthentication.Models.Dkim;

namespace Nager.EmailAuthentication.UnitTest.DkimPublicKeyRecordTests.Parser
{
    [TestClass]
    public sealed class PublicKeyTest
    {
        private const string RsaPublicKey2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuu8v3TAGlg2cKEVtHbqh5QfebUSdVp2qwH4NFaIG/rEsBshHI97fdP6TqiJCmpLhK8mHSQMit2HiHAEUApa0xAw7SI68XiBr6epKpTkHaUx27C/kjyuxYmGFOJy6mrDzeC2E5+Lp1u9QifjuBtUk78ORSA+EXeEMxssHy51NdHT0BlZGk1M+wXTxniQ2d198gDVjjqRGM433Q0AP6uSJac9LQj80tHkWrnr/bjct7EOdtF+6mDl4qjAaJTruk03Xt3Alaj+DIOPmnwP1mbPLQmK4blnzM7jwQc2kZz9gSJocc0nhs8KfuR6Xj23iSOJV+WEt6WoLoJzSl8/Dx5CKJwIDAQAB";
        private const string RsaPublicKey1024 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFCobkeqfYIxcXooAxjH5UAc9mmpc5K4Gy4+CCE2ql/qOEPc5HF9KEkxEpmV1Ro5wymud9FE9Xjfj2IzcJIWd0ZYiYySvJM2cR/k8n9ncEm2t/wEefBLX12ARxuq9izVah5DIGoR7EAfo9U6FrLdYniKsNM+2ILVlPLNl/zYyUZwIDAQAB";

        // RSAPublicKey without the algorithm identifier (RFC 8301 section 3.2)
        private const string RsaPublicKey1024WithoutAlgorithmIdentifier = "MIGJAoGBALrnXkTBQngq20X1dtAL5mZJtVDiirPmNBF5Enqe4tqu2XgvrTFHdUuWUSpcsSxD7trh6/qSVJpZSQxwGVtWK/HIWzVOgR9Hrr4wWgaIBkAXmt1gHxE6POZOQNylY8b1ybBWTkW0t/8QxY2MEMtKquUcR2HQbv3gikw37R8hQIE9AgMBAAE=";

        // RFC 8463 appendix A.2
        private const string Ed25519PublicKey = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

        private static DkimPublicKeyRecordV1 Parse(string dkimPublicKeyRecordRaw)
        {
            var isSuccessful = DkimPublicKeyRecordParser.TryParse(dkimPublicKeyRecordRaw, out var dkimPublicKeyRecord);

            Assert.IsTrue(isSuccessful);

            if (dkimPublicKeyRecord is not DkimPublicKeyRecordV1 dkimPublicKeyRecordV1)
            {
                Assert.Fail("Wrong DkimPublicKeyRecordV1 class");
                return null!;
            }

            return dkimPublicKeyRecordV1;
        }

        [DataRow(RsaPublicKey2048, 2048)]
        [DataRow(RsaPublicKey1024, 1024)]
        [DataRow(RsaPublicKey1024WithoutAlgorithmIdentifier, 1024)]
        [TestMethod]
        public void TryParse_RsaPublicKey_ReturnsKeyLength(string publicKey, int expectedKeyLength)
        {
            var dkimPublicKeyRecord = Parse($"v=DKIM1; k=rsa; p={publicKey}");

            Assert.AreEqual(expectedKeyLength, dkimPublicKeyRecord.KeyLength);
            Assert.IsFalse(dkimPublicKeyRecord.IsRevoked);
        }

        [TestMethod]
        public void TryParse_RsaPublicKeyWithoutKeyType_ReturnsKeyLength()
        {
            var dkimPublicKeyRecord = Parse($"p={RsaPublicKey2048}");

            Assert.AreEqual("rsa", dkimPublicKeyRecord.KeyType);
            Assert.AreEqual(2048, dkimPublicKeyRecord.KeyLength);
        }

        [TestMethod]
        public void TryParse_RsaPublicKeyInMultipleStrings_ReturnsKeyLength()
        {
            var dkimPublicKeyRecord = Parse($"v=DKIM1; k=rsa; p={RsaPublicKey2048[..200]} {RsaPublicKey2048[200..]}");

            Assert.AreEqual(2048, dkimPublicKeyRecord.KeyLength);
        }

        [TestMethod]
        public void TryParse_Ed25519PublicKey_ReturnsKeyLength()
        {
            var dkimPublicKeyRecord = Parse($"v=DKIM1; k=ed25519; p={Ed25519PublicKey}");

            Assert.AreEqual(256, dkimPublicKeyRecord.KeyLength);
        }

        [DataRow("v=DKIM1; k=rsa; p=test")]
        [DataRow("v=DKIM1; k=rsa; p=aGVsbG8gd29ybGQ=")]
        [DataRow("v=DKIM1; k=rsa; p=!!!")]
        [DataRow("v=DKIM1; k=ed25519; p=aGVsbG8gd29ybGQ=")]
        [DataRow("v=DKIM1; k=ed25519; p=" + RsaPublicKey1024)]
        [DataRow("v=DKIM1; k=rsa; p=" + Ed25519PublicKey)]
        [TestMethod]
        public void TryParse_PublicKeyDataIsNotAKey_ReturnsNoKeyLength(string dkimPublicKeyRecordRaw)
        {
            var dkimPublicKeyRecord = Parse(dkimPublicKeyRecordRaw);

            Assert.IsNull(dkimPublicKeyRecord.KeyLength);
            Assert.IsFalse(dkimPublicKeyRecord.IsRevoked);
        }

        [DataRow("v=DKIM1; p=")]
        [DataRow("v=DKIM1; k=rsa; p=;")]
        [DataRow("p=")]
        [TestMethod]
        public void TryParse_EmptyPublicKey_ReturnsRevokedKey(string dkimPublicKeyRecordRaw)
        {
            var dkimPublicKeyRecord = Parse(dkimPublicKeyRecordRaw);

            // RFC 6376 section 3.6.1: an empty value means that the public key has been revoked
            Assert.IsTrue(dkimPublicKeyRecord.IsRevoked);
            Assert.IsNull(dkimPublicKeyRecord.KeyLength);
            Assert.AreEqual(string.Empty, dkimPublicKeyRecord.PublicKeyData);
        }

        [DataRow("v=DKIM1")]
        [DataRow("v=DKIM1; k=rsa")]
        [DataRow("k=rsa")]
        [DataRow("t=y")]
        [TestMethod]
        public void TryParse_WithoutPublicKey_ReturnsFalse(string dkimPublicKeyRecordRaw)
        {
            // The public key is required, a record without it is not a DKIM public key record
            var isSuccessful = DkimPublicKeyRecordParser.TryParse(dkimPublicKeyRecordRaw, out var dkimPublicKeyRecord);

            Assert.IsFalse(isSuccessful);
            Assert.IsNull(dkimPublicKeyRecord);
        }

        [DataRow(null, false, false)]
        [DataRow("y", true, false)]
        [DataRow("s", false, true)]
        [DataRow("y:s", true, true)]
        [DataRow("s : Y", true, true)]
        [DataRow("x", false, false)]
        [TestMethod]
        public void TryParse_Flags_ReturnsTestModeAndStrictIdentity(string? flags, bool expectedTestMode, bool expectedStrictIdentity)
        {
            var flagsTag = flags == null ? string.Empty : $" t={flags};";
            var dkimPublicKeyRecord = Parse($"v=DKIM1;{flagsTag} p={RsaPublicKey1024}");

            Assert.AreEqual(expectedTestMode, dkimPublicKeyRecord.IsTestMode);
            Assert.AreEqual(expectedStrictIdentity, dkimPublicKeyRecord.IsStrictIdentity);
        }

        [TestMethod]
        public void TryParse_WhitespaceAroundEqualSign_ReturnsTrueAndPopulatesData()
        {
            var dkimPublicKeyRecord = Parse($"v = DKIM1 ; k = rsa ; p = {RsaPublicKey1024}");

            Assert.AreEqual("DKIM1", dkimPublicKeyRecord.Version);
            Assert.AreEqual("rsa", dkimPublicKeyRecord.KeyType);
            Assert.AreEqual(1024, dkimPublicKeyRecord.KeyLength);
        }
    }
}
