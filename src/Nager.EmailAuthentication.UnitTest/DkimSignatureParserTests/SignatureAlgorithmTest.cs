namespace Nager.EmailAuthentication.UnitTest.DkimSignatureParserTests
{
    [TestClass]
    public sealed class SignatureAlgorithmTest
    {
        [DataRow("rsa-sha256")]
        [DataRow("ed25519-sha256")]
        [DataTestMethod]
        public void TryParse_ValidSignatureAlgorithm_ReturnsTrueAndPopulatesDataFragment(string signatureAlgorithm)
        {
            var dkimSignature = $"v=1; a={signatureAlgorithm}; d=domain.com; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParser.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is null");
        }

        [DataRow("rsa-sha1")]
        [DataTestMethod]
        public void TryParse_UnsecureSignatureAlgorithm_ReturnsTrueAndPopulatesDataFragment(string signatureAlgorithm)
        {
            var dkimSignature = $"v=1; a={signatureAlgorithm}; d=domain.com; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParser.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }

        [DataRow("rsa-sha512")]
        [DataTestMethod]
        public void TryParse_InvalidSignatureAlgorithm_ReturnsTrueAndPopulatesDataFragment(string signatureAlgorithm)
        {
            var dkimSignature = $"v=1; a={signatureAlgorithm}; d=domain.com; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParser.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }
    }
}
