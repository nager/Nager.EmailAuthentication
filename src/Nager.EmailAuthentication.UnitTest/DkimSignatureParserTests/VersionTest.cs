namespace Nager.EmailAuthentication.UnitTest.DkimSignatureParserTests
{
    [TestClass]
    public sealed class VersionTest
    {
        [DataRow("1")]
        [DataTestMethod]
        public void TryParse_ValidVersion_ReturnsTrueAndPopulatesDataFragment(string version)
        {
            var dkimSignature = $"v={version}; a=rsa-sha256; d=domain.com; s=myselector; h=from:to:reply-to:subject:date:cc:content-type; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParser.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [DataRow("2")]
        [DataRow("3")]
        [DataRow("a")]
        [DataRow("a1")]
        [DataTestMethod]
        public void TryParse_InvalidVersion_ReturnsTrueAndPopulatesDataFragment(string version)
        {
            var dkimSignature = $"v={version}; a=rsa-sha256; d=domain.com; s=myselector; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParser.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }
    }
}
