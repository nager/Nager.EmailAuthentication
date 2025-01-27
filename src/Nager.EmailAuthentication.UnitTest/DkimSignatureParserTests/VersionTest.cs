namespace Nager.EmailAuthentication.UnitTest.DkimSignatureParserTests
{
    [TestClass]
    public sealed class VersionTest
    {
        [DataRow("1")]
        [DataRow("2")]
        [DataRow("3")]
        [DataTestMethod]
        public void TryParse_ValidVersion_ReturnsTrueAndPopulatesDataFragment(string version)
        {
            var dkimSignature = $"v={version}; a=rsa-sha256; d=domain.com; s=myselector; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignature, out var dkimHeaderDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimHeaderDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [DataRow("a")]
        [DataRow("a1")]
        [DataTestMethod]
        public void TryParse_InvalidVersion_ReturnsTrueAndPopulatesDataFragment(string version)
        {
            var dkimSignature = $"v={version}; a=rsa-sha256; d=domain.com; s=myselector; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignature, out var dkimHeaderDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimHeaderDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }
    }
}
