namespace Nager.EmailAuthentication.UnitTest.DkimHeaderParserTests
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
            var dkimHeader = $"v={version}; a=rsa-sha256; d=domain.com; s=myselector; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimHeaderParser.TryParse(dkimHeader, out var dkimHeaderDataFragment, out var parseErrors);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimHeaderDataFragment);
            Assert.IsNull(parseErrors, "ParseErrors is not null");
        }

        [DataRow("a")]
        [DataRow("a1")]
        [DataTestMethod]
        public void TryParse_InvalidVersion_ReturnsTrueAndPopulatesDataFragment(string version)
        {
            var dkimHeader = $"v={version}; a=rsa-sha256; d=domain.com; s=myselector; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimHeaderParser.TryParse(dkimHeader, out var dkimHeaderDataFragment, out var parseErrors);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimHeaderDataFragment);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
        }
    }
}
