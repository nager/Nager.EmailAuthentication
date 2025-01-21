namespace Nager.EmailAuthentication.UnitTest.DkimHeaderParserTests
{
    [TestClass]
    public sealed class SelectorTest
    {
        [DataRow("selector1")]
        [DataRow("selector2")]
        [DataRow("google")]
        [DataTestMethod]
        public void TryParse_ValidVersionDkimHeaderString_ReturnsTrueAndPopulatesDataFragment(string selector)
        {
            var dkimHeader = $"v=1; a=rsa-sha256; d=domain.com; s={selector}; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimHeaderParser.TryParse(dkimHeader, out var dkimHeaderDataFragment, out var parseErrors);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimHeaderDataFragment);
            Assert.IsNull(parseErrors, "ParseErrors is not null");
        }

        [DataRow("verylongandinvalidselectorverylongandinvalidselectorverylongandinvalidselector")]
        [DataTestMethod]
        public void TryParse_InvalidVersionDkimHeaderString_ReturnsTrueAndPopulatesDataFragment(string selector)
        {
            var dkimHeader = $"v=1; a=rsa-sha256; d=domain.com; s={selector}; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimHeaderParser.TryParse(dkimHeader, out var dkimHeaderDataFragment, out var parseErrors);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimHeaderDataFragment);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
        }
    }
}
