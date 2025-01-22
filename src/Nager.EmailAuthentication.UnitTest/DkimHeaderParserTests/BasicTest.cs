namespace Nager.EmailAuthentication.UnitTest.DkimHeaderParserTests
{
    [TestClass]
    public sealed class BasicTest
    {
        [TestMethod]
        public void TryParse_ValidDkimHeaderString1_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimHeader = "v=1; a=rsa-sha256; c=relaxed/simple; q=dns/txt; d=domain.com; i=noreply@domain.com; s=mailjet; x=1737017824; h=message-id:from:from:reply-to:to:to:subject:subject:date:date:list-unsubscribe-post:list-unsubscribe:feedback-id:x-csa-complaints:x-mj-mid:x-report-abuse-to:mime-version:content-type; bh=TyN/x6t3AOfI298rgJAgZHgdWcq/XLISGen5nN3NLAc=; b=HLCLiikV92Ku/k9mGlZM0bmqPjKggGnMI0igqhXmPRzPJUC+5SUWRS6/FLUpxbX6AUGJRDYQnKKMtp6uZkYVuKG8SPZ01cUkvIiiAkczb4bK6IVvPbZOnsWqHkD6EvK3TrpIhgFfGLlcG+zIwgdDZ3O++uhpJkIX1WJlkXZYqxQ=";

            var isSuccessful = DkimHeaderParser.TryParse(dkimHeader, out var dkimHeaderDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimHeaderDataFragment);
            //Assert.IsNull(parsingResults, "ParsingResults is not null");
        }
    }
}
