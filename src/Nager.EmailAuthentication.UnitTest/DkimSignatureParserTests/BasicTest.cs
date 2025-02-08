using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication.UnitTest.DkimSignatureParserTests
{
    [TestClass]
    public sealed class BasicTest
    {
        [TestMethod]
        public void TryParse_ValidDkimSignature1_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimSignature = "v=1; a=rsa-sha256; c=relaxed/simple; q=dns/txt; d=domain.com; i=noreply@domain.com; s=mailjet; x=1737017824; h=message-id:from:from:reply-to:to:to:subject:subject:date:date:list-unsubscribe-post:list-unsubscribe:feedback-id:x-csa-complaints:x-mj-mid:x-report-abuse-to:mime-version:content-type; bh=TyN/x6t3AOfI298rgJAgZHgdWcq/XLISGen5nN3NLAc=; b=HLCLiikV92Ku/k9mGlZM0bmqPjKggGnMI0igqhXmPRzPJUC+5SUWRS6/FLUpxbX6AUGJRDYQnKKMtp6uZkYVuKG8SPZ01cUkvIiiAkczb4bK6IVvPbZOnsWqHkD6EvK3TrpIhgFfGLlcG+zIwgdDZ3O++uhpJkIX1WJlkXZYqxQ=";

            var isSuccessful = DkimSignatureDataFragmentParser.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_ValidDkimSignature_ReturnsTrueAndDkimSignature()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; c=relaxed/simple; q=dns/txt; d=domain.com; i=noreply@domain.com; s=mailjet; x=1737017824; h=message-id:from:from:reply-to:to:to:subject:subject:date:date:list-unsubscribe-post:list-unsubscribe:feedback-id:x-csa-complaints:x-mj-mid:x-report-abuse-to:mime-version:content-type; bh=TyN/x6t3AOfI298rgJAgZHgdWcq/XLISGen5nN3NLAc=; b=HLCLiikV92Ku/k9mGlZM0bmqPjKggGnMI0igqhXmPRzPJUC+5SUWRS6/FLUpxbX6AUGJRDYQnKKMtp6uZkYVuKG8SPZ01cUkvIiiAkczb4bK6IVvPbZOnsWqHkD6EvK3TrpIhgFfGLlcG+zIwgdDZ3O++uhpJkIX1WJlkXZYqxQ=";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsTrue(isSuccessful);

            Assert.IsNotNull(parsingResults);
            Assert.IsTrue(parsingResults.Length > 0);
            
            Assert.IsNotNull(dkimSignature);
            Assert.AreEqual("1", dkimSignature.Version);
            Assert.AreEqual(SignatureAlgorithm.RsaSha256, dkimSignature.SignatureAlgorithm);
            Assert.AreEqual(CanonicalizationType.Relaxed, dkimSignature.MessageCanonicalizationHeader);
            Assert.AreEqual(CanonicalizationType.Simple, dkimSignature.MessageCanonicalizationBody);
            Assert.AreEqual("dns/txt", dkimSignature.QueryMethods);
            Assert.AreEqual("domain.com", dkimSignature.SigningDomainIdentifier);
            Assert.AreEqual("noreply@domain.com", dkimSignature.AgentOrUserIdentifier);
            Assert.AreEqual("mailjet", dkimSignature.Selector);
            Assert.AreEqual(new DateTimeOffset(2025, 1, 16, 8, 57, 4, TimeSpan.Zero), dkimSignature.SignatureExpiration);
            Assert.AreEqual(18, dkimSignature.SignedHeaderFields.Length);
            Assert.AreEqual("TyN/x6t3AOfI298rgJAgZHgdWcq/XLISGen5nN3NLAc=", dkimSignature.BodyHash);
            Assert.AreEqual("HLCLiikV92Ku/k9mGlZM0bmqPjKggGnMI0igqhXmPRzPJUC+5SUWRS6/FLUpxbX6AUGJRDYQnKKMtp6uZkYVuKG8SPZ01cUkvIiiAkczb4bK6IVvPbZOnsWqHkD6EvK3TrpIhgFfGLlcG+zIwgdDZ3O++uhpJkIX1WJlkXZYqxQ=", dkimSignature.SignatureData);
        }
    }
}
