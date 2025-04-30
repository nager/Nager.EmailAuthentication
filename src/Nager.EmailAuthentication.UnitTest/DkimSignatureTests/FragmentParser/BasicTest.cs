using Nager.EmailAuthentication.FragmentParsers;

namespace Nager.EmailAuthentication.UnitTest.DkimSignatureTests.FragmentParser
{
    [TestClass]
    public sealed class BasicTest
    {
        [TestMethod]
        public void TryParse_ValidDkimSignature1_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimSignature = "v=1; a=rsa-sha256; c=relaxed/simple; q=dns/txt; d=domain.com; i=noreply@domain.com; s=mailjet; x=1737017824; h=message-id:from:from:reply-to:to:to:subject:subject:date:date:list-unsubscribe-post:list-unsubscribe:feedback-id:x-csa-complaints:x-mj-mid:x-report-abuse-to:mime-version:content-type; bh=TyN/x6t3AOfI298rgJAgZHgdWcq/XLISGen5nN3NLAc=; b=HLCLiikV92Ku/k9mGlZM0bmqPjKggGnMI0igqhXmPRzPJUC+5SUWRS6/FLUpxbX6AUGJRDYQnKKMtp6uZkYVuKG8SPZ01cUkvIiiAkczb4bK6IVvPbZOnsWqHkD6EvK3TrpIhgFfGLlcG+zIwgdDZ3O++uhpJkIX1WJlkXZYqxQ=";

            var isSuccessful = DkimSignatureDataFragmentParserV1.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_ValidDkimSignatureWithTabs_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimSignature = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=domain.com;\r\n s=testselector;\r\n h=From:Date:Subject:Message-ID:Content-Type:MIME-Version\r\n :X-MS-Exchange-SenderADCheck;\r\n bh=qxq6it6URJf9QDr82aTOS1esfmgKTsALYByECu5Ypjo=;\r\n b=Ps4k/pVqXOLkxP1x8YJL+ofgVAfNYNPGT0ln4pSQ5M7T+KTND8ijzYrPIocjiE40qLmQAnccrxMRS56weM2Jgb4F0cXkWJop1wJnUmKsFpMOYzaIXKUy4XnTaakR592E5t9ejoAgZIfE/jl3fcjKUIhNZuDGCSUYDAd64a1UndacEG+efXBG57bclUNmzuwx2tHXTBdKLecm0fZ0ST2OfAosrE8lwFyprzxSEoOFb8/PiA20MI1b2tMg7tH0pOcbLkdTHiSvkGuQFTvX87zCJk6WxW92bEP35kekPlqiFDKjpC5cVoIuC5UN9cHTsWvJLanaJJI+Ol9GB18dmqmCKw==";
            //TODO: Add logic for removing tabs and line breaks

            var isSuccessful = DkimSignatureDataFragmentParserV1.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_ValidDkimSignatureWithSpaces_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimSignature = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=\r\n\tdomain.com; h=cc:content-type:content-type:date:date\r\n\t:feedback-id:feedback-id:from:from:in-reply-to:message-id\r\n\t:mime-version:reply-to:subject:subject:to:to:x-me-proxy\r\n\t:x-me-sender:x-me-sender:x-sasl-enc; s=testselector; t=1745335784; x=\r\n\t1745422184; bh=xaB6q5eOaduj6x70tDxwBNy7rJTejazDBdT+WsewRKw=; b=E\r\n\tQ/mLssK64d4QUX83KuBeqAyPHgXI9lMNH3aiemXdgTOJukRuU28gmeuuL0uyp4ca\r\n\tIYIObYggaI+Q69W7SbNlIWRLAoWwi+9H1dPQ/7MJndenkHmwWKTlL5m5uPGtksge\r\n\t6yvbJYdR2poDiKA5nAowi8La9Jg1AubTV4TkctpPDejBqLKd9sYPY2oP6QcbKna3\r\n\teAw16V4n3Pi82+deH7+V38a0wwmZZb7+0omuSM2j1s2wBVg70vGdPY5wINudvtFp\r\n\tswSKhMdr8n6vS5omFOWAFvkYFnm3W4PLi9+XPAYznpo4lZg4Zsl0iigAJk1ytcSh\r\n\thQtwY3ewvD0gxbjw5p1Kw==";
            //TODO: Add logic for removing spaces and line breaks

            var isSuccessful = DkimSignatureDataFragmentParserV1.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is not null");
        }
    }
}
