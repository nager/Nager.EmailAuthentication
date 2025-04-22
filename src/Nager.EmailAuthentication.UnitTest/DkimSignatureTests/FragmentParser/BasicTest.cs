using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models;

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
            var dkimSignature = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=\tdomain.com; h=cc:content-type:content-type:date:date\t:feedback-id:feedback-id:from:from:in-reply-to:message-id\t:mime-version:reply-to:subject:subject:to:to:x-me-proxy\t:x-me-sender:x-me-sender:x-sasl-enc; s=fm2; t=1745335784; x=\t1745422184; bh=xaB6q5eOaduj6x70tDxwBNy7rJTejazDBdT+WsewRKw=; b=E\tQ/mLssK64d4QUX83KuBeqAyPHgXI9lMNH3aiemXdgTOJukRuU28gmeuuL0uyp4ca\tIYIObYggaI+Q69W7SbNlIWRLAoWwi+9H1dPQ/7MJndenkHmwWKTlL5m5uPGtksge\t6yvbJYdR2poDiKA5nAowi8La9Jg1AubTV4TkctpPDejBqLKd9sYPY2oP6QcbKna3\teAw16V4n3Pi82+deH7+V38a0wwmZZb7+0omuSM2j1s2wBVg70vGdPY5wINudvtFp\tswSKhMdr8n6vS5omFOWAFvkYFnm3W4PLi9+XPAYznpo4lZg4Zsl0iigAJk1ytcSh\thQtwY3ewvD0gxbjw5p1Kw==";
            //TODO: Add logic for removing tabs

            var isSuccessful = DkimSignatureDataFragmentParserV1.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_ValidDkimSignatureWithSpaces_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimSignature = "v=1; a=rsa-sha256; c=relaxed/relaxed;        d=domain.com; s=google; t=1744644510; x=1745249310; darn=audit.mailtower.app;        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject         :date:message-id:reply-to;        bh=w69OA+I6wWRcn0DkZDv7yYmnjGR7+kWh6VX1cEfJdUs=;        b=T2Xje/yAu4r88I7E5E36zHFrbF5Cv5x+Fb15kUxkf//d5cYcl9bX1LTPrj9V5DZskl         ErTozaI7s6BXdo3IoHq6ZX8TvbVTDTuP7d7bkdiW16twzl8OpT3pW04T1HjElz464v37         MwLSS4ZX48pGv2IWv/EVAKQUUfr2OMIs4mC5ZjtCWBTZ2n1BtVBaM6ZBCRUK72t6HfXP         X54HFf5jZo+I4gqZGsd7ZrXF/TISHTt1493IIJNp9J1Q9dVwNlJ2lELr66LBAld0gI8C         aFQ71Bxa5ahcl6w+k9OSiPP0apwY+QC3KYkSnGYoswIoSOgZGJETdNkePd447kiH8MkU         ikMg==";
            //TODO: Add logic for removing spaces

            var isSuccessful = DkimSignatureDataFragmentParserV1.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is not null");
        }
    }
}
