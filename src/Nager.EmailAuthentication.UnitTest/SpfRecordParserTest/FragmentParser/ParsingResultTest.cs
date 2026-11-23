using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models;
using Nager.EmailAuthentication.Models.Spf;
using Nager.EmailAuthentication.Models.Spf.Mechanisms;
using Nager.EmailAuthentication.Models.Spf.Modifiers;

namespace Nager.EmailAuthentication.UnitTest.SpfRecordParserTest.FragmentParser
{
    [TestClass]
    public sealed class ParsingResultTest
    {
        [TestMethod]
        public void Should_Parse_Spf_Without_ParsingResults()
        {
            var spf = "v=spf1 a mx:example.com ip4:192.0.2.0/24 ip6:2001:db8::/32 include:example.net exists:%{i}.example.org ptr ~all";

            var isSuccessful = SpfRecordDataFragmentParserV1.TryParse(spf, out var spfDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(spfDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(8, spfDataFragment.SpfTerms.Length);
        }

        [DataRow("v=spf1")]
        [DataRow("V=SPF1")]
        [DataRow("v=spf1 ")]
        [TestMethod]
        public void Should_Parse_Spf_With_Version_Only(string spf)
        {
            var isSuccessful = SpfRecordDataFragmentParserV1.TryParse(spf, out var spfDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(spfDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(0, spfDataFragment.SpfTerms.Length);
        }

        [DataRow("v=spf10 -all")]
        [DataRow("v=spf1-all")]
        [DataRow("v=spf2.0/pra -all")]
        [DataRow("spf1 -all")]
        [TestMethod]
        public void Should_Not_Parse_Other_Version(string spf)
        {
            var isSuccessful = SpfRecordDataFragmentParserV1.TryParse(spf, out var spfDataFragment, out var parsingResults);

            Assert.IsFalse(isSuccessful);
            Assert.IsNull(spfDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [DataRow("apple")]
        [DataRow("mxfoo")]
        [DataRow("allx")]
        [DataRow("includes:example.com")]
        [DataRow("ip5:192.0.2.1")]
        [DataRow("foo")]
        [TestMethod]
        public void Should_Report_Unknown_Term_As_Error(string term)
        {
            var spf = $"v=spf1 {term} -all";

            var isSuccessful = SpfRecordDataFragmentParserV1.TryParse(spf, out var spfDataFragment, out var parsingResults);

            // Only the all mechanism is a term of the record, the name of a term has to match exactly
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(spfDataFragment);
            Assert.AreEqual(1, spfDataFragment.SpfTerms.Length);
            Assert.IsTrue(spfDataFragment.SpfTerms[0] is AllMechanism);

            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual(ParsingStatus.Error, parsingResults[0].Status);
            Assert.IsTrue(parsingResults[0].Message.Contains(term));
        }

        [TestMethod]
        public void Should_Report_Unknown_Modifier_As_Info()
        {
            var spf = "v=spf1 mx unknown=value -all";

            var isSuccessful = SpfRecordDataFragmentParserV1.TryParse(spf, out var spfDataFragment, out var parsingResults);

            // Unknown modifiers are ignored by mail receivers (RFC 7208 section 6)
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(spfDataFragment);
            Assert.AreEqual(2, spfDataFragment.SpfTerms.Length);

            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual(ParsingStatus.Info, parsingResults[0].Status);
            Assert.AreEqual("unknown", parsingResults[0].Field);
        }

        [TestMethod]
        public void Should_Parse_Mechanism_With_Cidr_And_Modifier()
        {
            var spf = "v=spf1 a/24 mx/24 a:example.com/24 redirect=example.net exp=explain.example.net";

            var isSuccessful = SpfRecordDataFragmentParserV1.TryParse(spf, out var spfDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(spfDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(5, spfDataFragment.SpfTerms.Length);

            Assert.IsTrue(spfDataFragment.SpfTerms[0] is AMechanism);
            Assert.IsTrue(spfDataFragment.SpfTerms[1] is MxMechanism);
            Assert.IsTrue(spfDataFragment.SpfTerms[2] is AMechanism { MechanismData: "example.com/24" });
            Assert.IsTrue(spfDataFragment.SpfTerms[3] is RedirectModifier { ModifierType: ModifierType.Redirect, ModifierData: "example.net" });
            Assert.IsTrue(spfDataFragment.SpfTerms[4] is ExpModifier { ModifierData: "explain.example.net" });
        }

        [TestMethod]
        public void Should_Not_Parse_Modifier_Name_As_Mechanism()
        {
            var spf = "v=spf1 a=example.com all=example.com -all";

            var isSuccessful = SpfRecordDataFragmentParserV1.TryParse(spf, out var spfDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(spfDataFragment);
            Assert.AreEqual(1, spfDataFragment.SpfTerms.Length);
            Assert.IsTrue(spfDataFragment.SpfTerms[0] is AllMechanism { Qualifier: SpfQualifier.Fail });

            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(2, parsingResults.Length);
            Assert.IsTrue(parsingResults.All(o => o.Status == ParsingStatus.Info));
        }
    }
}
