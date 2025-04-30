using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models.Spf;
using Nager.EmailAuthentication.Models.Spf.Mechanisms;
using Nager.EmailAuthentication.Models.Spf.Modifiers;

namespace Nager.EmailAuthentication.UnitTest.SpfRecordParserTest.FragmentParser
{
    [TestClass]
    public sealed class BasicTest
    {
        [TestMethod]
        public void Should_Parse_Spf_With_Include_And_All()
        {
            var spf = "v=spf1 include:spf.protection.outlook.com -all";
            var isSuccessful = SpfRecordDataFragmentParserV1.TryParse(spf, out var spfDataFragment);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(spfDataFragment);
            Assert.IsNotNull(spfDataFragment.SpfTerms);
            Assert.AreEqual(2, spfDataFragment.SpfTerms.Length);


            if (spfDataFragment.SpfTerms[0] is SpfModifierBase spfModifier)
            {
                Assert.Fail("Wrong mapping, is not a modifier");
            }

            if (spfDataFragment.SpfTerms[0] is not SpfMechanismBase spfMechanism)
            {
                Assert.Fail("Wrong mapping, is a mechanism");
                return;
            }

            Assert.AreEqual(MechanismType.Include, spfMechanism.MechanismType);
            Assert.AreEqual("spf.protection.outlook.com", spfMechanism.MechanismData);
            Assert.AreEqual(SpfQualifier.Pass, spfMechanism.Qualifier);
        }

        [TestMethod]
        public void Should_Parse_Spf_With_Redirect()
        {
            var spf = "v=spf1 redirect=spf.provider.com";
            var isSuccessful = SpfRecordDataFragmentParserV1.TryParse(spf, out var spfDataFragment);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(spfDataFragment);
            Assert.IsNotNull(spfDataFragment.SpfTerms);
            Assert.AreEqual(1, spfDataFragment.SpfTerms.Length);

            if (spfDataFragment.SpfTerms[0] is SpfMechanismBase spfMechanism)
            {
                Assert.Fail("Wrong mapping, is not a mechanism");
            }

            if (spfDataFragment.SpfTerms[0] is not SpfModifierBase spfModifier)
            {
                Assert.Fail("Wrong mapping, is a modifier");
                return;
            }

            Assert.AreEqual(ModifierType.Redirect, spfModifier.ModifierType);
            Assert.AreEqual("spf.provider.com", spfModifier.ModifierData);
        }

        [TestMethod]
        public void Should_Parse_Spf_With_Multiple_Ip4_And_Include()
        {
            var spf = "v=spf1 ip4:155.56.66.96/30 ip4:155.56.66.102/31 ip4:155.56.66.104/32 ip4:155.56.66.106/32 ip4:155.56.68.128/26 include:spf.protection.outlook.com -all";
            var isSuccessful = SpfRecordDataFragmentParserV1.TryParse(spf, out var spfDataFragment);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(spfDataFragment);
            Assert.IsNotNull(spfDataFragment.SpfTerms);
            Assert.AreEqual(7, spfDataFragment.SpfTerms.Length);
        }
    }
}
