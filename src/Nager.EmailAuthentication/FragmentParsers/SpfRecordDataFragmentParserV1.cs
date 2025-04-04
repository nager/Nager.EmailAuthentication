using Nager.EmailAuthentication.Models.Spf;
using Nager.EmailAuthentication.Models.Spf.Mechanisms;
using Nager.EmailAuthentication.Models.Spf.Modifiers;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication.FragmentParsers
{
    /// <summary>
    /// Spf Record Data Fragment Parser
    /// </summary>
    public static class SpfRecordDataFragmentParserV1
    {
        /// <summary>
        /// Try Parse
        /// </summary>
        /// <param name="spf"></param>
        /// <param name="spfDataFragment"></param>
        /// <returns></returns>
        public static bool TryParse(
            string spf,
            [NotNullWhen(true)] out SpfRecordDataFragmentV1? spfDataFragment)
        {
            var spfPrefix = "v=spf1 ";

            if (!spf.StartsWith(spfPrefix, StringComparison.OrdinalIgnoreCase))
            {
                spfDataFragment = null;
                return false;
            }

            var spfTerms = new List<SpfTerm>();
            var mechanismTypes = new Dictionary<string, Type>
            {
                { AllMechanism.MechanismKey,      typeof(AllMechanism) },
                { Ip4Mechanism.MechanismKey,      typeof(Ip4Mechanism) },
                { Ip6Mechanism.MechanismKey,      typeof(Ip6Mechanism) },
                { IncludeMechanism.MechanismKey,  typeof(IncludeMechanism) },
                { ExistsMechanism.MechanismKey,   typeof(ExistsMechanism) },
                { AMechanism.MechanismKey,        typeof(AMechanism) },
                { MxMechanism.MechanismKey,       typeof(MxMechanism) },
                { PtrMechanism.MechanismKey,      typeof(PtrMechanism) },
            };

            var modifierTypes = new Dictionary<string, Type>
            {
                { RedirectModifier.ModifierKey,   typeof(RedirectModifier) },
                { ExpModifier.ModifierKey,        typeof(ExpModifier) }
            };

            var spfTermDelimiter = ' ';
            var allowedQualifiers = new char[] { '+', '?', '~', '-' };
            var inputSpan = spf.AsSpan()[spfPrefix.Length..];
            var nextIndexOfDelimiter = 0;
            var termIndex = 0;

            while (nextIndexOfDelimiter != -1)
            {
                termIndex++;

                nextIndexOfDelimiter = inputSpan.IndexOf(spfTermDelimiter);
                if (nextIndexOfDelimiter == 0)
                {
                    inputSpan = inputSpan[1..];
                    continue;
                }

                ReadOnlySpan<char> value;
                if (nextIndexOfDelimiter == -1)
                {
                    value = inputSpan.Trim();
                }
                else
                {
                    value = inputSpan[..nextIndexOfDelimiter].Trim();
                }

                var qualifier = '+';
                var indexOfQualifier = Array.IndexOf(allowedQualifiers, value[0]);
                if (indexOfQualifier != -1)
                {
                    qualifier = allowedQualifiers[indexOfQualifier];
                    value = value[1..];
                }

                foreach (var mechanismType in mechanismTypes)
                {
                    if (!value.StartsWith(mechanismType.Key))
                    {
                        continue;
                    }

                    var term = Activator.CreateInstance(mechanismType.Value) as SpfTerm;
                    if (term is null)
                    {
                        continue;
                    }

                    term.Index = termIndex;

                    if (term is SpfMechanismBase spfMechanism)
                    {
                        spfMechanism.SetQualifier(qualifier);

                        value = value[mechanismType.Key.Length..];
                        if (value.Length > 0)
                        {
                            spfMechanism.GetDataPart(value);
                        }

                        spfTerms.Add(spfMechanism);
                        break;
                    }
                }

                foreach (var modifierType in modifierTypes)
                {
                    if (!value.StartsWith(modifierType.Key))
                    {
                        continue;
                    }

                    var term = Activator.CreateInstance(modifierType.Value) as SpfTerm;
                    if (term is null)
                    {
                        continue;
                    }

                    term.Index = termIndex;

                    if (term is SpfModifierBase spfModifier)
                    {
                        value = value[modifierType.Key.Length..];
                        if (value.Length > 0)
                        {
                            spfModifier.GetDataPart(value);
                        }

                        spfTerms.Add(spfModifier);
                        break;
                    }
                }

                inputSpan = inputSpan[(nextIndexOfDelimiter + 1)..];
            }

            spfDataFragment = new SpfRecordDataFragmentV1
            {
                Version = "1",
                SpfTerms = [.. spfTerms]
            };

            return true;
        }
    }
}
