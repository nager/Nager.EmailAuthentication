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
        /// <param name="spfString"></param>
        /// <param name="spfDataFragment"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? spfString,
            [NotNullWhen(true)] out SpfRecordDataFragmentV1? spfDataFragment)
        {
            var spfPrefix = "v=spf1 ";

            if (string.IsNullOrWhiteSpace(spfString))
            {
                spfDataFragment = null;
                return false;
            }

            if (!spfString.StartsWith(spfPrefix, StringComparison.OrdinalIgnoreCase))
            {
                spfDataFragment = null;
                return false;
            }

            var spfTerms = new List<SpfTerm>();
            var mechanismTypes = new Dictionary<string, Type>
            {
                { Ip4Mechanism.MechanismKey,      typeof(Ip4Mechanism) },
                { Ip6Mechanism.MechanismKey,      typeof(Ip6Mechanism) },
                { IncludeMechanism.MechanismKey,  typeof(IncludeMechanism) },
                { AMechanism.MechanismKey,        typeof(AMechanism) },
                { MxMechanism.MechanismKey,       typeof(MxMechanism) },
                { ExistsMechanism.MechanismKey,   typeof(ExistsMechanism) },
                { PtrMechanism.MechanismKey,      typeof(PtrMechanism) },
                { AllMechanism.MechanismKey,      typeof(AllMechanism) },
            };

            var modifierTypes = new Dictionary<string, Type>
            {
                { RedirectModifier.ModifierKey,   typeof(RedirectModifier) },
                { ExpModifier.ModifierKey,        typeof(ExpModifier) }
            };

            var spfTermDelimiter = ' ';
            var allowedQualifiers = new char[] { '+', '?', '~', '-' };
            var inputSpan = spfString.AsSpan()[spfPrefix.Length..];
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

                if (value.Length == 0)
                {
                    continue;
                }

                var qualifier = '+';
                var indexOfQualifier = Array.IndexOf(allowedQualifiers, value[0]);
                if (indexOfQualifier != -1)
                {
                    qualifier = allowedQualifiers[indexOfQualifier];
                    value = value[1..];
                }

                var match = false;

                foreach (var mechanismType in mechanismTypes)
                {
                    if (!value.StartsWith(mechanismType.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (Activator.CreateInstance(mechanismType.Value) is not SpfTerm term)
                    {
                        continue;
                    }

                    term.Index = termIndex;

                    if (term is MechanismBase spfMechanism)
                    {
                        spfMechanism.SetQualifier(qualifier);

                        value = value[mechanismType.Key.Length..];
                        if (value.Length > 0)
                        {
                            spfMechanism.GetDataPart(value);
                        }

                        spfTerms.Add(spfMechanism);
                        match = true;
                        break;
                    }
                }

                if (!match)
                {
                    foreach (var modifierType in modifierTypes)
                    {
                        if (!value.StartsWith(modifierType.Key, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        if (Activator.CreateInstance(modifierType.Value) is not SpfTerm term)
                        {
                            continue;
                        }

                        term.Index = termIndex;

                        if (term is ModifierBase spfModifier)
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
                }

                if (!match)
                {
                    //Failure found no match
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
