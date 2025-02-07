using System.Text.RegularExpressions;

namespace Nager.EmailAuthentication.RegexProviders
{
    internal static partial class DkimSelectorRegexProvider
    {
        [GeneratedRegex("^[a-z0-9]{1}[a-z0-9-]*[a-z0-9]{1}$", RegexOptions.IgnoreCase)]
        internal static partial Regex GetRegex();
    }
}
