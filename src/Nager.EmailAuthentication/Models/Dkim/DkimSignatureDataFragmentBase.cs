﻿namespace Nager.EmailAuthentication.Models.Dkim
{
    /// <summary>
    /// Dkim Signature Data Fragment Base
    /// </summary>
    public class DkimSignatureDataFragmentBase
    {
        /// <summary>
        /// Dkim Version <strong>(v=)</strong>
        /// </summary>
        public string? Version { get; set; }
    }
}
