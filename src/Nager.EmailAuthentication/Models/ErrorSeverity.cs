namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Error Severity
    /// </summary>
    public enum ErrorSeverity
    {
        /// <summary>
        /// Minor issues or informational messages
        /// </summary>
        Info,

        /// <summary>
        /// Potential issues that don't invalidate the DMARC string
        /// </summary>
        Warning,

        /// <summary>
        /// Severe issues that invalidate the DMARC string
        /// </summary>
        Critical
    }
}
