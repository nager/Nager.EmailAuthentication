namespace Nager.EmailAuthentication.Models
{
    internal class ValidateRequest
    {
        internal required string Field { get; set; }
        internal string? Value { get; set; }
    }
}
