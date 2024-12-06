namespace Nager.EmailAuthentication.KeyValueParser
{
    /// <summary>
    /// Interface Key Value Parser
    /// </summary>
    public interface IKeyValueParser
    {
        /// <summary>
        /// Parse
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        ParseResult Parse(string input);
    }
}
