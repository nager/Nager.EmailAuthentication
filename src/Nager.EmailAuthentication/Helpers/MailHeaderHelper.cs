namespace Nager.EmailAuthentication.Helpers
{
    /// <summary>
    /// Mail Header Helper
    /// </summary>
    public static class MailHeaderHelper
    {
        /// <summary>
        /// Unfolding Mail Header
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        public static string UnfoldingHeader(string header)
        {
            Span<char> buffer = stackalloc char[header.Length];
            int bufferIndex = 0;
            bool newLine = false;

            for (var i = 0; i < header.Length;)
            {
                if (i < header.Length)
                {
                    if (header[i] == '\r' && header[i + 1] == '\n')
                    {
                        i += 2;
                        newLine = true;
                        continue;
                    }
                }

                if (newLine)
                {
                    newLine = false;

                    if (header[i] == '\t')
                    {
                        i++;
                        continue;
                    }

                    if (header[i] == ' ')
                    {
                        i++;
                        continue;
                    }
                }

                buffer[bufferIndex++] = header[i];
                i++;
            }

            return new string(buffer[..bufferIndex]);
        }
    }
}
