namespace Maniekko.Cryptography
{
    /// <summary>
    /// Represents an implementation of Rivest Cipher 4 (RC4) symmetrical stream cipher algorithm
    /// </summary>
    /// <seealse href="https://en.wikipedia.org/wiki/RC4"/>
    public static class RC4
    {
        /// <summary>
        /// Apply RC4 encoding to a input array of bytes, with a specified key. 
        /// </summary>
        /// <remarks>
        /// RC4 is symmetrical, so the same method is used for both data encoding and decoding.
        /// </remarks>
        /// <param name="input">Array of bytes to be encoded.</param>
        /// <param name="key">Key for encoding.</param>
        /// <returns>Encypted array of bytes.</returns>
        public static byte[] Apply(byte[] input, byte[] key)
        {
            byte i, j;

            // State is first initialized with a identity permutation of bytes
            byte[] State = new byte[256];
            for (i = 0; i < 255; i++)
                State[i] = i;

            // State is then processed with PRGA with keys bytes mixed in.
            j = 0;
            for (i = 0; i < 255; i++)
            {
                j = (byte)((j + State[i] + key[i % key.Length]) % 256);
                (State[i], State[j]) = (State[j], State[i]); // Swap State[i] and State[j]
            }

            // For each byte of input, PRGA is used for getting the ciphertext of that byte.
            // RC4 is symmetrical, meaning applying this algorithm 
            // for ciphertext will return the initial text
            i = 0;
            j = 0;
            byte[] result = new byte[input.Length];
            for (long streamPosition = 0; streamPosition < input.LongLength; streamPosition++)
            {
                i = (byte)((i + 1) % 256);
                j = (byte)((j + State[i]) % 256);
                (State[i], State[j]) = (State[j], State[i]); // Swap State[i] and State[j]
                byte statePos = (byte)((State[i] + State[j]) % 256);
                result[streamPosition] = (byte)(input[streamPosition] ^ State[statePos]);
            }

            return result;
        }
    }
}
