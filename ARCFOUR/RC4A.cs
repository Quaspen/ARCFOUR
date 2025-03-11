namespace Maniekko.Cryptography
{
    /// <summary>
    /// Represents an implementation of RC4A (variant of the Rivest Cipher 4) symmetrical stream cipher algorithm
    /// </summary>
    /// <seealso href="https://link.springer.com/chapter/10.1007/978-3-540-25937-4_16"/>
    public static class RC4A
    {
        /// <summary>
        /// Apply RC4A encoding to a input array of bytes, using two specified keys.
        /// </summary>
        /// <remarks>
        /// RC4A is symmetrical, so the same method is used for both data encoding and decoding.
        /// </remarks>
        /// <param name="input"/>
        /// <param name="key1">Key to use for encoding. Keys can match</param>
        /// <param name="key2">Second key to use for encoding. Keys can match</param>
        /// <returns>Encypted array of bytes.</returns>
        public static byte[] Apply(byte[] input, byte[] key1, byte[] key2)
        {
            // Both states are initialized with a identity permutation of bytes.
            byte[] State1 = new byte[256];
            byte[] State2 = new byte[256];
            for (byte i = 0; i < 255; i++)
            {
                State1[i] = i;
                State2[i] = i;
            }

            // For each byte of input, PRGA is used for getting the ciphertext of that byte.
            // RC4A is symmetrical, meaning applying this algorithm 
            // for ciphertext will return the initial text
            byte j1 = 0, j2 = 0;
            byte[] result = new byte[input.Length];

            for (long streamPos = 0; streamPos < input.LongLength; streamPos++)
            {
                byte i = (byte)(streamPos % 256);
                j1 = (byte)((j1 + State1[i]) % 256);
                (State1[i], State1[j1]) = (State1[j1], State1[i]);
                result[i] = (byte)(input[i] ^ State2[(State1[i] + State1[j1]) % 256]);

                j2 = (byte)((j2 + State2[i]) % 256);
                (State2[i], State2[j2]) = (State2[j2], State2[i]);
                result[streamPos] = (byte)(input[streamPos] ^ State1[(State2[i] + State2[j2]) % 256]);
            }

            return result;
        }
    }
}
