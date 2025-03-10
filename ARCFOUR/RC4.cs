namespace Maniekko.Cryptography
{
    public static class RC4
    {
        /// <summary>
        /// Apply RC4 encoding to a input array of bytes, with a specified key. <para/>
        /// RC4 is symmetrical, so the same method is used for both data encoding and decoding.
        /// </summary>
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
            for(long pos=0; pos < input.LongLength; pos++)
            {
                i = (byte)((i + 1) % 256);
                j = (byte)((j + State[i]) % 256);
                (State[i], State[j]) = (State[j], State[i]); // Swap State[i] and State[j]
                byte t = (byte)((State[i] + State[j]) % 256);
                byte k = State[t];
                result[pos] = (byte)(input[pos] ^ k);
            }

            return result;
        }
    }
}
