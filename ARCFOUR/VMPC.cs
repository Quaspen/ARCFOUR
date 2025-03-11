namespace Maniekko.Cryptography
{
    /// <summary>
    /// Represents an implementation of Variably Modified Permutation Composition (VMPC) symmetrical stream cipher algorithm
    /// </summary>
    /// <seealso href="https://www.vmpcfunction.com/vmpc.pdf"/>
    public static class VMPC
    {
        /// <summary>
        /// Apply VMPC encoding to a input array of bytes, with a specified key. 
        /// </summary>
        /// <param name="input">Array of bytes to be encoded.</param>
        /// <param name="key">Key for encoding.</param>
        /// <param name="DoubleKSARuns">Whether to run Key-scheduling algorithm (KSA) two times</param>
        /// <returns>Encypted array of bytes.</returns>
        public static byte[] Apply(byte[] input, byte[] key, bool DoubleKSARuns = false)
        {
            int i, j = 0;

            // State is first initialized with a identity permutation of bytes
            byte[] State = new byte[256];
            for (i = 0; i < 255; i++)
                State[i] = (byte)i;

            // State is then processed with PRGA with keys bytes mixed in.
            // The algorithm is the same as in RC4, but is ran 768 times instead of 256
            // PRGA can be optionally ran 768 more times to incorporate an initial vector
            for (int k = 0; k < 3 * (DoubleKSARuns ? 2 : 1); k++)
            {
                for (i = 0; i < 255; i++)
                {
                    j = (byte)((j + State[i] + key[i % key.Length]) % 256);
                    (State[i], State[j]) = (State[j], State[i]); // Swap State[i] and State[j]
                }
            }

            // For each byte of input, PRGA is used for getting the ciphertext of that byte.
            // VMPC is symmetrical, meaning applying this algorithm 
            // for ciphertext will return the initial text


            i = 0;
            j = 0;
            byte[] result = new byte[input.Length];
            for (long streamPosition = 0; streamPosition < input.LongLength; streamPosition++)
            {
                i = (byte)(streamPosition % 256);
                j = State[(j + State[i]) % 256];
                byte stateByte = State[State[(State[j] + 1) % 256]];
                (State[i], State[j]) = (State[j], State[i]); // Swap State[i] and State[j]

                result[streamPosition] = (byte)(input[streamPosition] ^ stateByte);
            }

            return result;
        }
    }
}
