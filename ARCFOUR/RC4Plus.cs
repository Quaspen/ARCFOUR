namespace Maniekko.Cryptography
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso href="https://eprint.iacr.org/2008/396"/>
    public static class RC4Plus
    {
        public static byte[] Apply(byte[] input, byte[] key)
        {
            // RC4Plus uses different version of KSA, named KSA+, which consists of 3 layers:

            // 1) The initialization and basic scrambling in the
            //    first layer are the same as the original RC4
            // (Identity permutation of bytes)
            byte i, j;
            byte[] State = new byte[256];
            for (i = 0; i < 255; i++)
            {
                State[i] = i;
            }
            // (Scrambling)
            j = 0;
            for (i = 0; i < 255; i++)
            {
                j = (byte)((j + State[i] + key[i % key.Length]) % 256);
                (State[i], State[j]) = (State[j], State[i]); // Swap State[i] and State[j]
            }

            // 2) Scrambling with IV (Initializtion Vector)
            

            return result;

        }
    }
}
