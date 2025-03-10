using System.Text;
using Maniekko.Cryptography;

namespace ARCFOUR.Example
{
    internal class Program
    {
        private static void Main()
        {
            string input = "Plaintext";
            string key = "Key";

            // Encode
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);
            byte[] cipherBytes = RC4.Apply(inputBytes, keyBytes);
            Console.WriteLine($"Encoded text (in Hexadecimal form): \"{Convert.ToHexString(cipherBytes)}\"");

            // Decode
            byte[] outputBytes = RC4.Apply(cipherBytes, keyBytes);
            Console.WriteLine($"Decoded source text: \"{Encoding.ASCII.GetString(outputBytes)}\"");
        }
    }
}
