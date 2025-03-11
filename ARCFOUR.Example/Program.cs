using System.Text;
using Maniekko.Cryptography;

namespace ARCFOUR.Example
{
    internal static class Program
    {
        private static string[] TestInputs =
        [
            "Plaintext",
            "!(Special)!",
            "Кириллица",
        ];
        private const string SecretKey = "Top secret!";
        private static readonly Encoding TextEncoding = Encoding.Unicode;

        private static void Main()
        {
            WriteLineColored("RC4 implementations example by Maniekko", ConsoleColor.Yellow);

            // ----- Initialization 
            List<byte[]> testInputsBytes = [];
            foreach (string inputString in TestInputs)
            {
                byte[] inputBytes = TextEncoding.GetBytes(inputString);
                testInputsBytes.Add(inputBytes);
            }
            byte[] secretKeyBytes = TextEncoding.GetBytes(SecretKey);
            Console.WriteLine($"Text encoding used for converting text to bytes: \"{TextEncoding.EncodingName}\"");
            Console.WriteLine($"Secret key used for encoding: \"{SecretKey}\"");
            Console.WriteLine($"Secret key bytes (in Hexadecimal form): \"{Convert.ToHexString(secretKeyBytes)}\"");
            Console.WriteLine();

            // i could use reflection to not copy-paste tests, but that would look ugly.
            WriteLineColored("----- RC4 test -----", ConsoleColor.Cyan);
            for (int i = 0; i < TestInputs.Length; i++)
            {
                // Encode
                Console.WriteLine($"Input: \"{TestInputs[i]}\"");
                byte[] cipherBytes = RC4.Apply(testInputsBytes[i], secretKeyBytes);
                Console.WriteLine($"Encoded bytes (in Hexadecimal form): \"{Convert.ToHexString(cipherBytes)}\"");

                // Decode
                byte[] outputBytes = RC4.Apply(cipherBytes, secretKeyBytes);
                string decodedOutputString = TextEncoding.GetString(outputBytes);
                bool inputMatchesOutput = string.Equals(TestInputs[i], decodedOutputString);

                // Output to console
                Console.WriteLine($"Decoded text: \"{decodedOutputString}\"");
                Console.Write($"Input matches output: ");
                WriteLineColored(inputMatchesOutput, inputMatchesOutput ? ConsoleColor.DarkGreen : ConsoleColor.Red);
                Console.WriteLine();
            }

            WriteLineColored("----- RC4A test -----", ConsoleColor.Cyan);
            string additionalKey = new string(SecretKey.Reverse().ToArray())!;
            byte[] additionalKeyBytes = TextEncoding.GetBytes(additionalKey);
            WriteLineColored($"[!] Additional key used: {additionalKey}", ConsoleColor.Yellow);
            WriteLineColored($"[!] Additional key bytes (in Hexadecimal form): \"{Convert.ToHexString(secretKeyBytes)}\"", ConsoleColor.Yellow);
            for (int i = 0; i < TestInputs.Length; i++)
            {
                // Encode
                Console.WriteLine($"Input: \"{TestInputs[i]}\"");
                byte[] cipherBytes = RC4A.Apply(testInputsBytes[i], secretKeyBytes, additionalKeyBytes);
                Console.WriteLine($"Encoded bytes (in Hexadecimal form): \"{Convert.ToHexString(cipherBytes)}\"");

                // Decode
                byte[] outputBytes = RC4A.Apply(cipherBytes, secretKeyBytes, additionalKeyBytes);
                string decodedOutputString = TextEncoding.GetString(outputBytes);
                bool inputMatchesOutput = string.Equals(TestInputs[i], decodedOutputString);

                // Output to console
                Console.WriteLine($"Decoded text: \"{decodedOutputString}\"");
                Console.Write($"Input matches output: ");
                WriteLineColored(inputMatchesOutput, inputMatchesOutput ? ConsoleColor.DarkGreen : ConsoleColor.Red);
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Helper function to output colored text to console
        /// </summary>
        private static void WriteLineColored(object text, ConsoleColor color)
        {
            ConsoleColor prevColor = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ForegroundColor = prevColor;
        }
    }
}
