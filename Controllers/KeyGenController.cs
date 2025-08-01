using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace Shamir.Controllers
{
    public class KeyGenController : Controller
    {
        public IActionResult Index()
        {
            ViewBag.Components = new string[3];
            ViewBag.ComponentKCVs = new string[3];
            ViewBag.ComponentCKCVs = new string[3];
            ViewBag.Algorithm = "AES";
            ViewBag.ForceOdd = true;
            return View();
        }

        [HttpPost]
        public IActionResult Split(string combinedKeyHex, string algorithm = "AES", bool forceOdd = true)
        {
            if (string.IsNullOrWhiteSpace(combinedKeyHex))
            {
                ViewBag.Error = "Combined Key giriniz.";
                return Index();
            }

            combinedKeyHex = combinedKeyHex.Replace(" ", "").Replace("-", "");
            int keyByteLength = combinedKeyHex.Length / 2;

            if (!KeyLengthValid(algorithm, keyByteLength))
            {
                ViewBag.Error = $"{algorithm} için geçersiz key uzunluğu!";
                return Index();
            }

            byte[] combinedKey = Enumerable.Range(0, keyByteLength)
                .Select(i => Convert.ToByte(combinedKeyHex.Substring(i * 2, 2), 16))
                .ToArray();

            byte[] c1 = GenerateStrongKey(algorithm, keyByteLength, forceOdd);
            byte[] c2 = GenerateStrongKey(algorithm, keyByteLength, forceOdd);

            // xor
            byte[] c3 = new byte[keyByteLength];
            for (int i = 0; i < keyByteLength; i++)
                c3[i] = (byte)(combinedKey[i] ^ c1[i] ^ c2[i]);

            // KCV/CKCV
            string[] componentKCVs = new string[3];
            string[] componentCKCVs = new string[3];
            var keys = new[] { c1, c2, c3 };
            for (int i = 0; i < 3; i++)
            {
                componentKCVs[i] = CalculateKCV(keys[i], algorithm);
                componentCKCVs[i] = algorithm == "AES" ? CalculateCKCV(keys[i]) : null;
            }

            // Combined KCV/CKCV
            ViewBag.CombinedKey = BitConverter.ToString(combinedKey).Replace("-", "");
            ViewBag.KCV = CalculateKCV(combinedKey, algorithm);
            ViewBag.CKCV = algorithm == "AES" ? CalculateCKCV(combinedKey) : null;
            ViewBag.Components = new[]
            {
                BitConverter.ToString(c1).Replace("-", ""),
                BitConverter.ToString(c2).Replace("-", ""),
                BitConverter.ToString(c3).Replace("-", "")
            };
            ViewBag.ComponentKCVs = componentKCVs;
            ViewBag.ComponentCKCVs = componentCKCVs;
            ViewBag.Algorithm = algorithm;
            ViewBag.ForceOdd = forceOdd;

            return View("Index");
        }

        [HttpPost]
        public IActionResult Combine(string? component1 = null, string? component2 = null, string? component3 = null, string algorithm = "AES", bool forceOdd = true)
        {
            if (string.IsNullOrWhiteSpace(component1) || string.IsNullOrWhiteSpace(component2) || string.IsNullOrWhiteSpace(component3))
            {
                ViewBag.Error = "Tüm bileşenleri giriniz.";
                // Tüm viewbag'leri doldurup (boş diziler vs), aynı Index ekranına dön:
                ViewBag.Components = new string[3];
                ViewBag.ComponentKCVs = new string[3];
                ViewBag.ComponentCKCVs = new string[3];
                ViewBag.Algorithm = algorithm;
                ViewBag.ForceOdd = forceOdd;
                return View("Index");
            }
            string[] compsHex = new[] { component1, component2, component3 };
            byte[][] comps = new byte[3][];
            int keyByteLength = 0;

            for (int i = 0; i < 3; i++)
            {
                if (string.IsNullOrWhiteSpace(compsHex[i]))
                {
                    int fillLen = keyByteLength > 0 ? keyByteLength : 16; // Default 16 (128 bit)
                    comps[i] = GenerateStrongKey(algorithm, fillLen, forceOdd);
                }
                else
                {
                    compsHex[i] = compsHex[i].Replace(" ", "").Replace("-", "");
                    keyByteLength = compsHex[i].Length / 2;
                    comps[i] = Enumerable.Range(0, keyByteLength)
                        .Select(j => Convert.ToByte(compsHex[i].Substring(j * 2, 2), 16))
                        .ToArray();
                }
            }

            if (!KeyLengthValid(algorithm, keyByteLength))
            {
                ViewBag.Error = $"{algorithm} için geçersiz key uzunluğu!";
                return Index();
            }

            byte[] combinedKey = new byte[keyByteLength];
            for (int i = 0; i < keyByteLength; i++)
                combinedKey[i] = (byte)(comps[0][i] ^ comps[1][i] ^ comps[2][i]);

            string[] componentKCVs = new string[3];
            string[] componentCKCVs = new string[3];
            for (int i = 0; i < 3; i++)
            {
                componentKCVs[i] = CalculateKCV(comps[i], algorithm);
                componentCKCVs[i] = algorithm == "AES" ? CalculateCKCV(comps[i]) : null;
            }

            ViewBag.CombinedKey = BitConverter.ToString(combinedKey).Replace("-", "");
            ViewBag.KCV = CalculateKCV(combinedKey, algorithm);
            ViewBag.CKCV = algorithm == "AES" ? CalculateCKCV(combinedKey) : null;
            ViewBag.Components = new[]
            {
                BitConverter.ToString(comps[0]).Replace("-", ""),
                BitConverter.ToString(comps[1]).Replace("-", ""),
                BitConverter.ToString(comps[2]).Replace("-", "")
            };
            ViewBag.ComponentKCVs = componentKCVs;
            ViewBag.ComponentCKCVs = componentCKCVs;
            ViewBag.Algorithm = algorithm;
            ViewBag.ForceOdd = forceOdd;

            return View("Index");
        }

        [HttpPost]
        public IActionResult Generate(int length = 16, string algorithm = "AES", bool forceOdd = true)
        {
            if (!KeyLengthValid(algorithm, length))
            {
                ViewBag.Error = $"{algorithm} için geçersiz key uzunluğu!";
                ViewBag.Components = new string[3];
                ViewBag.ComponentKCVs = new string[3];
                ViewBag.ComponentCKCVs = new string[3];
                ViewBag.Algorithm = algorithm;
                ViewBag.ForceOdd = forceOdd;
                return View("Index");
            }

            byte[] key = GenerateStrongKey(algorithm, length, forceOdd);
            if (key == null)
            {
                ViewBag.Error = "Güçlü key üretilemedi, tekrar deneyin.";
                // ViewBag'leri doldur ve Index'e dön:
                ViewBag.Components = new string[3];
                ViewBag.ComponentKCVs = new string[3];
                ViewBag.ComponentCKCVs = new string[3];
                ViewBag.Algorithm = algorithm;
                ViewBag.ForceOdd = forceOdd;
                return View("Index");
            }
            string hex = BitConverter.ToString(key).Replace("-", "");

            ViewBag.CombinedKey = hex;
            ViewBag.KCV = CalculateKCV(key, algorithm);
            ViewBag.CKCV = algorithm == "AES" ? CalculateCKCV(key) : null;
            ViewBag.Components = new string[3];
            ViewBag.ComponentKCVs = new string[3];
            ViewBag.ComponentCKCVs = new string[3];
            ViewBag.Algorithm = algorithm;
            ViewBag.ForceOdd = forceOdd;

            return View("Index");
        }
        [HttpPost]
        [HttpPost]
        public IActionResult GenerateComp(
    int which = 1, int length = 16, string algorithm = "AES", bool forceOdd = true,
    string? component1 = null, string? component2 = null, string? component3 = null)
        {
            // Mevcut componentleri tekrar oku
            var comps = new string[3];
            comps[0] = component1 ?? "";
            comps[1] = component2 ?? "";
            comps[2] = component3 ?? "";

            // Sadece ilgili componenti random üret
            byte[] newKey = GenerateStrongKey(algorithm, length, forceOdd);
            if (newKey == null)
            {
                ViewBag.Error = "Güçlü key üretilemedi, tekrar deneyin.";
                // ViewBag'leri doldur ve Index'e dön
                ViewBag.Components = new string[3];
                ViewBag.ComponentKCVs = new string[3];
                ViewBag.ComponentCKCVs = new string[3];
                ViewBag.Algorithm = algorithm;
                ViewBag.ForceOdd = forceOdd;
                return View("Index");
            }
            comps[which - 1] = BitConverter.ToString(newKey).Replace("-", "");

            // KCV/CKCV güncelle
            string[] componentKCVs = new string[3];
            string[] componentCKCVs = new string[3];
            for (int i = 0; i < 3; i++)
            {
                if (!string.IsNullOrWhiteSpace(comps[i]) && comps[i].Length % 2 == 0)
                {
                    byte[] keyBytes = Enumerable.Range(0, comps[i].Length / 2)
                                        .Select(j => Convert.ToByte(comps[i].Substring(j * 2, 2), 16))
                                        .ToArray();
                    componentKCVs[i] = CalculateKCV(keyBytes, algorithm);
                    componentCKCVs[i] = algorithm == "AES" ? CalculateCKCV(keyBytes) : null;
                }
                else
                {
                    componentKCVs[i] = "";
                    componentCKCVs[i] = "";
                }
            }

            // Geri kalan ViewBag'ler
            ViewBag.Components = comps;
            ViewBag.ComponentKCVs = componentKCVs;
            ViewBag.ComponentCKCVs = componentCKCVs;
            ViewBag.Algorithm = algorithm;
            ViewBag.ForceOdd = forceOdd;
            ViewBag.CombinedKey = "";
            ViewBag.KCV = "";
            ViewBag.CKCV = "";

            return View("Index");
        }


        // --- Fonksiyonlar ---

        private static bool KeyLengthValid(string algorithm, int length)
        {
            if (algorithm == "AES")
                return length == 16 || length == 24 || length == 32;
            if (algorithm == "DES")
                return length == 8;
            if (algorithm == "3DES")
                return length == 16 || length == 24;
            return false;
        }

        // Zayıf/parity safe key üretimi
        private byte[] GenerateStrongKey(string algorithm, int length, bool forceOdd)
        {
            byte[] key;
            bool valid = false;
            int retry = 0;

            do
            {
                key = RandomNumberGenerator.GetBytes(length);

                if (forceOdd && (algorithm == "DES" || algorithm == "3DES"))
                {
                    for (int i = 0; i < key.Length; i++)
                    {
                        int bitCount = CountBits(key[i]);
                        if (bitCount % 2 == 0)
                            key[i] ^= 0x01;
                    }
                }

                try
                {
                    if (algorithm == "AES")
                    {
                        using var aes = Aes.Create();
                        aes.Key = key;
                    }
                    else if (algorithm == "DES")
                    {
                        using var des = DES.Create();
                        des.Key = key;
                    }
                    else if (algorithm == "3DES")
                    {
                        using var tdes = TripleDES.Create();
                        tdes.Key = key;
                    }
                    valid = true;
                }
                catch
                {
                    valid = false;
                }

                retry++;
                if (retry > 100) return null; 
            } while (!valid);

            return key;
        }

        private string CalculateKCV(byte[] key, string algorithm)
        {
            byte[] block = algorithm == "AES" ? new byte[16] : new byte[8];
            using SymmetricAlgorithm algo = algorithm == "AES" ? Aes.Create() :
                                            algorithm == "DES" ? DES.Create() :
                                            TripleDES.Create();
            algo.Mode = CipherMode.ECB;
            algo.Padding = PaddingMode.None;
            algo.Key = key;
            using var encryptor = algo.CreateEncryptor();
            var encrypted = encryptor.TransformFinalBlock(block, 0, block.Length);
            return BitConverter.ToString(encrypted).Replace("-", "").Substring(0, 6);
        }

        private string CalculateCKCV(byte[] key)
        {
            byte[] msg = new byte[16];
            byte[] cmac = AesCmac(key, msg);
            return BitConverter.ToString(cmac).Replace("-", "").Substring(0, 10);
        }

        public static byte[] AesCmac(byte[] key, byte[] message)
        {
            using (var aes = new AesManaged { Key = key, Mode = CipherMode.ECB, Padding = PaddingMode.None })
            using (var encryptor = aes.CreateEncryptor())
            {
                int blockSize = 16;
                int n = (message.Length + blockSize - 1) / blockSize;
                byte[] lastBlock = new byte[blockSize];
                byte[] buffer = new byte[blockSize];
                byte[] mac = new byte[blockSize];

                var zero = new byte[blockSize];
                var l = encryptor.TransformFinalBlock(zero, 0, zero.Length);
                var k1 = LeftShiftOneBit(l);
                if ((l[0] & 0x80) != 0)
                    k1[blockSize - 1] ^= 0x87;
                var k2 = LeftShiftOneBit(k1);
                if ((k1[0] & 0x80) != 0)
                    k2[blockSize - 1] ^= 0x87;

                if (n == 0)
                {
                    n = 1;
                    Xor(lastBlock, new byte[blockSize], k2);
                }
                else
                {
                    int lastBlockLen = message.Length % blockSize == 0 ? blockSize : message.Length % blockSize;
                    Buffer.BlockCopy(message, blockSize * (n - 1), buffer, 0, lastBlockLen);
                    if (message.Length % blockSize == 0)
                    {
                        Xor(lastBlock, buffer, k1);
                    }
                    else
                    {
                        buffer[lastBlockLen] = 0x80;
                        for (int i = lastBlockLen + 1; i < blockSize; i++)
                            buffer[i] = 0;
                        Xor(lastBlock, buffer, k2);
                    }
                }

                for (int i = 0; i < n - 1; i++)
                {
                    for (int j = 0; j < blockSize; j++)
                        mac[j] ^= message[blockSize * i + j];
                    mac = encryptor.TransformFinalBlock(mac, 0, blockSize);
                }

                for (int j = 0; j < blockSize; j++)
                    mac[j] ^= lastBlock[j];
                mac = encryptor.TransformFinalBlock(mac, 0, blockSize);

                return mac;
            }
        }

        private static byte[] LeftShiftOneBit(byte[] input)
        {
            byte[] output = new byte[input.Length];
            byte overflow = 0;
            for (int i = input.Length - 1; i >= 0; i--)
            {
                output[i] = (byte)((input[i] << 1) | overflow);
                overflow = (byte)((input[i] & 0x80) >> 7);
            }
            return output;
        }

        private static void Xor(byte[] output, byte[] a, byte[] b)
        {
            for (int i = 0; i < output.Length; i++)
                output[i] = (byte)((a.Length > i ? a[i] : 0) ^ (b.Length > i ? b[i] : 0));
        }

        private int CountBits(byte b)
        {
            int count = 0;
            while (b != 0)
            {
                count += b & 1;
                b >>= 1;
            }
            return count;
        }
    }
}
