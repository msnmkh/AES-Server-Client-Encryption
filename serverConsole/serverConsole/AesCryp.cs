using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;


namespace serverConsole
{
    class AesCryp
    {
        public static string IV;
        public static string key;
        public static string Encryption(string decrypted)
        {
            byte[] textbyte = ASCIIEncoding.ASCII.GetBytes(decrypted);
            AesCryptoServiceProvider encode = new AesCryptoServiceProvider();
            encode.BlockSize = 128;
            encode.KeySize = 256;
            encode.Key = ASCIIEncoding.ASCII.GetBytes(key);
            encode.IV = ASCIIEncoding.ASCII.GetBytes(IV);
            encode.Padding = PaddingMode.PKCS7;
            encode.Mode = CipherMode.CBC;
            ICryptoTransform icypt = encode.CreateEncryptor(encode.Key, encode.IV);

            byte[] enc = icypt.TransformFinalBlock(textbyte, 0, textbyte.Length);
            icypt.Dispose();

            return Convert.ToBase64String(enc); 
        }



    }
}
