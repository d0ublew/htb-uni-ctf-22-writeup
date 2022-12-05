// https://www.mono-project.com/docs/about-mono/languages/csharp/
// compile with `mcs decrypt.cs`
// run with `mono decrypt.exe`

using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;

class Crypto {
    private static string Decrypt(string toBeDecrypted, string key, string initVector) {
        var keyByte = Encoding.Default.GetBytes(key);
        var iv = Encoding.Default.GetBytes(initVector);

        var rijndael = new RijndaelManaged {
            BlockSize = 256,
            IV = iv,
            KeySize = 256,
            Key = keyByte,
            Mode = CipherMode.CBC,
            Padding = PaddingMode.Zeros,
        };

        var buffer = Convert.FromBase64String(toBeDecrypted);
        var transform = rijndael.CreateDecryptor();
        string decrypted;
        using (var ms = new MemoryStream())
        {
            using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
            {
                cs.Write(buffer, 0, buffer.Length);
                cs.FlushFinalBlock();
                decrypted = Encoding.UTF8.GetString(ms.ToArray());
                cs.Close();
            }
            ms.Close();
        }

        return decrypted;
    }

    public static string Base64Decode(string base64EncodedData) {
        var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
        return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
    }

    public static void Main() {
        string enc_data = "F02fGjYTWhdk3JYn2nntOcU56fnU0YD4prneoaPxbsNIcMgcwsFFGWifg7tNNkohHj9nZRTWJDg/BcnUpTuKynaTtMg9fnOnhjYmg++Q6pklR9Zt0s2vzVu2FMJxO+xBaQrONSPvPg5sd2qRtAkrCa4ikKuKwg38QA7v+wseZRrx37P2sIiellwVcWFMRQCZtlE6bdN14JKmXn+GeXFIP51KHOCR3qd34NgzcGuLySbH9ZGzldLZWagnIcAFKTP9";
        string iv = "*twGsy*#p7XY8CT4N3RpGq5xDzL7EMHW";
        string key = "8xppg2oX68Bo6koL7hwSeC8bCEWvk540";
        string data = Decrypt(enc_data, key, iv);

        Console.WriteLine("Decrypted data:\n" + data);
    }
    
}
