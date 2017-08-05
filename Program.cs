using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography; 

namespace app
{
    class Program
    {
        private static T readPem<T>(string key) {
            using (StringReader sr = new StringReader(key))
            {
                PemReader pr = new PemReader(sr);
                return (T)pr.ReadObject();
            } 
        }

        public static string CreateToken(List<Claim> claims, string key)
        { 
            AsymmetricCipherKeyPair keyPair = readPem<AsymmetricCipherKeyPair>(key);
            
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                Dictionary<string, object> payload = claims.ToDictionary(k => k.Type, v => (object)v.Value);
                return Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS256);
            }
        }

        public static string DecodeToken(string token, string key)
        {
            RsaKeyParameters keyParams = readPem<RsaKeyParameters>(key);
            
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(keyParams);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                return Jose.JWT.Decode(token, rsa);
            }
        }

        private static DateTime epoch = new DateTime(1970, 01, 01);
        private static string unixTime(DateTime time) 
        {
            return Convert.ToInt64(time.Subtract(epoch).TotalMilliseconds).ToString();
        }

        private static Claim claim(string ct, string cv)
        { 
            return new Claim(ct, cv);
        }

        static void Main(string[] args)
        {
            var now = DateTime.Now;
            List<Claim> claims = new List<Claim> { 
                claim("clientId", "CLIENT-ID-GOES-HERE"), 
                claim("sub", "USER-IDENTIFIER-GOES-HERE"),
                claim("iss", "AUTH-SERVER-IDENTIFIER-GOES-HERE"),
                claim("iat", unixTime(now)),
                claim("exp", unixTime(now.AddMinutes(60)))
            };
            
            string token = CreateToken(claims, privateKey);
            string json = DecodeToken(token, publicKey);

            Console.WriteLine("Generated JWT:");
            Console.WriteLine(token);
            Console.WriteLine("Validated JSON from JWT:");
            Console.WriteLine(json);
        }

        private static string privateKey = 
@"-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDdK8YIs0AS2HhaTwFb9Eg8Q7aj0M38IGGG/hy+FgOfsvadcXJm
vv+dLMtxw+Q+S/G4sMfXb8vQ9AnAYuR52mfJ12JyMI7eXGzI/8xjJroCTEkfnxkS
4F3XkbDUP5ypzBc6Qbb9QUgqguCwouTVHX6sdb86Ljjkm5+twkVrk10tPwIDAQAB
AoGAMFD4wTvPeo55tFjgFiOGiEvOoXjjFvpH9AKdatVKU1/4SirXcCS3mLGJfD/s
I8PZeZx8+857exlk6/durEQPOfvXUXr06NtyhiwZhb1B9P/VRFgs2piZlUcjCglN
MYA+QKBV+MIEe4G/jeLxkpfGGDPYWTqTE827trGJo3TxlfECQQD4wjHlkGVdYNh4
e2X8o7Vy4s9cAr++iCWjKIAVB1tqjSWLDHWzYvqc8Pq+UsNPKFq3/3YcHQr+BENU
ku9WB+dHAkEA45v9YL9/6OdBP9ojSlBWOPfOh1W3ZlnWLmWww98fL4f0lsqyChLK
sEHKRKLZnkLdiOIq1VOKyEwbSI2CATL2SQJALW5B8JwTdx9VyYM32BEJ9WZo2nQC
EskInqip461JS8dlYOSwpkdgX8M+9/1jgBRtpQb5yh6fwE6FAXAoV7zvxwJAHKKC
VQqil/WIEvVpnS7QOiiK9iHFif3hYULv4ySN8tfi4JmtnnDQyS3tuYbXY/67ij4R
73asLhjNEeqjoWz86QJAdx9SFobJ839tsDL9O6rF5cszFpKeA171Ou8t1psipkKh
ebONsdqbn3t8ghszgc1F7QyXgd+loVFKUTFGmyVE6Q==
-----END RSA PRIVATE KEY-----";

        private static string publicKey = 
@"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdK8YIs0AS2HhaTwFb9Eg8Q7aj
0M38IGGG/hy+FgOfsvadcXJmvv+dLMtxw+Q+S/G4sMfXb8vQ9AnAYuR52mfJ12Jy
MI7eXGzI/8xjJroCTEkfnxkS4F3XkbDUP5ypzBc6Qbb9QUgqguCwouTVHX6sdb86
Ljjkm5+twkVrk10tPwIDAQAB
-----END PUBLIC KEY-----";
    }
}
