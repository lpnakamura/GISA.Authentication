using System;
using System.Security.Cryptography;
using System.Text;

namespace GISA.Authentication.Application.Helpers
{
    public static class CognitoHashCalculatorHelper
    {
        public static string GetSecretHash(string userName, string appClientId, string appSecretKey)
        {
            var data = Encoding.UTF8.GetBytes($"{userName}{appClientId}");
            var key = Encoding.UTF8.GetBytes(appSecretKey);
            return Convert.ToBase64String(HmacSHA256(key, data));
        }

        private static byte[] HmacSHA256(byte[] data, byte[] key)
        {
            using (var shaAlgorithm = new HMACSHA256(data))
                return shaAlgorithm.ComputeHash(key);
        }
    }
}