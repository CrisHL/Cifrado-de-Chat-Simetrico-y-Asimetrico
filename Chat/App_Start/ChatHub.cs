using Microsoft.Ajax.Utilities;
using Microsoft.AspNet.SignalR;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml;

namespace Chat.App_Start
{
    public class ChatHub: Hub
    {
        private RSACryptoServiceProvider rsa;

        public ChatHub()
        {
            rsa = new RSACryptoServiceProvider();
        }
        public void Send(string name, string message, bool symmetric)
        {
            var encryptedMessage = "";
            var decryptedMessage = "";
            var iv = GenerateRandomIV();
            var key = GenerateRandomKey();
            if (symmetric)
            {
                encryptedMessage = Encrypt(message, key, iv);
                decryptedMessage = Decrypt(encryptedMessage,key, iv);
            }
            else
            {
                encryptedMessage = EncryptWithPublicKey(message);
                decryptedMessage = DecryptWithPrivateKey(encryptedMessage);

            }

            Clients.All.broadcastMessage(name, encryptedMessage, decryptedMessage, symmetric);
        }

        

        private string GenerateRandomKey()
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.GenerateKey();
                return Convert.ToBase64String(aesAlg.Key);
            }
        }

        private string GenerateRandomIV()
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.GenerateIV();
                return Convert.ToBase64String(aesAlg.IV);
            }
        }

        private string Encrypt(string text, string key, string iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Convert.FromBase64String(key);
                aesAlg.IV = Convert.FromBase64String(iv);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                byte[] encryptedBytes;

                using (var msEncrypt = new System.IO.MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (var swEncrypt = new System.IO.StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(text);
                    }

                    encryptedBytes = msEncrypt.ToArray();
                }

                return Convert.ToBase64String(encryptedBytes);
            }
        }

        public string Decrypt(string encryptedText, string key, string iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Convert.FromBase64String(key);
                aesAlg.IV = Convert.FromBase64String(iv);

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                byte[] encryptedBytes = Convert.FromBase64String(encryptedText);

                using (var msDecrypt = new System.IO.MemoryStream(encryptedBytes))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new System.IO.StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        private string EncryptWithPublicKey(string plainText)
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedData = rsa.Encrypt(dataToEncrypt, false);
            return Convert.ToBase64String(encryptedData);
        }

        private string DecryptWithPrivateKey(string encryptedText)
        {
            byte[] dataToDecrypt = Convert.FromBase64String(encryptedText);
            byte[] decryptedData = rsa.Decrypt(dataToDecrypt, false);
            return Encoding.UTF8.GetString(decryptedData);
        }

    }
}