using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AccessOAuthRESTApi
{
    internal class Token
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
    }

    class Program
    {
        static void Main(string[] args)
        {
            // Generate Authorize Access Token to authenticate REST Web API.  
            string oAuthInfo = Program.GetAuthorizeToken().Result;

            // Process response access token info.  
            Token tok = JsonConvert.DeserializeObject<Token>(oAuthInfo);

            // Call REST Web API method with authorize access token.  
            string responseObj = Program.GetInfo(tok.AccessToken).Result;

            // Process Result.  
            Console.WriteLine(responseObj);
        }

        public static async Task<string> GetAuthorizeToken()
        {
            // Initialization.  
            string responseObj = string.Empty;
            // Posting.  
            using (var client = new HttpClient())
            {
                // Setting Base address.  
                client.BaseAddress = new Uri("https://demo.etitlelien.net/");

                // Setting content type.  
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                // Initialization.  
                HttpResponseMessage response = new HttpResponseMessage();
                List<KeyValuePair<string, string>> allIputParams = GetRequestParams();

                // URL Request parameters.  
                HttpContent requestParams = new FormUrlEncodedContent(allIputParams);

                // HTTP POST  
                response = await client.PostAsync("Token", requestParams).ConfigureAwait(false);

                // Verification  
                if (response.IsSuccessStatusCode)
                {
                    // Display Response.  
                    Console.WriteLine(response.Content);
                }
            }

            return responseObj;
        }

        public static async Task<string> GetInfo(string authorizeToken)
        {
            // Initialization.  
            string responseObj = string.Empty;

            // HTTP GET.  
            using (var client = new HttpClient())
            {
                // Initialization  
                string authorization = authorizeToken;

                // Setting Authorization.  
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authorization);

                // Setting Base address.  
                client.BaseAddress = new Uri("https://demo.etitlelien.net/");

                // Setting content type.  
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                // Initialization.  
                HttpResponseMessage response = new HttpResponseMessage();

                // HTTP GET  
                response = await client.GetAsync("Dealers?Action=GetDealer").ConfigureAwait(false);

                // Verification  
                if (response.IsSuccessStatusCode)
                {
                    // Display Response.  
                    Console.WriteLine(response.Content);
                }
            }

            return responseObj;
        }

        public static List<KeyValuePair<string, string>> GetRequestParams()
        {
            int nOnce, min = int.MinValue, max = int.MaxValue;
            string loginName, password;
            string concatenatedString, hashedString, x509String, signatureString;
            loginName = "";
            password = "";

            // Random Integer
            nOnce = GetRandomInteger(min, max);

            // Concatenates String
            concatenatedString = nOnce.ToString() + loginName + password;

            // Hashed String
            hashedString = GetHashSha256(concatenatedString);

            // X509 signed string
            x509String = GetX509SignedString(hashedString);

            // Base 64 string
            signatureString = Base64Encode(x509String);


            List<KeyValuePair<string, string>> allIputParams = new List<KeyValuePair<string, string>>();

            // Convert Request Params to Key Value Pair.  
            allIputParams.Insert(0, new KeyValuePair<string, string>("loginName", loginName));
            allIputParams.Insert(1, new KeyValuePair<string, string>("password", password));
            allIputParams.Insert(2, new KeyValuePair<string, string>("nonce", nOnce.ToString()));
            allIputParams.Insert(3, new KeyValuePair<string, string>("partnerId", x509String));
            allIputParams.Insert(4, new KeyValuePair<string, string>("signature", signatureString));

            return allIputParams;
        }

        #region Helper Methods
        private static int GetRandomInteger(int min, int max)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] buffer = new byte[4];

            rng.GetBytes(buffer);
            int result = BitConverter.ToInt32(buffer, 0);
            return new Random(result).Next(min, max);
        }

        private static string GetHashSha256(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            SHA256Managed hashstring = new SHA256Managed();
            byte[] hash = hashstring.ComputeHash(bytes);
            string hashString = string.Empty;
            foreach (byte x in hash)
            {
                hashString += String.Format("{0:x2}", x);
            }
            return hashString;
        }

        private static string GetX509SignedString(string hashedString)
        {
            // Certificate path
            string Certificate = "Certificate.cer";

            // Load the certificate into an X509Certificate object.
            X509Certificate cert = X509Certificate.CreateFromCertFile(Certificate);

            // Get the value.
            string results = cert.GetCertHashString();
            return results;
        }

        private static string Base64Encode(string x509String)
        {
            var plainTextBytes = Encoding.UTF8.GetBytes(x509String);
            return Convert.ToBase64String(plainTextBytes);
        }
        #endregion
    }
}
