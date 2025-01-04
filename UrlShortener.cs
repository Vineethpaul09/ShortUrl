using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Text.Json;

namespace ShortUrl
{
    public class UrlShortener
    {
        private const string Characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        private const int CodeLength = 8;
        private readonly string _secretKey;
        private readonly ConcurrentDictionary<string, UrlEntry> _urlDatabase = new(); // In-memory database

        public UrlShortener(string secretKey)
        {
            if (string.IsNullOrWhiteSpace(secretKey))
                throw new ArgumentException("Secret key cannot be null or empty.");

            _secretKey = secretKey;
        }

        /// <summary>
        /// Shortens a given URL by generating a secure random code with HMAC for integrity.
        /// </summary>
        /// <param name="originalUrl">The original URL to shorten.</param>
        /// <param name="expiryDate">Optional expiration date for the URL.</param>
        /// <returns>The generated short code.</returns>
        public string ShortenUrl(string originalUrl, DateTime? expiryDate = null)
        {
            if (string.IsNullOrWhiteSpace(originalUrl))
                throw new ArgumentException("URL cannot be null or empty.");

            var randomCode = GenerateSecureRandomCode();
            var hmac = GenerateHMAC(randomCode, _secretKey);
            var shortCode = $"{randomCode}.{hmac}";

            var urlEntry = new UrlEntry
            {
                OriginalUrl = originalUrl,
                ShortCode = shortCode,
                CreatedAt = DateTime.UtcNow,
                ExpiryDate = expiryDate
            };

            _urlDatabase[shortCode] = urlEntry;

            return shortCode;
        }

        /// <summary>
        /// Resolves a short code to its original URL, ensuring integrity and validity.
        /// </summary>
        /// <param name="shortCode">The short code to resolve.</param>
        /// <returns>The original URL if valid; otherwise, null.</returns>
        public string? ResolveUrl(string shortCode)
        {
            if (string.IsNullOrWhiteSpace(shortCode))
                return null;

            var parts = shortCode.Split('.');
            if (parts.Length != 2)
                return null;

            var randomCode = parts[0];
            var providedHmac = parts[1];

            // Validate HMAC
            var computedHmac = GenerateHMAC(randomCode, _secretKey);
            if (!computedHmac.Equals(providedHmac))
                return null; // Tampered or invalid short URL

            // Retrieve URL entry
            if (!_urlDatabase.TryGetValue(shortCode, out var urlEntry))
                return null;

            // Check expiration
            if (urlEntry.ExpiryDate.HasValue && urlEntry.ExpiryDate.Value < DateTime.UtcNow)
                return null; // Expired URL

            // Increment click count
            urlEntry.ClickCount++;

            return urlEntry.OriginalUrl;
        }

        /// <summary>
        /// Generates a secure random code.
        /// </summary>
        private string GenerateSecureRandomCode()
        {
            var data = new byte[CodeLength];
            using var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(data);
            return new string(data.Select(b => Characters[b % Characters.Length]).ToArray());
        }

        /// <summary>
        /// Generates an HMAC for a given input and key.
        /// </summary>
        private string GenerateHMAC(string input, string key)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToBase64String(hash).Replace("/", "").Substring(0, 8);
        }

        /// <summary>
        /// Gets analytics for a short code.
        /// </summary>
        public UrlAnalytics? GetAnalytics(string shortCode)
        {
            if (string.IsNullOrWhiteSpace(shortCode))
                return null;

            if (!_urlDatabase.TryGetValue(shortCode, out var urlEntry))
                return null;

            return new UrlAnalytics
            {
                OriginalUrl = urlEntry.OriginalUrl,
                CreatedAt = urlEntry.CreatedAt,
                ClickCount = urlEntry.ClickCount,
                ExpiryDate = urlEntry.ExpiryDate
            };
        }

        public async Task<bool> IsUrlSafe(string url)
        {
            // Your Google Safe Browsing API Key
            const string apiKey = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY";
            const string apiUrl = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=";

            var client = new HttpClient();

            // Construct the request payload
            var requestPayload = new
            {
                client = new { clientId = "YourAppName", clientVersion = "1.0" },
                threatInfo = new
                {
                    threatTypes = new[] { "MALWARE", "SOCIAL_ENGINEERING" },
                    platformTypes = new[] { "ANY_PLATFORM" },
                    threatEntryTypes = new[] { "URL" },
                    threatEntries = new[] { new { url } }
                }
            };

            var content = new StringContent(JsonSerializer.Serialize(requestPayload), System.Text.Encoding.UTF8, "application/json");

            // Send the request
            var response = await client.PostAsync(apiUrl + apiKey, content);

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Error calling Safe Browsing API: {response.StatusCode}");
            }

            var jsonResponse = await response.Content.ReadAsStringAsync();

            // If there are matches, the URL is unsafe
            return string.IsNullOrWhiteSpace(jsonResponse);
        }

    }

    public class UrlEntry
    {
        public string OriginalUrl { get; set; } = string.Empty;
        public string ShortCode { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public int ClickCount { get; set; }
        public DateTime? ExpiryDate { get; set; }
    }

    public class UrlAnalytics
    {
        public string OriginalUrl { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public int ClickCount { get; set; }
        public DateTime? ExpiryDate { get; set; }
    }
}
