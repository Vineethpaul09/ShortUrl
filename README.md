# ShortUrl

A secure and feature-rich URL shortening library with support for:
- Secure random short codes.
- Tamper-proof HMAC validation.
- URL expiration.
- Click count analytics.
- Lightweight and scalable design.

## Installation
Install via NuGet Package Manager:
dotnet add package ShortUrl

bash
Copy code

## Usage
```csharp
using ShortUrl;

var shortener = new UrlShortener(\"YourSecretKey\");
string shortCode = shortener.ShortenUrl(\"https://example.com\", DateTime.UtcNow.AddDays(30));
string? originalUrl = shortener.ResolveUrl(shortCode);
