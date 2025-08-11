using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SocialLoginApplicationMVC.Data;
using SocialLoginApplicationMVC.Models;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SocialLoginApplicationMVC.Controllers
{
    public class AuthController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ApplicationDbContext _db;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;

        public AuthController(IConfiguration configuration, IPasswordHasher<ApplicationUser> passwordHasher, IHttpClientFactory httpClientFactory, ApplicationDbContext db)
        {
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            _db = db;
            _passwordHasher = passwordHasher;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var existingUser = await _db.Users.FirstOrDefaultAsync(u => u.Email == model.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "Email is already registered");
                return View(model);
            }

            var user = new ApplicationUser
            {
                Email = model.Email,
                Name = model.Name,
                Provider = null, // Internal user
                ProviderId = null,
            };

            user.PasswordHash = _passwordHasher.HashPassword(user, model.Password);

            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View(); // returns Views/Auth/Login.cshtml
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == model.Email);

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid email or password");
                return View(model);
            }

            if (!string.IsNullOrEmpty(user.Provider))
            {
                // User registered via external provider
                // Redirect them to external login page for that provider
                // You can pass provider name as query parameter or route
                return RedirectToAction("ExternalLogin", new { provider = user.Provider });
            }

            // Internal user: verify password
            var verificationResult = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password);
            if (verificationResult == PasswordVerificationResult.Failed)
            {
                ModelState.AddModelError("", "Invalid email or password");
                return View(model);
            }

            // Sign in internal user
            var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                            new Claim(ClaimTypes.Name, user.Name ?? ""),
                            new Claim(ClaimTypes.Email, user.Email)
                        };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

            return RedirectToAction("Index", "Dashboard");
        }

        [HttpGet]
        public IActionResult ExternalLogin(string provider)
        {
            if (string.IsNullOrEmpty(provider))
                return BadRequest("Provider not specified");

            switch (provider.ToLower())
            {
                case "google":
                    return RedirectToAction("GoogleLogin");
                // Add other providers here if you have
                default:
                    return BadRequest("Unsupported external provider");
            }
        }


        [HttpGet("auth/google-login")]
        public IActionResult GoogleLogin()
        {
            var clientId = _configuration["Google:ClientId"];
            var redirectUri = _configuration["Google:RedirectUri"];
            var state = Guid.NewGuid().ToString("N");

            Response.Cookies.Append("oauth_state", state, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax });

            var authorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth" +
                                   $"?client_id={Uri.EscapeDataString(clientId)}" +
                                   $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                   "&response_type=code" +
                                   "&scope=openid%20email%20profile" +
                                   $"&state={Uri.EscapeDataString(state)}";

            return Redirect(authorizationUrl);
        }

        [HttpGet("auth/google-callback")]
        public async Task<IActionResult> GoogleCallback(string code, string state)
        {
            var cookieState = Request.Cookies["oauth_state"];
            if (cookieState != state) return BadRequest("Invalid state");

            var tokens = await ExchangeCodeForTokensAsync(code);
            if (tokens == null) return BadRequest("Token exchange failed");

            var userInfo = await GetGoogleUserInfoAsync(tokens.AccessToken);
            if (userInfo == null) return BadRequest("Failed to get user info");

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Provider == "Google" && u.ProviderId == userInfo.Sub);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    Email = userInfo.Email,
                    Name = userInfo.Name,
                    Provider = "Google",
                    ProviderId = userInfo.Sub,
                    Picture = userInfo.Picture
                };
                _db.Users.Add(user);
                await _db.SaveChangesAsync();
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Email, user.Email)
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

            return RedirectToAction("Index", "Dashboard");
        }

        private async Task<TokenResponse?> ExchangeCodeForTokensAsync(string code)
        {
            var client = _httpClientFactory.CreateClient();
            var parameters = new[]
            {
                new KeyValuePair<string,string>("code", code),
                new KeyValuePair<string,string>("client_id", _configuration["Google:ClientId"]),
                new KeyValuePair<string,string>("client_secret", _configuration["Google:ClientSecret"]),
                new KeyValuePair<string,string>("redirect_uri", _configuration["Google:RedirectUri"]),
                new KeyValuePair<string,string>("grant_type", "authorization_code")
            };

            var response = await client.PostAsync("https://oauth2.googleapis.com/token", new FormUrlEncodedContent(parameters));
            if (!response.IsSuccessStatusCode) return null;

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<TokenResponse>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }

        private async Task<GoogleUserInfo?> GetGoogleUserInfoAsync(string accessToken)
        {
            var client = _httpClientFactory.CreateClient();
            var request = new HttpRequestMessage(HttpMethod.Get, "https://openidconnect.googleapis.com/v1/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await client.SendAsync(request);
            if (!response.IsSuccessStatusCode) return null;

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<GoogleUserInfo>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }

        private class TokenResponse
        {
            //{
            //  "access_token": "ya29.a0AfH6SMD...",
            //  "expires_in": 3599,
            //  "refresh_token": "1//0gL_RuM2H-M...",
            //  "scope": "openid email profile",
            //  "token_type": "Bearer",
            //  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
            //}
            [JsonPropertyName("access_token")]
            public string AccessToken { get; set; }
            [JsonPropertyName("id_token")]
            public string IdToken { get; set; }
        }

        private class GoogleUserInfo
        {
            public string Sub { get; set; }
            public string Email { get; set; }
            public string Name { get; set; }
            public string Picture { get; set; }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }
    }
}
