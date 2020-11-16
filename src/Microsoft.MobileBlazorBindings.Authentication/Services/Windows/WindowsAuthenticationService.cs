using IdentityModel.OidcClient;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.MobileBlazorBindings.Authentication
{
    /// <summary>
    /// The default implementation for <see cref="IAuthenticationService{TRemoteAuthenticationState}"/> that uses JS interop to authenticate the user.
    /// </summary>
    /// <typeparam name="TRemoteAuthenticationState">The state to preserve across authentication operations.</typeparam>
    /// <typeparam name="TAccount">The type of the <see cref="RemoteUserAccount" />.</typeparam>
    /// <typeparam name="TProviderOptions">The options to be passed down to the underlying JavaScript library handling the authentication operations.</typeparam>
    public class WindowsAuthenticationService<TRemoteAuthenticationState, TAccount, TProviderOptions> :
        OidcAuthenticationService<TRemoteAuthenticationState, TAccount, TProviderOptions>
        where TRemoteAuthenticationState : OidcAuthenticationState, new()
        where TProviderOptions : new()
        where TAccount : RemoteUserAccount
    {
        /// <summary>
        /// The Http Listener that we will use to listen to requests.
        /// </summary>
        private HttpListener _httpListener;

        /// <summary>
        /// Initializes a new instance.
        /// </summary>
        /// <param name="options">The options to be passed down to the underlying JavaScript library handling the authentication operations.</param>
        /// <param name="tokenCache">The token cache to use to store tokens.</param>
        /// <param name="accountClaimsPrincipalFactory">The <see cref="AccountClaimsPrincipalFactory{TAccount}"/> used to generate the <see cref="ClaimsPrincipal"/> for the user.</param>
        public WindowsAuthenticationService(
            IOptionsSnapshot<RemoteAuthenticationOptions<TProviderOptions>> options,
            ITokenCache tokenCache,
            AccountClaimsPrincipalFactory<TAccount> accountClaimsPrincipalFactory) : base (options, tokenCache, accountClaimsPrincipalFactory)
        {
        }

        /// <inheritdoc/>
        protected override OidcClient CreateOidcClientFromOptions()
        {
            var result = base.CreateOidcClientFromOptions();

            var redirectUri = new UriBuilder(result.Options.RedirectUri);
            var postLogoutRedirectUri = new UriBuilder(result.Options.PostLogoutRedirectUri);

            if (redirectUri.Port != postLogoutRedirectUri.Port)
            {
                throw new OptionsValidationException("RedirectUri", typeof(OidcProviderOptions), new string[]
                    {
                        "The port of the RedirectUri must be equal to the port of the PostLogoutRedirectUri",
                    });
            }

            if (
                redirectUri.Port == 0 && (redirectUri.Host == "localhost" || redirectUri.Host == "127.0.0.1") &&
                postLogoutRedirectUri.Port == 0 && (postLogoutRedirectUri.Host == "localhost" || postLogoutRedirectUri.Host == "127.0.0.1"))
            {
                int port = GetRandomUnusedPort();

                // set ports to the random port value.
                redirectUri.Port = port;
                postLogoutRedirectUri.Port = port;
                result.Options.RedirectUri = redirectUri.ToString();
                result.Options.PostLogoutRedirectUri = postLogoutRedirectUri.ToString();
            }

            // create a listener and add the prefix to reserve the port.
            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add($"{redirectUri.Scheme}://{redirectUri.Host}:{redirectUri.Port}/");

            return result;
        }

        protected override async Task<string> StartSecureNavigation(Uri startUrl, Uri redirectUrl)
        {
            _httpListener.Start();

            // Opens request in the browser.
            var ps = new ProcessStartInfo(startUrl.ToString())
            {
                UseShellExecute = true,
                Verb = "open"
            };

            System.Diagnostics.Process.Start(ps);

            string resultUri = string.Empty;

            // Waits for the OAuth authorization response.
            while (resultUri == string.Empty)
            {
                var context = await _httpListener.GetContextAsync();
                var response = context.Response;

                var requestedUri = context.Request.Url.ToString();

                if (requestedUri.StartsWith(redirectUrl.ToString()))
                {
                    resultUri = requestedUri.ToString();

                    // Sends an HTTP response to the browser.
                    string responseString = "<html><head></head><body>Please return to the app.</body></html>";
                    var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
                    response.ContentLength64 = buffer.Length;
                    var responseOutput = response.OutputStream;
                    _ = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
                    {
                        responseOutput.Close();
                        var prefix = _httpListener.Prefixes.First();
                        _httpListener.Close();

                        // Create a new one due to a disposal bug on stop
                        _httpListener = new HttpListener();
                        _httpListener.Prefixes.Add(prefix);
                    }, TaskScheduler.Current);
                } else
                {
                    response.StatusCode = 404;
                    response.OutputStream.Close();
                }
            }

            return new Uri(resultUri).Query;
        }


        public static int GetRandomUnusedPort()
        {
            // Get a random unused port by starting a Tcp listener on port 0.
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }
}
