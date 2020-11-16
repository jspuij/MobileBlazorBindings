// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using IdentityModel.Client;
using IdentityModel.OidcClient;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Options;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using static IdentityModel.OidcClient.OidcClientOptions;
using System.Net.Http;
using System.Text.Json;
using System.Linq;

namespace Microsoft.MobileBlazorBindings.Authentication
{
    /// <summary>
    /// The default implementation for <see cref="IAuthenticationService{TRemoteAuthenticationState}"/> that uses JS interop to authenticate the user.
    /// </summary>
    /// <typeparam name="TRemoteAuthenticationState">The state to preserve across authentication operations.</typeparam>
    /// <typeparam name="TAccount">The type of the <see cref="RemoteUserAccount" />.</typeparam>
    /// <typeparam name="TProviderOptions">The options to be passed down to the underlying JavaScript library handling the authentication operations.</typeparam>
    public abstract class OidcAuthenticationService<TRemoteAuthenticationState, TAccount, TProviderOptions> :
        AuthenticationStateProvider,
        IAuthenticationService,
        IAccessTokenProvider
        where TRemoteAuthenticationState : OidcAuthenticationState, new()
        where TProviderOptions : new()
        where TAccount : RemoteUserAccount
    {
        private static readonly string[] ProtocolClaims = new string[] { "nonce", "at_hash", "iat", "nbf", "exp", "aud", "iss", "c_hash" };
        private readonly ITokenCache _tokenCache;

        // We cache the user claims for 60 seconds to avoid spamming the server.
        // But we also want additional claims that are added to appear in the app fairly quickly.
        private static readonly TimeSpan _userCacheRefreshInterval = TimeSpan.FromSeconds(60);
        private bool _initialized = false;

        // This defaults to 1/1/1970
        private DateTimeOffset _userLastCheck = DateTimeOffset.FromUnixTimeSeconds(0);
        private ClaimsPrincipal _cachedUser = new ClaimsPrincipal(new ClaimsIdentity());

        /// <summary>
        /// Gets the <see cref="AccountClaimsPrincipalFactory{TAccount}"/> to map accounts to <see cref="ClaimsPrincipal"/>.
        /// </summary>
        protected AccountClaimsPrincipalFactory<TAccount> AccountClaimsPrincipalFactory { get; }

        /// <summary>
        /// Gets the options for the underlying JavaScript library handling the authentication operations.
        /// </summary>
        protected RemoteAuthenticationOptions<TProviderOptions> Options { get; }

        /// <summary>
        /// The Oidc Client that is used for all requests.
        /// </summary>
        protected OidcClient Client { get; private set; }

        /// <summary>
        /// Initializes a new instance.
        /// </summary>
        /// <param name="options">The options to be passed down to the underlying JavaScript library handling the authentication operations.</param>
        /// <param name="tokenCache">The token cache to use to store tokens.</param>
        /// <param name="accountClaimsPrincipalFactory">The <see cref="AccountClaimsPrincipalFactory{TAccount}"/> used to generate the <see cref="ClaimsPrincipal"/> for the user.</param>
        public OidcAuthenticationService(
            IOptionsSnapshot<RemoteAuthenticationOptions<TProviderOptions>> options,
            ITokenCache tokenCache,
            AccountClaimsPrincipalFactory<TAccount> accountClaimsPrincipalFactory)
        {
            _tokenCache = tokenCache;
            AccountClaimsPrincipalFactory = accountClaimsPrincipalFactory;
            Options = options.Value;
        }

        public virtual ValueTask<AccessTokenResult> RequestAccessToken()
        {
            throw new System.NotImplementedException();
        }

        public virtual ValueTask<AccessTokenResult> RequestAccessToken(AccessTokenRequestOptions options)
        {
            throw new System.NotImplementedException();
        }

        public async Task SignIn()
        {
            await EnsureAuthService();

            var internalState = await Client.PrepareLoginAsync();
            var rawQuery = await StartSecureNavigation(new Uri(internalState.StartUrl), new Uri(internalState.RedirectUri));
            var loginResult = await Client.ProcessResponseAsync(rawQuery, internalState);

            if (loginResult.AccessToken != null)
            {
                await this._tokenCache.Add("access_token", new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(loginResult.AccessToken));
            }
            if (loginResult.IdentityToken != null)
            {
                await this._tokenCache.Add("id_token", new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(loginResult.IdentityToken));
            }

            var getUserTask = GetUser();
            await getUserTask;
            UpdateUser(getUserTask);
        }

        protected abstract Task<string> StartSecureNavigation(Uri startUrl, Uri redirectUrl);

        /// <summary>
        /// Creates a new <see cref="OidcClient"/> given the <see cref="OidcProviderOptions"/>.
        /// </summary>
        /// <returns>An <see cref="OidcClient"/> to use.</returns>

        protected virtual OidcClient CreateOidcClientFromOptions()
        {
            OidcProviderOptions oidcProviderOptions = null;

            if (this.Options.ProviderOptions is OidcProviderOptions)
            {
                oidcProviderOptions = this.Options.ProviderOptions as OidcProviderOptions;
            } 
            else if (this.Options.ProviderOptions is ApiAuthorizationProviderOptions apiAuthorizationProviderOptions)
            {
                // TODO: Implement configuration fetch from endpoint.
            } else
            {
                throw new InvalidOperationException($"{typeof(TProviderOptions)} is not a known options type.");
            }

            if (!Enum.TryParse<AuthorizeResponseMode>(oidcProviderOptions.ResponseMode, out var responseMode))
            {
                throw new OptionsValidationException("ResponseMode", typeof(OidcProviderOptions), new string[] { $"{oidcProviderOptions.ResponseMode} is not a valid response mode." });
            }

            return new OidcClient(new OidcClientOptions()
            {
                Authority = oidcProviderOptions.Authority,
                ClientId = oidcProviderOptions.ClientId,
                PostLogoutRedirectUri = oidcProviderOptions.PostLogoutRedirectUri,
                RedirectUri = oidcProviderOptions.RedirectUri,
                ResponseMode = responseMode,
                LoadProfile = false,
                Scope = string.Join(' ', oidcProviderOptions.DefaultScopes),
            });
        }

        public async virtual Task SignOut()
        {
            await EnsureAuthService();

            string idTokenString = null;
            if (await _tokenCache.TryGet("id_token", out var idToken))
            {
                idTokenString = idToken.RawData;
            }

            var logoutUrl = await Client.PrepareLogoutAsync(new LogoutRequest()
            {
                IdTokenHint = idTokenString,
            });
            var rawQuery = await StartSecureNavigation(new Uri(logoutUrl), new Uri(Client.Options.PostLogoutRedirectUri));

            if (string.IsNullOrEmpty(rawQuery))
            {
                await _tokenCache.Clear();
                _userLastCheck = DateTimeOffset.FromUnixTimeSeconds(0);
                var getUserTask = GetUser();
                await getUserTask;
                UpdateUser(getUserTask);
            }
        }

        /// <inheritdoc />
        public override async Task<AuthenticationState> GetAuthenticationStateAsync() => new AuthenticationState(await GetUser(useCache: true));

        private async Task<ClaimsPrincipal> GetUser(bool useCache = false)
        {
            var now = DateTimeOffset.Now;
            if (useCache && now < _userLastCheck + _userCacheRefreshInterval)
            {
                return _cachedUser;
            }

            _cachedUser = await GetAuthenticatedUser();
            _userLastCheck = now;

            return _cachedUser;
        }

        /// <summary>
        /// Gets the current authenticated used using JavaScript interop.
        /// </summary>
        /// <returns>A <see cref="Task{ClaimsPrincipal}"/>that will return the current authenticated user when completes.</returns>
        protected internal virtual async ValueTask<ClaimsPrincipal> GetAuthenticatedUser()
        {
            await EnsureAuthService();

            if (await _tokenCache.TryGet("access_token", out var access_token))
            {
                using var userInfoClient = CreateClient(Client.Options);
                using var request = new UserInfoRequest
                {
                    Address = Client.Options.ProviderInformation.UserInfoEndpoint,
                    Token = access_token.RawData
                };

                var userInfoResponse = await userInfoClient.GetUserInfoAsync(request).ConfigureAwait(true);

                if (userInfoResponse.Exception != null)
                {
                    throw userInfoResponse.Exception;
                }

                var account = JsonSerializer.Deserialize<TAccount>(userInfoResponse.Raw);

                await MergeIdTokenClaims(account);

                return await AccountClaimsPrincipalFactory.CreateUserAsync(account, Options.UserOptions);
            }
            else
            {
                return new ClaimsPrincipal(new ClaimsIdentity());
            }
        }

        private async Task MergeIdTokenClaims(TAccount account)
        {
            if (await _tokenCache.TryGet("id_token", out var idToken))
            {
                foreach (var claim in idToken.Claims)
                {
                    if (!account.AdditionalProperties.ContainsKey(claim.Type) && !ProtocolClaims.Contains(claim.Type))
                    {
                        account.AdditionalProperties.Add(claim.Type, claim.Value);
                    }
                }
            }
        }

        protected async ValueTask EnsureAuthService()
        {
            if (!_initialized)
            {
                Client = CreateOidcClientFromOptions();
                _initialized = true;
            }
        }

        private static HttpClient CreateClient(OidcClientOptions options)
        {
            HttpClient client;

            if (options.BackchannelHandler != null)
            {
                client = new HttpClient(options.BackchannelHandler);
            }
            else
            {
                client = new HttpClient();
            }

            client.Timeout = options.BackchannelTimeout;
            return client;
        }

        private void UpdateUser(Task<ClaimsPrincipal> task)
        {
            NotifyAuthenticationStateChanged(UpdateAuthenticationState(task));

            static async Task<AuthenticationState> UpdateAuthenticationState(Task<ClaimsPrincipal> futureUser) => new AuthenticationState(await futureUser);
        }
    }
}
