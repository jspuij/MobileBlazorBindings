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
        /// Initializes a new instance.
        /// </summary>
        /// <param name="options">The options to be passed down to the underlying JavaScript library handling the authentication operations.</param>
        /// <param name="accountClaimsPrincipalFactory">The <see cref="AccountClaimsPrincipalFactory{TAccount}"/> used to generate the <see cref="ClaimsPrincipal"/> for the user.</param>
        public OidcAuthenticationService(
            IOptionsSnapshot<RemoteAuthenticationOptions<TProviderOptions>> options,
            AccountClaimsPrincipalFactory<TAccount> accountClaimsPrincipalFactory)
        {
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

        public async Task SignInAsync()
        {
            var client = CreateOidcClientFromOptions();

            var internalState = await client.PrepareLoginAsync();
            var raw = await SignInAsync(new TRemoteAuthenticationState()
            {
                StartUrl = internalState.StartUrl,
                CodeVerifier = internalState.CodeVerifier,
                Nonce = internalState.Nonce,
                RedirectUrl = internalState.RedirectUri,
                State = internalState.State,
            });

            var loginResult = await client.ProcessResponseAsync(raw, internalState);
            _cachedUser = loginResult.User;
            this.NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        protected abstract Task<string> SignInAsync(TRemoteAuthenticationState authenticationState);



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
                Scope = string.Join(' ', oidcProviderOptions.DefaultScopes),
            });
        }

        public virtual Task SignOutAsync()
        {
            throw new System.NotImplementedException();
        }

        /// <inheritdoc />
        public override async Task<AuthenticationState> GetAuthenticationStateAsync() => new AuthenticationState(await GetUser(useCache: true));
        private async Task<ClaimsPrincipal> GetUser(bool useCache = false)
        {
            return _cachedUser;

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
            throw new NotImplementedException();

            //var account = await JsRuntime.InvokeAsync<TAccount>("AuthenticationService.getUser");
            //var user = await AccountClaimsPrincipalFactory.CreateUserAsync(account, Options.UserOptions);

            //return user;
        }

        private async ValueTask EnsureAuthService()
        {
        }

    }
}
