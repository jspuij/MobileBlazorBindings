// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Options;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.MobileBlazorBindings.Authentication
{
    /// <summary>
    /// The default implementation for <see cref="IRemoteAuthenticationService{TRemoteAuthenticationState}"/> that uses JS interop to authenticate the user.
    /// </summary>
    /// <typeparam name="TRemoteAuthenticationState">The state to preserve across authentication operations.</typeparam>
    /// <typeparam name="TAccount">The type of the <see cref="RemoteUserAccount" />.</typeparam>
    /// <typeparam name="TProviderOptions">The options to be passed down to the underlying JavaScript library handling the authentication operations.</typeparam>
    public class OidcAuthenticationService<TRemoteAuthenticationState, TAccount, TProviderOptions> :
        AuthenticationStateProvider,
        IRemoteAuthenticationService<TRemoteAuthenticationState>,
        IAccessTokenProvider
        where TRemoteAuthenticationState : RemoteAuthenticationState
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

        public Task<RemoteAuthenticationResult<TRemoteAuthenticationState>> CompleteSignInAsync(RemoteAuthenticationContext<TRemoteAuthenticationState> context)
        {
            throw new System.NotImplementedException();
        }

        public Task<RemoteAuthenticationResult<TRemoteAuthenticationState>> CompleteSignOutAsync(RemoteAuthenticationContext<TRemoteAuthenticationState> context)
        {
            throw new System.NotImplementedException();
        }

        public ValueTask<AccessTokenResult> RequestAccessToken()
        {
            throw new System.NotImplementedException();
        }

        public ValueTask<AccessTokenResult> RequestAccessToken(AccessTokenRequestOptions options)
        {
            throw new System.NotImplementedException();
        }

        public Task<RemoteAuthenticationResult<TRemoteAuthenticationState>> SignInAsync(RemoteAuthenticationContext<TRemoteAuthenticationState> context)
        {
            throw new System.NotImplementedException();
        }

        public Task<RemoteAuthenticationResult<TRemoteAuthenticationState>> SignOutAsync(RemoteAuthenticationContext<TRemoteAuthenticationState> context)
        {
            throw new System.NotImplementedException();
        }

        /// <inheritdoc />
        public override async Task<AuthenticationState> GetAuthenticationStateAsync() => new AuthenticationState(await GetUser(useCache: true));

        private async Task<ClaimsPrincipal> GetUser(bool useCache = false)
        {
            return _cachedUser;
        }
    }
}
