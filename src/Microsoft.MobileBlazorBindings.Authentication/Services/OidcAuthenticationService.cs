// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Components.Authorization;
using System.Threading.Tasks;

namespace Microsoft.MobileBlazorBindings.Authentication.Services
{
    /// <summary>
    /// The default implementation for <see cref="IRemoteAuthenticationService{TRemoteAuthenticationState}"/> that uses JS interop to authenticate the user.
    /// </summary>
    /// <typeparam name="TRemoteAuthenticationState">The state to preserve across authentication operations.</typeparam>
    /// <typeparam name="TAccount">The type of the <see cref="RemoteUserAccount" />.</typeparam>
    /// <typeparam name="TProviderOptions">The options to be passed down to the underlying JavaScript library handling the authentication operations.</typeparam>
    public class RemoteAuthenticationService<TRemoteAuthenticationState, TAccount, TProviderOptions> :
        AuthenticationStateProvider,
        IRemoteAuthenticationService<TRemoteAuthenticationState>,
        IAccessTokenProvider
        where TRemoteAuthenticationState : RemoteAuthenticationState
        where TProviderOptions : new()
        where TAccount : RemoteUserAccount
    {
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
    }
}
