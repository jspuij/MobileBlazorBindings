// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.MobileBlazorBindings.Authentication
{
    /// <summary>
    /// Represents a contract for services that perform authentication operations for a Blazor WebAssembly application.
    /// </summary>
    /// <typeparam name="TRemoteAuthenticationState">The state to be persisted across authentication operations.</typeparam>
    public interface IRemoteAuthenticationService<TRemoteAuthenticationState>
        where TRemoteAuthenticationState : RemoteAuthenticationState
    {
        /// <summary>
        /// Signs in a user.
        /// </summary>
        /// <param name="context">The <see cref="RemoteAuthenticationContext{TRemoteAuthenticationState}"/> for authenticating the user.</param>
        /// <returns>The result of the authentication operation.</returns>
        Task<RemoteAuthenticationResult<TRemoteAuthenticationState>> SignInAsync();

        /// <summary>
        /// Signs out a user.
        /// </summary>
        /// <param name="context">The <see cref="RemoteAuthenticationContext{TRemoteAuthenticationState}"/> for authenticating the user.</param>
        /// <returns>The result of the authentication operation.</returns>
        Task<RemoteAuthenticationResult<TRemoteAuthenticationState>> SignOutAsync();
    }
}
