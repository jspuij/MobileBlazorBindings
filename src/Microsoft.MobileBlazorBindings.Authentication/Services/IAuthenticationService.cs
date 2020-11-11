// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.MobileBlazorBindings.Authentication
{
    /// <summary>
    /// Represents a contract for services that perform authentication operations for a Blazor WebAssembly application.
    /// </summary>
    public interface IAuthenticationService
    {
        /// <summary>
        /// Signs in a user.
        /// </summary>
        /// <returns>The result of the authentication operation.</returns>
        Task SignInAsync();

        /// <summary>
        /// Signs out a user.
        /// </summary>
        /// <returns>The result of the authentication operation.</returns>
        Task SignOutAsync();
    }
}
