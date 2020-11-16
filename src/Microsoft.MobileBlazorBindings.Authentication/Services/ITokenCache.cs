// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace Microsoft.MobileBlazorBindings.Authentication
{
    /// <summary>
    /// Interface that defines a token cache.
    /// </summary>
    public interface ITokenCache
    {
        /// <summary>
        /// Adds a token to the cache using the specified key.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        Task Add(string key, JwtSecurityToken token);

        /// <summary>
        /// Tries to get the Token from the cache using the specified key.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        Task<bool> TryGet(string key, out JwtSecurityToken token);

        /// <summary>
        /// Clears the token cache.
        /// </summary>
        /// <returns>A taks representing the asynchronous operation.</returns>
        Task Clear();
    }
}
