﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace Microsoft.MobileBlazorBindings.Authentication
{
    /// <summary>
    /// A memory token cache implementation.
    /// </summary>
    public class MemoryTokenCache : ITokenCache
    {
        private ConcurrentDictionary<string, JwtSecurityToken> tokens = new ConcurrentDictionary<string, JwtSecurityToken>();

        /// <inheritdoc />
        public Task Add(string key, JwtSecurityToken token)
        {
            tokens[key] = token;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task<bool> TryGet(string key, out JwtSecurityToken token)
        {
            token = null;

            var result = tokens.TryGetValue(key, out var foundToken);

            if (result)
            {
                if (foundToken.ValidTo < DateTime.UtcNow)
                {
                    tokens.TryRemove(key, out _);
                }
                else
                {
                    token = foundToken;
                    return Task.FromResult(true);
                }
            }
            return Task.FromResult(false);
        }
    }
}
