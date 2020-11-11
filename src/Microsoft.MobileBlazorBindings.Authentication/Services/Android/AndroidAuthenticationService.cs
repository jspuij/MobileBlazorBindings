using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Xamarin.Essentials;

namespace Microsoft.MobileBlazorBindings.Authentication
{
    /// <summary>
    /// The default implementation for <see cref="IRemoteAuthenticationService{TRemoteAuthenticationState}"/> that uses JS interop to authenticate the user.
    /// </summary>
    /// <typeparam name="TRemoteAuthenticationState">The state to preserve across authentication operations.</typeparam>
    /// <typeparam name="TAccount">The type of the <see cref="RemoteUserAccount" />.</typeparam>
    /// <typeparam name="TProviderOptions">The options to be passed down to the underlying JavaScript library handling the authentication operations.</typeparam>
    public class AndroidAuthenticationService<TRemoteAuthenticationState, TAccount, TProviderOptions> :
        OidcAuthenticationService<TRemoteAuthenticationState, TAccount, TProviderOptions>
        where TRemoteAuthenticationState : OidcAuthenticationState
        where TProviderOptions : new()
        where TAccount : RemoteUserAccount
    {
        /// <summary>
        /// Initializes a new instance.
        /// </summary>
        /// <param name="options">The options to be passed down to the underlying JavaScript library handling the authentication operations.</param>
        /// <param name="accountClaimsPrincipalFactory">The <see cref="AccountClaimsPrincipalFactory{TAccount}"/> used to generate the <see cref="ClaimsPrincipal"/> for the user.</param>
        public AndroidAuthenticationService(
            IOptionsSnapshot<RemoteAuthenticationOptions<TProviderOptions>> options,
            AccountClaimsPrincipalFactory<TAccount> accountClaimsPrincipalFactory) : base(options, accountClaimsPrincipalFactory)
        {
        }

        public override async Task<RemoteAuthenticationResult<TRemoteAuthenticationState>> SignInAsync()
        {
            var result = await base.SignInAsync();
            try
            {
                var authenticationResult = await WebAuthenticator.AuthenticateAsync(new Uri(result.State.StartUrl), new Uri(result.State.RedirectUrl));
            } 
            catch (Exception ex)
            {

            }

            return result;
        }
    }
}
