using Microsoft.AspNetCore.Components;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.MobileBlazorBindings.Authentication
{
    /// <summary>
    /// A component that will handle an unauthenticated situation in Mobile Blazor Bindings.
    /// </summary>
    public class UnauthenticatedView : ComponentBase
    {
        /// <summary>
        /// The Authentication Service to use to sign in.
        /// </summary>
        [Inject]
        public IAuthenticationService AuthenticationService { get; set; }

        /// <summary>
        /// Tries to sign in on first render.
        /// </summary>
        /// <param name="firstRender">Whether this render is the first render.</param>
        /// <returns></returns>
        protected override async Task OnAfterRenderAsync(bool firstRender)
        {
            if (!firstRender)
            {
                return;
            }

            await AuthenticationService.SignIn();
        }
    }
}
