using Android.App;
using Android.Content;
using Android.Content.PM;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.MobileBlazorBindings.Authentication
{
    [Activity(NoHistory = true, LaunchMode = LaunchMode.SingleTop)]
    [IntentFilter(new[] { Intent.ActionView }, Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable }, DataScheme = "app")]
    public class WebAuthenticationCallbackActivity : Xamarin.Essentials.WebAuthenticatorCallbackActivity
    {
    }
}
