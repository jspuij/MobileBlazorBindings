// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.MobileBlazorBindings;
using System.Collections.Generic;
using Xamarin.Forms;

namespace AuthApp
{
    public class App : Application
    {
        public App(string[] args = null, IFileProvider fileProvider = null)
        {
            var hostBuilder = MobileBlazorBindingsHost.CreateDefaultBuilder(args)
                .ConfigureServices((hostContext, services) =>
                {
                    // Adds web-specific services such as NavigationManager
                    services.AddBlazorHybrid();

                    // Register app-specific services
                    services.AddSingleton<CounterState>();
                    services.AddOidcAuthentication(options =>
                    {
                        options.ProviderOptions.Authority = "https://demo.identityserver.io/";
                        options.ProviderOptions.ClientId = "interactive.public";
                        options.ProviderOptions.DefaultScopes.Add("openid");
                        options.ProviderOptions.DefaultScopes.Add("profile");
                        options.ProviderOptions.ResponseType = "code";
                    });
                })
                .UseWebRoot("wwwroot");

            if (fileProvider != null)
            {
                hostBuilder.UseStaticFiles(fileProvider);
            }
            else
            {
                hostBuilder.UseStaticFiles();
            }
            var host = hostBuilder.Build();

            MainPage = new ContentPage { Title = "My Application" };
            host.AddComponent<Main>(parent: MainPage);
        }

        protected override void OnStart()
        {
        }

        protected override void OnSleep()
        {
        }

        protected override void OnResume()
        {
        }
    }
}
