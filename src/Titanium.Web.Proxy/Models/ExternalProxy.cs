﻿using System;
using System.Net;

namespace Titanium.Web.Proxy.Models
{
    /// <summary>
    ///     An upstream proxy this proxy uses if any.
    /// </summary>
    public class ExternalProxy : IExternalProxy
    {
        private static readonly Lazy<NetworkCredential> defaultCredentials =
            new Lazy<NetworkCredential>(() => CredentialCache.DefaultNetworkCredentials);

        private string? password;

        private string? userName;

        /// <summary>
        ///     Use default windows credentials?
        /// </summary>
        public bool UseDefaultCredentials { get; set; }

        /// <summary>
        ///     Bypass this proxy for connections to localhost?
        /// </summary>
        public bool BypassLocalhost { get; set; }

        /// <summary>
        ///     Username.
        /// </summary>
        public string? UserName
        {
            get => UseDefaultCredentials ? defaultCredentials.Value.UserName : userName;
            set
            {
                userName = value;

                if (defaultCredentials.Value.UserName != userName)
                {
                    UseDefaultCredentials = false;
                }
            }
        }

        /// <summary>
        ///     Password.
        /// </summary>
        public string? Password
        {
            get => UseDefaultCredentials ? defaultCredentials.Value.Password : password;
            set
            {
                password = value;

                if (defaultCredentials.Value.Password != password)
                {
                    UseDefaultCredentials = false;
                }
            }
        }

        /// <summary>
        ///     Host name.
        /// </summary>
        public string HostName { get; set; } = string.Empty;

        /// <summary>
        ///     Port.
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        ///     returns data in Hostname:port format.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"{HostName}:{Port}";
        }

    }
}
