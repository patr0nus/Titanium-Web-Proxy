using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Titanium.Web.Proxy.Helpers;
using Titanium.Web.Proxy.Network.Certificate;
using Titanium.Web.Proxy.Shared;

namespace Titanium.Web.Proxy.Network
{
    /// <summary>
    ///     A class to manage SSL certificates used by this proxy server.
    /// </summary>
    public sealed class CertificateManager : IDisposable
    {
        private const string defaultRootCertificateIssuer = "Titanium";

        private const string defaultRootRootCertificateName = "Titanium Root Certificate Authority";

        /// <summary>
        ///     Cache dictionary
        /// </summary>
        private readonly ConcurrentDictionary<string, CachedCertificate> cachedCertificates
                            = new ConcurrentDictionary<string, CachedCertificate>();

        /// <summary>
        /// A list of pending certificate creation tasks.
        /// Useful to prevent multiple threads working on same certificate generation 
        /// when burst certificate generation requests happen for same certificate.
        /// </summary>
        private readonly ConcurrentDictionary<string, Task<X509Certificate2?>> pendingCertificateCreationTasks
                            = new ConcurrentDictionary<string, Task<X509Certificate2?>>();

        private readonly CancellationTokenSource clearCertificatesTokenSource
                            = new CancellationTokenSource();

        private readonly object rootCertCreationLock = new object();

        private ICertificateMaker? certEngineValue;
        private ICertificateMaker certEngine
        {
            get
            {
                if (certEngineValue == null)
                {
                    certEngineValue = new BCCertificateMaker(ExceptionFunc);
                }
                return certEngineValue;
            }
        }

        private string? issuer;

        private X509Certificate2? rootCertificate;

        private string? rootCertificateName;

        private ICertificateCache certificateCache = new DefaultCertificateDiskCache();

        /// <summary>
        ///     Initializes a new instance of the <see cref="CertificateManager"/> class.
        /// </summary>
        /// <param name="rootCertificateName"></param>
        /// <param name="rootCertificateIssuerName"></param>
        /// <param name="exceptionFunc"></param>
        internal CertificateManager(string? rootCertificateName, string? rootCertificateIssuerName, ExceptionHandler exceptionFunc)
        {
            ExceptionFunc = exceptionFunc;

            if (rootCertificateName != null)
            {
                RootCertificateName = rootCertificateName;
            }

            if (rootCertificateIssuerName != null)
            {
                RootCertificateIssuerName = rootCertificateIssuerName;
            }
        }

        /// <summary>
        ///     Is the root certificate used by this proxy is valid?
        /// </summary>
        internal bool CertValidated => RootCertificate != null;

        /// <summary>
        /// Exception handler
        /// </summary>
        internal ExceptionHandler ExceptionFunc { get; set; }


        /// <summary>
        ///     Password of the Root certificate file.
        ///     <para>Set a password for the .pfx file</para>
        /// </summary>
        public string PfxPassword { get; set; } = string.Empty;

        /// <summary>
        ///     Name(path) of the Root certificate file.
        ///     <para>
        ///         Set the name(path) of the .pfx file. If it is string.Empty Root certificate file will be named as
        ///         "rootCert.pfx" (and will be saved in proxy dll directory)
        ///     </para>
        /// </summary>
        public string PfxFilePath { get; set; } = string.Empty;

        /// <summary>
        ///     Name of the root certificate issuer.
        ///     (This is valid only when RootCertificate property is not set.)
        /// </summary>
        public string RootCertificateIssuerName
        {
            get => issuer ?? defaultRootCertificateIssuer;
            set => issuer = value;
        }

        /// <summary>
        ///     Name of the root certificate.
        ///     (This is valid only when RootCertificate property is not set.)
        ///     If no certificate is provided then a default Root Certificate will be created and used.
        ///     The provided root certificate will be stored in proxy exe directory with the private key.
        ///     Root certificate file will be named as "rootCert.pfx".
        /// </summary>
        public string RootCertificateName
        {
            get => rootCertificateName ?? defaultRootRootCertificateName;
            set => rootCertificateName = value;
        }

        /// <summary>
        ///     The root certificate.
        /// </summary>
        public X509Certificate2? RootCertificate
        {
            get => rootCertificate;
            set
            {
                ClearRootCertificate();
                rootCertificate = value;
            }
        }

        /// <summary>
        ///     Save all fake certificates using <seealso cref="CertificateStorage"/>.
        ///     <para>for can load the certificate and not make new certificate every time. </para>
        /// </summary>
        public bool SaveFakeCertificates { get; set; } = false;

        /// <summary>
        ///     The fake certificate cache storage.
        ///     The default cache storage implementation saves certificates in folder "crts" (will be created in proxy dll directory).
        ///     Implement ICertificateCache interface and assign concrete class here to customize.
        /// </summary>
        public ICertificateCache CertificateStorage
        {
            get => certificateCache;
            set => certificateCache = value ?? new DefaultCertificateDiskCache();
        }

        /// <summary>
        ///     Overwrite Root certificate file.
        ///     <para>true : replace an existing .pfx file if password is incorrect or if RootCertificate = null.</para>
        /// </summary>
        public bool OverwritePfxFile { get; set; } = true;

        /// <summary>
        ///     Minutes certificates should be kept in cache when not used.
        /// </summary>
        public int CertificateCacheTimeOutMinutes { get; set; } = 60;

        /// <summary>
        ///     Adjust behaviour when certificates are saved to filesystem.
        /// </summary>
        public X509KeyStorageFlags StorageFlag { get; set; } = X509KeyStorageFlags.Exportable;

        /// <summary>
        ///     Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            clearCertificatesTokenSource.Dispose();
        }

        private X509Certificate2 makeCertificate(string certificateName, bool isRootCertificate)
        {
            //if (isRoot != (null == signingCertificate))
            //{
            //    throw new ArgumentException(
            //        "You must specify a Signing Certificate if and only if you are not creating a root.",
            //        nameof(signingCertificate));
            //}

            if (!isRootCertificate && RootCertificate == null)
            {
                CreateRootCertificate();
            }

            var certificate = certEngine.MakeCertificate(certificateName, isRootCertificate ? null : RootCertificate);

            return certificate;
        }

        /// <summary>
        ///     Create an SSL certificate
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="isRootCertificate"></param>
        /// <returns></returns>
        internal X509Certificate2? CreateCertificate(string certificateName, bool isRootCertificate)
        {
            X509Certificate2? certificate;
            try
            {
                if (!isRootCertificate && SaveFakeCertificates)
                {
                    string subjectName = ProxyConstants.CNRemoverRegex
                        .Replace(certificateName, string.Empty)
                        .Replace("*", "$x$");

                    try
                    {
                        certificate = certificateCache.LoadCertificate(subjectName, StorageFlag);
                    }
                    catch (Exception e)
                    {
                        ExceptionFunc(new Exception("Failed to load fake certificate.", e));
                        certificate = null;
                    }

                    if (certificate == null)
                    {
                        certificate = makeCertificate(certificateName, false);

                        try
                        {
                            certificateCache.SaveCertificate(subjectName, certificate);
                        }
                        catch (Exception e)
                        {
                            ExceptionFunc(new Exception("Failed to save fake certificate.", e));
                        }
                    }
                }
                else
                {
                    certificate = makeCertificate(certificateName, isRootCertificate);
                }
            }
            catch (Exception e)
            {
                ExceptionFunc(e);
                certificate = null;
            }

            return certificate;
        }

        /// <summary>
        ///     Creates a server certificate signed by the root certificate.
        /// </summary>
        /// <param name="certificateName"></param>
        /// <returns></returns>
        public async Task<X509Certificate2?> CreateServerCertificate(string certificateName)
        {
            // check in cache first
            if (cachedCertificates.TryGetValue(certificateName, out var cached))
            {
                cached.LastAccess = DateTime.Now;
                return cached.Certificate;
            }

            // handle burst requests with same certificate name
            // by checking for existing task for same certificate name
            if (pendingCertificateCreationTasks.TryGetValue(certificateName, out var task))
            {
                return await task;
            }

            // run certificate creation task & add it to pending tasks
            task = Task.Run(() =>
            {
                var result = CreateCertificate(certificateName, false);
                if (result != null)
                {
                    cachedCertificates.TryAdd(certificateName, new CachedCertificate(result));
                }

                return result;
            });
            pendingCertificateCreationTasks.TryAdd(certificateName, task);

            // cleanup pending tasks & return result
            var certificate = await task;
            pendingCertificateCreationTasks.TryRemove(certificateName, out task);

            return certificate;
        }

        /// <summary>
        ///     A method to clear outdated certificates
        /// </summary>
        internal async void ClearIdleCertificates()
        {
            var cancellationToken = clearCertificatesTokenSource.Token;
            while (!cancellationToken.IsCancellationRequested)
            {
                var cutOff = DateTime.Now.AddMinutes(-CertificateCacheTimeOutMinutes);

                var outdated = cachedCertificates.Where(x => x.Value.LastAccess < cutOff).ToList();

                foreach (var cache in outdated)
                {
                    cachedCertificates.TryRemove(cache.Key, out _);
                }

                // after a minute come back to check for outdated certificates in cache
                try
                {
                    await Task.Delay(1000 * 60, cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    return;
                }
            }
        }

        /// <summary>
        ///     Stops the certificate cache clear process
        /// </summary>
        internal void StopClearIdleCertificates()
        {
            clearCertificatesTokenSource.Cancel();
        }

        /// <summary>
        ///     Attempts to create a RootCertificate.
        /// </summary>
        /// <param name="persistToFile">if set to <c>true</c> try to load/save the certificate from rootCert.pfx.</param>
        /// <returns>
        ///     true if succeeded, else false.
        /// </returns>
        public bool CreateRootCertificate(bool persistToFile = true)
        {
            Console.WriteLine("Creating");
            lock (rootCertCreationLock)
            {
                if (persistToFile && RootCertificate == null)
                {
                    RootCertificate = LoadRootCertificate();
                }

                if (RootCertificate != null)
                {
                    return true;
                }

                if (!OverwritePfxFile)
                {
                    try
                    {
                        var rootCert = certificateCache.LoadRootCertificate(PfxFilePath, PfxPassword,
                            X509KeyStorageFlags.Exportable);

                        if (rootCert != null)
                        {
                            return false;
                        }
                    }
                    catch
                    {
                        // root cert cannot be loaded
                    }
                }

                try
                {
                    RootCertificate = CreateCertificate(RootCertificateName, true);
                }
                catch (Exception e)
                {
                    ExceptionFunc(e);
                }

                if (persistToFile && RootCertificate != null)
                {
                    try
                    {
                        try
                        {
                            certificateCache.Clear();
                        }
                        catch
                        {
                            // ignore
                        }

                        certificateCache.SaveRootCertificate(PfxFilePath, PfxPassword, RootCertificate);
                    }
                    catch (Exception e)
                    {
                        ExceptionFunc(e);
                    }
                }

                return RootCertificate != null;
            }
        }

        /// <summary>
        ///     Loads root certificate from current executing assembly location with expected name rootCert.pfx.
        /// </summary>
        /// <returns></returns>
        public X509Certificate2? LoadRootCertificate()
        {
            try
            {
                return certificateCache.LoadRootCertificate(PfxFilePath, PfxPassword, X509KeyStorageFlags.Exportable);
            }
            catch (Exception e)
            {
                ExceptionFunc(e);
                return null;
            }
        }

        /// <summary>
        ///     Manually load a Root certificate file from give path (.pfx file).
        /// </summary>
        /// <param name="pfxFilePath">
        ///     Set the name(path) of the .pfx file. If it is string.Empty Root certificate file will be
        ///     named as "rootCert.pfx" (and will be saved in proxy dll directory).
        /// </param>
        /// <param name="password">Set a password for the .pfx file.</param>
        /// <param name="overwritePfXFile">
        ///     true : replace an existing .pfx file if password is incorrect or if
        ///     RootCertificate==null.
        /// </param>
        /// <param name="storageFlag"></param>
        /// <returns>
        ///     true if succeeded, else false.
        /// </returns>
        public bool LoadRootCertificate(string pfxFilePath, string password, bool overwritePfXFile = true,
            X509KeyStorageFlags storageFlag = X509KeyStorageFlags.Exportable)
        {
            PfxFilePath = pfxFilePath;
            PfxPassword = password;
            OverwritePfxFile = overwritePfXFile;
            StorageFlag = storageFlag;

            RootCertificate = LoadRootCertificate();

            return RootCertificate != null;
        }

        /// <summary>
        ///     Clear the root certificate and cache.
        /// </summary>
        public void ClearRootCertificate()
        {
            certificateCache.Clear();
            cachedCertificates.Clear();
            rootCertificate = null;
        }
    }
}
