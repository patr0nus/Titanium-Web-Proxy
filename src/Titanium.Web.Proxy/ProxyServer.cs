﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Extensions;
using Titanium.Web.Proxy.Helpers;
using Titanium.Web.Proxy.Models;
using Titanium.Web.Proxy.Network;
using Titanium.Web.Proxy.Network.Tcp;
using Titanium.Web.Proxy.StreamExtended.BufferPool;

namespace Titanium.Web.Proxy
{
    /// <inheritdoc />
    /// <summary>
    ///     This class is the backbone of proxy. One can create as many instances as needed.
    ///     However care should be taken to avoid using the same listening ports across multiple instances.
    /// </summary>
    public partial class ProxyServer : IDisposable
    {
        /// <summary>
        ///     HTTP &amp; HTTPS scheme shorthands.
        /// </summary>
        internal static readonly string UriSchemeHttp = Uri.UriSchemeHttp;
        internal static readonly string UriSchemeHttps = Uri.UriSchemeHttps;

        internal static ByteString UriSchemeHttp8 = (ByteString)UriSchemeHttp;
        internal static ByteString UriSchemeHttps8 = (ByteString)UriSchemeHttps;


        /// <summary>
        ///     A default exception log func.
        /// </summary>
        private readonly ExceptionHandler defaultExceptionFunc = e => { };

        /// <summary>
        ///     Backing field for exposed public property.
        /// </summary>
        private int clientConnectionCount;

        /// <summary>
        ///     Backing field for exposed public property.
        /// </summary>
        private ExceptionHandler? exceptionFunc;

        /// <summary>
        ///     Backing field for exposed public property.
        /// </summary>
        private int serverConnectionCount;

        /// <summary>
        ///     Initializes a new instance of ProxyServer class with provided parameters.
        /// </summary>
        /// <param name="rootCertificateName">Name of the root certificate.</param>
        /// <param name="rootCertificateIssuerName">Name of the root certificate issuer.</param>
        public ProxyServer(string? rootCertificateName, string? rootCertificateIssuerName)
        {
            BufferPool = new DefaultBufferPool();
            ProxyEndPoints = new List<ProxyEndPoint>();
            tcpConnectionFactory = new TcpConnectionFactory(this);

            CertificateManager = new CertificateManager(rootCertificateName, rootCertificateIssuerName, ExceptionFunc);
        }

        /// <summary>
        ///     An factory that creates tcp connection to server.
        /// </summary>
        private TcpConnectionFactory tcpConnectionFactory { get; }


        /// <summary>
        ///     Number of exception retries when connection pool is enabled.
        /// </summary>
        private int retries => EnableConnectionPool ? MaxCachedConnections : 0;

        /// <summary>
        ///     Is the proxy currently running?
        /// </summary>
        public bool ProxyRunning { get; private set; }

        /// <summary>
        ///     Gets or sets a value indicating whether requests will be chained to upstream gateway.
        ///     Defaults to false.
        /// </summary>
        public bool ForwardToUpstreamGateway { get; set; }


        /// <summary>
        ///     Enable disable HTTP/2 support.
        ///     Warning: HTTP/2 support is very limited
        ///      - only enabled when both client and server supports it (no protocol changing in proxy)
        ///      - cannot modify the request/response (e.g header modifications in BeforeRequest/Response events are ignored)
        /// </summary>
        public bool EnableHttp2 { get; set; } = false;

        /// <summary>
        ///     Should we check for certificate revocation during SSL authentication to servers
        ///     Note: If enabled can reduce performance. Defaults to false.
        /// </summary>
        public X509RevocationMode CheckCertificateRevocation { get; set; }

        /// <summary>
        ///     Does this proxy uses the HTTP protocol 100 continue behaviour strictly?
        ///     Broken 100 continue implementations on server/client may cause problems if enabled.
        ///     Defaults to false.
        /// </summary>
        public bool Enable100ContinueBehaviour { get; set; }

        /// <summary>
        ///     Should we enable experimental server connection pool?
        ///     Defaults to true.
        /// </summary>
        public bool EnableConnectionPool { get; set; } = true;

        /// <summary>
        ///     Should we enable tcp server connection prefetching?
        ///     When enabled, as soon as we receive a client connection we concurrently initiate 
        ///     corresponding server connection process using CONNECT hostname or SNI hostname on a separate task so that after parsing client request
        ///     we will have the server connection immediately ready or in the process of getting ready.
        ///     If a server connection is available in cache then this prefetch task will immediately return with the available connection from cache.
        ///     Defaults to true.
        /// </summary>
        public bool EnableTcpServerConnectionPrefetch { get; set; } = true;

        /// <summary>
        /// Gets or sets a Boolean value that specifies whether server and client stream Sockets are using the Nagle algorithm.
        /// Defaults to true, no nagle algorithm is used.
        /// </summary>
        public bool NoDelay { get; set; } = true;

        /// <summary>
        ///     Seconds client/server connection are to be kept alive when waiting for read/write to complete.
        ///     This will also determine the pool eviction time when connection pool is enabled.
        ///     Default value is 60 seconds.
        /// </summary>
        public int ConnectionTimeOutSeconds { get; set; } = 60;

        /// <summary>
        ///     Seconds server connection are to wait for connection to be established.
        ///     Default value is 20 seconds.
        /// </summary>
        public int ConnectTimeOutSeconds { get; set; } = 20;

        /// <summary>
        ///     Maximum number of concurrent connections per remote host in cache.
        ///     Only valid when connection pooling is enabled.
        ///     Default value is 2.
        /// </summary>
        public int MaxCachedConnections { get; set; } = 2;

        /// <summary>
        ///     Number of seconds to linger when Tcp connection is in TIME_WAIT state.
        ///     Default value is 30.
        /// </summary>
        public int TcpTimeWaitSeconds { get; set; } = 30;

        /// <summary>
        ///     Should we reuse client/server tcp sockets.
        ///     Default is true (disabled for linux/macOS due to bug in .Net core).
        /// </summary>
        public bool ReuseSocket { get; set; } = true;

        /// <summary>
        ///     Total number of active client connections.
        /// </summary>
        public int ClientConnectionCount => clientConnectionCount;

        /// <summary>
        ///     Total number of active server connections.
        /// </summary>
        public int ServerConnectionCount => serverConnectionCount;

        /// <summary>
        ///     Realm used during Proxy Basic Authentication.
        /// </summary>
        public string ProxyAuthenticationRealm { get; set; } = "TitaniumProxy";

        /// <summary>
        ///     List of supported Ssl versions.
        /// </summary>
#pragma warning disable 618
        public SslProtocols SupportedSslProtocols { get; set; } = SslProtocols.Ssl3 | SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12;
#pragma warning restore 618

        /// <summary>
        ///     The buffer pool used throughout this proxy instance.
        ///     Set custom implementations by implementing this interface.
        ///     By default this uses DefaultBufferPool implementation available in StreamExtended library package.
        ///     Buffer size should be at least 10 bytes.
        /// </summary>
        public IBufferPool BufferPool { get; set; }

        /// <summary>
        ///     Manages certificates used by this proxy.
        /// </summary>
        public CertificateManager CertificateManager { get; }

        /// <summary>
        ///     External proxy used for Http requests.
        /// </summary>
        public IExternalProxy? UpStreamHttpProxy { get; set; }

        /// <summary>
        ///     External proxy used for Https requests.
        /// </summary>
        public IExternalProxy? UpStreamHttpsProxy { get; set; }

        /// <summary>
        ///     Local adapter/NIC endpoint where proxy makes request via.
        ///     Defaults via any IP addresses of this machine.
        /// </summary>
        public IPEndPoint? UpStreamEndPoint { get; set; }

        /// <summary>
        ///     A list of IpAddress and port this proxy is listening to.
        /// </summary>
        public List<ProxyEndPoint> ProxyEndPoints { get; set; }

        /// <summary>
        ///     A callback to provide authentication credentials for up stream proxy this proxy is using for HTTP(S) requests.
        ///     User should return the ExternalProxy object with valid credentials.
        /// </summary>
        public Func<SessionEventArgsBase, Task<IExternalProxy?>>? GetCustomUpStreamProxyFunc { get; set; }

        /// <summary>
        ///     A callback to provide a chance for an upstream proxy failure to be handled by a new upstream proxy.
        ///     User should return the ExternalProxy object with valid credentials or null.
        /// </summary>
        public Func<SessionEventArgsBase, Task<IExternalProxy?>>? CustomUpStreamProxyFailureFunc { get; set; }

        /// <summary>
        ///     Callback for error events in this proxy instance.
        /// </summary>
        public ExceptionHandler ExceptionFunc
        {
            get => exceptionFunc ?? defaultExceptionFunc;
            set
            {
                exceptionFunc = value;
                CertificateManager.ExceptionFunc = value;
            }
        }

        /// <summary>
        ///     A callback to authenticate proxy clients via basic authentication.
        ///     Parameters are username and password as provided by client.
        ///     Should return true for successful authentication.
        /// </summary>
        public Func<SessionEventArgsBase, string, string, Task<bool>>? ProxyBasicAuthenticateFunc { get; set; }

        /// <summary>
        ///     A pluggable callback to authenticate clients by scheme instead of requiring basic authentication through ProxyBasicAuthenticateFunc.
        ///     Parameters are current working session, schemeType, and token as provided by a calling client.
        ///     Should return success for successful authentication, continuation if the package requests, or failure.
        /// </summary>
        public Func<SessionEventArgsBase, string, string, Task<ProxyAuthenticationContext>>? ProxySchemeAuthenticateFunc { get; set; }

        /// <summary>
        ///     A collection of scheme types, e.g. basic, NTLM, Kerberos, Negotiate, to return if scheme authentication is required.
        ///     Works in relation with ProxySchemeAuthenticateFunc.
        /// </summary>
        public IEnumerable<string> ProxyAuthenticationSchemes { get; set; } = new string[0];

        /// <summary>
        ///     Event occurs when client connection count changed.
        /// </summary>
        public event EventHandler? ClientConnectionCountChanged;

        /// <summary>
        ///     Event occurs when server connection count changed.
        /// </summary>
        public event EventHandler? ServerConnectionCountChanged;

        /// <summary>
        ///     Event to override the default verification logic of remote SSL certificate received during authentication.
        /// </summary>
        public event AsyncEventHandler<CertificateValidationEventArgs>? ServerCertificateValidationCallback;

        /// <summary>
        ///     Event to override client certificate selection during mutual SSL authentication.
        /// </summary>
        public event AsyncEventHandler<CertificateSelectionEventArgs>? ClientCertificateSelectionCallback;

        /// <summary>
        ///     Intercept request event to server.
        /// </summary>
        public event AsyncEventHandler<SessionEventArgs>? BeforeRequest;

        /// <summary>
        ///     Intercept response event from server.
        /// </summary>
        public event AsyncEventHandler<SessionEventArgs>? BeforeResponse;

        /// <summary>
        ///     Intercept after response event from server.
        /// </summary>
        public event AsyncEventHandler<SessionEventArgs>? AfterResponse;

        /// <summary>
        ///     Customize TcpClient used for client connection upon create.
        /// </summary>
        public event AsyncEventHandler<TcpClient>? OnClientConnectionCreate;

        /// <summary>
        ///     Customize TcpClient used for server connection upon create.
        /// </summary>
        public event AsyncEventHandler<TcpClient>? OnServerConnectionCreate;

        /// <summary>
        /// Customize the minimum ThreadPool size (increase it on a server)
        /// </summary>
        public int ThreadPoolWorkerThread { get; set; } = Environment.ProcessorCount;

        /// <summary>
        ///     Add a proxy end point.
        /// </summary>
        /// <param name="endPoint">The proxy endpoint.</param>
        public void AddEndPoint(ProxyEndPoint endPoint)
        {
            if (ProxyEndPoints.Any(x =>
                x.IpAddress.Equals(endPoint.IpAddress) && endPoint.Port != 0 && x.Port == endPoint.Port))
            {
                throw new Exception("Cannot add another endpoint to same port & ip address");
            }

            ProxyEndPoints.Add(endPoint);

            if (ProxyRunning)
            {
                listen(endPoint);
            }
        }

        /// <summary>
        ///     Remove a proxy end point.
        ///     Will throw error if the end point doesn't exist.
        /// </summary>
        /// <param name="endPoint">The existing endpoint to remove.</param>
        public void RemoveEndPoint(ProxyEndPoint endPoint)
        {
            if (ProxyEndPoints.Contains(endPoint) == false)
            {
                throw new Exception("Cannot remove endPoints not added to proxy");
            }

            ProxyEndPoints.Remove(endPoint);

            if (ProxyRunning)
            {
                quitListen(endPoint);
            }
        }


        /// <summary>
        ///     Start this proxy server instance.
        /// </summary>
        public void Start()
        {
            if (ProxyRunning)
            {
                throw new Exception("Proxy is already running.");
            }

            setThreadPoolMinThread(ThreadPoolWorkerThread);


            ProxyRunning = true;

            CertificateManager.ClearIdleCertificates();

            foreach (var endPoint in ProxyEndPoints)
            {
                listen(endPoint);
            }
        }

        /// <summary>
        ///     Stop this proxy server instance.
        /// </summary>
        public void Stop()
        {
            if (!ProxyRunning)
            {
                throw new Exception("Proxy is not running.");
            }

            foreach (var endPoint in ProxyEndPoints)
            {
                quitListen(endPoint);
            }

            ProxyEndPoints.Clear();

            CertificateManager?.StopClearIdleCertificates();
            tcpConnectionFactory.Dispose();

            ProxyRunning = false;
        }

        /// <summary>
        ///     Listen on given end point of local machine.
        /// </summary>
        /// <param name="endPoint">The end point to listen.</param>
        private void listen(ProxyEndPoint endPoint)
        {
            endPoint.Listener = new TcpListener(endPoint.IpAddress, endPoint.Port);

            if (ReuseSocket && RunTime.IsSocketReuseAvailable)
            {
                endPoint.Listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            }

            try
            {
                endPoint.Listener.Start();

                endPoint.Port = ((IPEndPoint)endPoint.Listener.LocalEndpoint).Port;

                // accept clients asynchronously
                endPoint.Listener.BeginAcceptTcpClient(onAcceptConnection, endPoint);
            }
            catch (SocketException ex)
            {
                var pex = new Exception(
                    $"Endpoint {endPoint} failed to start. Check inner exception and exception data for details.", ex);
                pex.Data.Add("ipAddress", endPoint.IpAddress);
                pex.Data.Add("port", endPoint.Port);
                throw pex;
            }
        }

        /// <summary>
        ///     Verify if its safe to set this end point as system proxy.
        /// </summary>
        /// <param name="endPoint">The end point to validate.</param>
        private void validateEndPointAsSystemProxy(ExplicitProxyEndPoint endPoint)
        {
            if (endPoint == null)
            {
                throw new ArgumentNullException(nameof(endPoint));
            }

            if (!ProxyEndPoints.Contains(endPoint))
            {
                throw new Exception("Cannot set endPoints not added to proxy as system proxy");
            }

            if (!ProxyRunning)
            {
                throw new Exception("Cannot set system proxy settings before proxy has been started.");
            }
        }

        /// <summary>
        ///     Act when a connection is received from client.
        /// </summary>
        private void onAcceptConnection(IAsyncResult asyn)
        {
            var endPoint = (ProxyEndPoint)asyn.AsyncState;

            TcpClient? tcpClient = null;

            try
            {
                // based on end point type call appropriate request handlers
                tcpClient = endPoint.Listener!.EndAcceptTcpClient(asyn);
                tcpClient.NoDelay = NoDelay;
            }
            catch (ObjectDisposedException)
            {
                // The listener was Stop()'d, disposing the underlying socket and
                // triggering the completion of the callback. We're already exiting,
                // so just return.
                return;
            }
            catch
            {
                // Other errors are discarded to keep proxy running
            }

            if (tcpClient != null)
            {
                Task.Run(async () =>
                {
                    await handleClient(tcpClient, endPoint);
                });
            }

            // Get the listener that handles the client request.
            endPoint.Listener!.BeginAcceptTcpClient(onAcceptConnection, endPoint);
        }


        /// <summary>
        /// Change the ThreadPool.WorkerThread minThread 
        /// </summary>
        /// <param name="workerThreads">minimum Threads allocated in the ThreadPool</param>
        private void setThreadPoolMinThread(int workerThreads)
        {
            ThreadPool.GetMinThreads(out int minWorkerThreads, out int minCompletionPortThreads);
            ThreadPool.GetMaxThreads(out int maxWorkerThreads, out _);

            minWorkerThreads = Math.Min(maxWorkerThreads, Math.Max(workerThreads, Environment.ProcessorCount));

            ThreadPool.SetMinThreads(minWorkerThreads, minCompletionPortThreads);
        }


        /// <summary>
        ///     Handle the client.
        /// </summary>
        /// <param name="tcpClient">The client.</param>
        /// <param name="endPoint">The proxy endpoint.</param>
        /// <returns>The task.</returns>
        private async Task handleClient(TcpClient tcpClient, ProxyEndPoint endPoint)
        {
            tcpClient.ReceiveTimeout = ConnectionTimeOutSeconds * 1000;
            tcpClient.SendTimeout = ConnectionTimeOutSeconds * 1000;

            tcpClient.LingerState = new LingerOption(true, TcpTimeWaitSeconds);

            await InvokeClientConnectionCreateEvent(tcpClient);

            using (var clientConnection = new TcpClientConnection(this, tcpClient))
            {
                if (endPoint is TransparentProxyEndPoint tep)
                {
                    await handleClient(tep, clientConnection);
                }
                else
                {
                    await handleClient((ExplicitProxyEndPoint)endPoint, clientConnection);
                }
            }
        }

        /// <summary>
        /// Handle exception.
        /// </summary>
        /// <param name="clientStream">The client stream.</param>
        /// <param name="exception">The exception.</param>
        private void onException(HttpClientStream clientStream, Exception exception)
        {
            ExceptionFunc(exception);
        }

        /// <summary>
        ///     Quit listening on the given end point.
        /// </summary>
        private void quitListen(ProxyEndPoint endPoint)
        {
            endPoint.Listener!.Stop();
            endPoint.Listener.Server.Dispose();
        }

        /// <summary>
        ///     Update client connection count.
        /// </summary>
        /// <param name="increment">Should we increment/decrement?</param>
        internal void UpdateClientConnectionCount(bool increment)
        {
            if (increment)
            {
                Interlocked.Increment(ref clientConnectionCount);
            }
            else
            {
                Interlocked.Decrement(ref clientConnectionCount);
            }

            ClientConnectionCountChanged?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        ///     Update server connection count.
        /// </summary>
        /// <param name="increment">Should we increment/decrement?</param>
        internal void UpdateServerConnectionCount(bool increment)
        {
            if (increment)
            {
                Interlocked.Increment(ref serverConnectionCount);
            }
            else
            {
                Interlocked.Decrement(ref serverConnectionCount);
            }

            ServerConnectionCountChanged?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        ///     Invoke client tcp connection events if subscribed by API user.
        /// </summary>
        /// <param name="client">The TcpClient object.</param>
        /// <returns></returns>
        internal async Task InvokeClientConnectionCreateEvent(TcpClient client)
        {
            // client connection created
            if (OnClientConnectionCreate != null)
            {
                await OnClientConnectionCreate.InvokeAsync(this, client, ExceptionFunc);
            }
        }

        /// <summary>
        ///     Invoke server tcp connection events if subscribed by API user.
        /// </summary>
        /// <param name="client">The TcpClient object.</param>
        /// <returns></returns>
        internal async Task InvokeServerConnectionCreateEvent(TcpClient client)
        {
            // server connection created
            if (OnServerConnectionCreate != null)
            {
                await OnServerConnectionCreate.InvokeAsync(this, client, ExceptionFunc);
            }
        }

        /// <summary>
        ///     Connection retry policy when using connection pool.
        /// </summary>
        private RetryPolicy<T> retryPolicy<T>() where T : Exception
        {
            return new RetryPolicy<T>(retries, tcpConnectionFactory);
        }

        /// <summary>
        ///     Dispose the Proxy instance.
        /// </summary>
        public void Dispose()
        {
            if (ProxyRunning)
            {
                Stop();
            }

            CertificateManager?.Dispose();
            BufferPool?.Dispose();
        }
    }
}
