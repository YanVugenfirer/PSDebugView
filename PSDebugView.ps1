# Run Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# ================================================================
# DBWIN System-Wide User-Mode Debug Output Collector
#
# Captures:
#   Local\DBWIN_*   - OutputDebugString from current user session
#   Global\DBWIN_*  - OutputDebugString from Session 0 / services
#
# Run PowerShell AS ADMINISTRATOR for Global\ capture.
#
# Do NOT run DebugView or another DBWIN collector simultaneously.
# ================================================================

if (-not ("DbWinCollector" -as [type])) {

Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public static class DbWinCollector
{
    private const int BUFFER_SIZE = 4096;

    private const uint PAGE_READWRITE = 0x04;
    private const uint FILE_MAP_READ  = 0x0004;

    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint WAIT_TIMEOUT  = 0x00000102;
    private const uint WAIT_FAILED   = 0xFFFFFFFF;

    private const int ERROR_ALREADY_EXISTS   = 183;
    private const int ERROR_NOT_ALL_ASSIGNED = 1300;

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY             = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED    = 0x0002;

    private static readonly IntPtr INVALID_HANDLE_VALUE =
        new IntPtr(-1);

    private static volatile bool stopping = false;

    private static Receiver localReceiver;
    private static Receiver globalReceiver;

    private static readonly object consoleLock =
        new object();


    // ============================================================
    // Native structures
    // ============================================================

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }


    // ============================================================
    // Native functions
    // ============================================================

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern bool
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string StringSecurityDescriptor,
            uint StringSDRevision,
            out IntPtr SecurityDescriptor,
            IntPtr SecurityDescriptorSize);


    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr CreateEventW(
        ref SECURITY_ATTRIBUTES lpEventAttributes,
        bool bManualReset,
        bool bInitialState,
        string lpName);


    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr CreateMutexW(
        ref SECURITY_ATTRIBUTES lpMutexAttributes,
        bool bInitialOwner,
        string lpName);


    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr CreateFileMappingW(
        IntPtr hFile,
        ref SECURITY_ATTRIBUTES lpFileMappingAttributes,
        uint flProtect,
        uint dwMaximumSizeHigh,
        uint dwMaximumSizeLow,
        string lpName);


    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern IntPtr MapViewOfFile(
        IntPtr hFileMappingObject,
        uint dwDesiredAccess,
        uint dwFileOffsetHigh,
        uint dwFileOffsetLow,
        UIntPtr dwNumberOfBytesToMap);


    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool SetEvent(
        IntPtr hEvent);


    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern uint WaitForSingleObject(
        IntPtr hHandle,
        uint dwMilliseconds);


    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool UnmapViewOfFile(
        IntPtr lpBaseAddress);


    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool CloseHandle(
        IntPtr hObject);


    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(
        IntPtr hMem);


    [DllImport("kernel32.dll")]
    private static extern uint GetACP();


    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern int MultiByteToWideChar(
        uint CodePage,
        uint dwFlags,
        byte[] lpMultiByteStr,
        int cbMultiByte,
        [Out] char[] lpWideCharStr,
        int cchWideChar);


    [DllImport(
        "advapi32.dll",
        SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle);


    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern bool LookupPrivilegeValue(
        string lpSystemName,
        string lpName,
        out LUID lpLuid);


    [DllImport(
        "advapi32.dll",
        SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);


    // ============================================================
    // Public interface
    // ============================================================

    public static void Start()
    {
        if (localReceiver != null ||
            globalReceiver != null)
        {
            throw new InvalidOperationException(
                "DBWIN collector is already running.");
        }

        stopping = false;

        /*
         * Global\ file mapping creation from a normal interactive
         * session requires SeCreateGlobalPrivilege.
         */
        if (Process.GetCurrentProcess().SessionId != 0)
        {
            EnablePrivilege(
                "SeCreateGlobalPrivilege");
        }

        try
        {
            localReceiver =
                new Receiver(
                    "LOCAL",
                    @"Local\");

            /*
             * Start local before constructing global.
             */
            localReceiver.Start();


            globalReceiver =
                new Receiver(
                    "GLOBAL",
                    @"Global\");

            globalReceiver.Start();


            WriteLine("");
            WriteLine("DBWIN collector started.");
            WriteLine("");
            WriteLine(
                "  LOCAL  = current interactive session");
            WriteLine(
                "  GLOBAL = Session 0 / services");
            WriteLine("");
        }
        catch
        {
            Stop();
            throw;
        }
    }


    public static void Stop()
    {
        stopping = true;

        /*
         * Threads use a 100 ms wait timeout, so they will notice
         * stopping quickly.
         */

        if (localReceiver != null)
        {
            localReceiver.Dispose();
            localReceiver = null;
        }

        if (globalReceiver != null)
        {
            globalReceiver.Dispose();
            globalReceiver = null;
        }

        WriteLine("");
        WriteLine("DBWIN collector stopped.");
    }


    // ============================================================
    // DBWIN receiver
    // ============================================================

    private sealed class Receiver : IDisposable
    {
        private readonly string displayName;
        private readonly string prefix;

        private IntPtr hMutex       = IntPtr.Zero;
        private IntPtr hBufferReady = IntPtr.Zero;
        private IntPtr hDataReady   = IntPtr.Zero;
        private IntPtr hMapping     = IntPtr.Zero;
        private IntPtr view         = IntPtr.Zero;

        private Thread thread;


        public Receiver(
            string displayName,
            string prefix)
        {
            this.displayName = displayName;
            this.prefix = prefix;

            try
            {
                CreateObjects();
            }
            catch
            {
                Dispose();
                throw;
            }
        }


        // --------------------------------------------------------
        // Create DBWIN kernel objects
        // --------------------------------------------------------

        private void CreateObjects()
        {
            IntPtr securityDescriptor =
                IntPtr.Zero;

            /*
             * DBWIN is intended for IPC between arbitrary
             * applications/services.
             *
             * Give Everyone full access to these temporary named
             * objects.
             *
             * This is intentionally permissive, similar to the
             * semantics needed by a system-wide debug monitor.
             */
            const string sddl =
                "D:(A;;GA;;;WD)";


            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl,
                    1,
                    out securityDescriptor,
                    IntPtr.Zero))
            {
                ThrowLastError(
                    "ConvertStringSecurityDescriptorToSecurityDescriptor");
            }


            try
            {
                SECURITY_ATTRIBUTES sa =
                    new SECURITY_ATTRIBUTES();

                sa.nLength =
                    Marshal.SizeOf(
                        typeof(SECURITY_ATTRIBUTES));

                sa.lpSecurityDescriptor =
                    securityDescriptor;

                sa.bInheritHandle =
                    false;


                /*
                 * DBWinMutex serializes writers.
                 *
                 * Its prior existence does NOT indicate another
                 * collector, so we don't reject ERROR_ALREADY_EXISTS
                 * here.
                 */
                hMutex =
                    CreateMutexW(
                        ref sa,
                        false,
                        prefix + "DBWinMutex");

                if (hMutex == IntPtr.Zero)
                {
                    ThrowLastError(
                        prefix + "DBWinMutex");
                }


                /*
                 * IMPORTANT:
                 *
                 * DBWIN_BUFFER_READY must initially be UNSIGNALED.
                 *
                 * The collector explicitly signals it immediately
                 * before waiting for DATA_READY.
                 */
                hBufferReady =
                    CreateEventW(
                        ref sa,
                        false,      // auto-reset
                        false,      // initially unsignaled
                        prefix + "DBWIN_BUFFER_READY");

                if (hBufferReady == IntPtr.Zero)
                {
                    ThrowLastError(
                        prefix + "DBWIN_BUFFER_READY");
                }

                ThrowIfAlreadyOwned(
                    prefix + "DBWIN_BUFFER_READY");


                /*
                 * Producer signals this after it has written:
                 *
                 *   DWORD PID
                 *   char message[]
                 */
                hDataReady =
                    CreateEventW(
                        ref sa,
                        false,      // auto-reset
                        false,      // initially unsignaled
                        prefix + "DBWIN_DATA_READY");

                if (hDataReady == IntPtr.Zero)
                {
                    ThrowLastError(
                        prefix + "DBWIN_DATA_READY");
                }

                ThrowIfAlreadyOwned(
                    prefix + "DBWIN_DATA_READY");


                /*
                 * Classic DBWIN_BUFFER is exactly 4096 bytes.
                 */
                hMapping =
                    CreateFileMappingW(
                        INVALID_HANDLE_VALUE,
                        ref sa,
                        PAGE_READWRITE,
                        0,
                        BUFFER_SIZE,
                        prefix + "DBWIN_BUFFER");

                if (hMapping == IntPtr.Zero)
                {
                    ThrowLastError(
                        prefix + "DBWIN_BUFFER");
                }

                ThrowIfAlreadyOwned(
                    prefix + "DBWIN_BUFFER");


                /*
                 * The collector only needs read access.
                 * Producers obtain write access separately.
                 */
                view =
                    MapViewOfFile(
                        hMapping,
                        FILE_MAP_READ,
                        0,
                        0,
                        (UIntPtr)BUFFER_SIZE);

                if (view == IntPtr.Zero)
                {
                    ThrowLastError(
                        "MapViewOfFile(" +
                        prefix +
                        "DBWIN_BUFFER)");
                }
            }
            finally
            {
                if (securityDescriptor != IntPtr.Zero)
                {
                    LocalFree(
                        securityDescriptor);
                }
            }
        }


        private void ThrowIfAlreadyOwned(
            string objectName)
        {
            int error =
                Marshal.GetLastWin32Error();

            if (error == ERROR_ALREADY_EXISTS)
            {
                throw new InvalidOperationException(
                    objectName +
                    " already exists. " +
                    "Another DBWIN collector is probably active. " +
                    "Close DebugView or the other collector first.");
            }
        }


        // --------------------------------------------------------
        // Start receiver thread
        // --------------------------------------------------------

        public void Start()
        {
            thread =
                new Thread(Run);

            thread.Name =
                "DBWIN-" + displayName;

            thread.IsBackground =
                true;

            thread.Start();
        }


        // --------------------------------------------------------
        // Main DBWIN handshake
        // --------------------------------------------------------

        private void Run()
        {
            byte[] bytes =
                new byte[
                    BUFFER_SIZE - sizeof(int)];


            while (!stopping)
            {
                /*
                 * Tell OutputDebugString() producers:
                 *
                 *     "The DBWIN_BUFFER slot is free."
                 *
                 * This is the beginning of ONE DBWIN transaction.
                 */
                if (!SetEvent(hBufferReady))
                {
                    int error =
                        Marshal.GetLastWin32Error();

                    WriteLine(
                        displayName +
                        ": SetEvent(DBWIN_BUFFER_READY) failed: " +
                        new Win32Exception(error).Message);

                    break;
                }


                /*
                 * Wait until one producer has:
                 *
                 *   1. consumed BUFFER_READY
                 *   2. written PID
                 *   3. written message
                 *   4. NUL terminated message
                 *   5. signaled DATA_READY
                 */
                uint result =
                    WaitForSingleObject(
                        hDataReady,
                        100);


                if (result == WAIT_TIMEOUT)
                {
                    continue;
                }


                if (result == WAIT_FAILED)
                {
                    int error =
                        Marshal.GetLastWin32Error();

                    WriteLine(
                        displayName +
                        ": WaitForSingleObject failed: " +
                        new Win32Exception(error).Message);

                    break;
                }


                if (result != WAIT_OBJECT_0)
                {
                    continue;
                }


                /*
                 * DATA_READY means the producer has finished
                 * writing the buffer.
                 *
                 * Do NOT signal BUFFER_READY again until we have
                 * copied the payload.
                 */

                int pid =
                    Marshal.ReadInt32(view);


                Marshal.Copy(
                    IntPtr.Add(
                        view,
                        sizeof(int)),
                    bytes,
                    0,
                    bytes.Length);


                /*
                 * Locate ANSI NUL terminator.
                 */
                int length = 0;

                while (length < bytes.Length &&
                       bytes[length] != 0)
                {
                    ++length;
                }


                /*
                 * At this point we own a private copy.
                 *
                 * Do not SetEvent(BUFFER_READY) here.
                 * The next iteration performs exactly one
                 * BUFFER_READY signal for the next message.
                 */


                string message =
                    DecodeAnsi(
                        bytes,
                        length);


                WriteMessage(
                    displayName,
                    pid,
                    message);
            }
        }


        // --------------------------------------------------------
        // Cleanup
        // --------------------------------------------------------

        public void Dispose()
        {
            /*
             * Let the thread notice stopping via its short timeout.
             */
            if (thread != null &&
                thread.IsAlive &&
                Thread.CurrentThread != thread)
            {
                thread.Join(1000);
            }

            thread = null;


            if (view != IntPtr.Zero)
            {
                UnmapViewOfFile(view);
                view = IntPtr.Zero;
            }


            if (hMapping != IntPtr.Zero)
            {
                CloseHandle(hMapping);
                hMapping = IntPtr.Zero;
            }


            if (hDataReady != IntPtr.Zero)
            {
                CloseHandle(hDataReady);
                hDataReady = IntPtr.Zero;
            }


            if (hBufferReady != IntPtr.Zero)
            {
                CloseHandle(hBufferReady);
                hBufferReady = IntPtr.Zero;
            }


            if (hMutex != IntPtr.Zero)
            {
                CloseHandle(hMutex);
                hMutex = IntPtr.Zero;
            }
        }
    }


    // ============================================================
    // Message formatting
    // ============================================================

    private static void WriteMessage(
        string scope,
        int pid,
        string message)
    {
        string processName = "?";
        int sessionId = -1;


        try
        {
            using (
                Process p =
                    Process.GetProcessById(pid))
            {
                processName =
                    p.ProcessName;

                try
                {
                    sessionId =
                        p.SessionId;
                }
                catch
                {
                }
            }
        }
        catch
        {
            /*
             * Very short-lived applications can exit between
             * OutputDebugString() and this lookup.
             */
        }


        string session =
            sessionId >= 0
            ? "S" + sessionId
            : "S?";


        string header =
            String.Format(
                "[{0:HH:mm:ss.fff}] [{1}] [{2}] [{3}:{4}] ",
                DateTime.Now,
                scope,
                session,
                processName,
                pid);


        lock (consoleLock)
        {
            Console.Write(header);

            Console.Write(message);

            /*
             * Preserve messages that already contain newline.
             */
            if (!message.EndsWith("\n"))
            {
                Console.WriteLine();
            }
        }
    }


    private static void WriteLine(
        string text)
    {
        lock (consoleLock)
        {
            Console.WriteLine(text);
        }
    }


    // ============================================================
    // DBWIN ANSI decoder
    // ============================================================

    private static string DecodeAnsi(
        byte[] bytes,
        int length)
    {
        if (length <= 0)
        {
            return String.Empty;
        }


        /*
         * Don't use Encoding.Default here.
         *
         * On modern .NET / PowerShell 7 Encoding.Default is UTF-8,
         * while classic DBWIN data is in the Windows ANSI code page.
         */
        uint codePage =
            GetACP();


        int required =
            MultiByteToWideChar(
                codePage,
                0,
                bytes,
                length,
                null,
                0);


        if (required <= 0)
        {
            return String.Empty;
        }


        char[] chars =
            new char[required];


        int converted =
            MultiByteToWideChar(
                codePage,
                0,
                bytes,
                length,
                chars,
                chars.Length);


        if (converted <= 0)
        {
            return String.Empty;
        }


        return new String(
            chars,
            0,
            converted);
    }


    // ============================================================
    // SeCreateGlobalPrivilege
    // ============================================================

    private static void EnablePrivilege(
        string privilegeName)
    {
        IntPtr token =
            IntPtr.Zero;


        if (!OpenProcessToken(
                Process.GetCurrentProcess().Handle,
                TOKEN_ADJUST_PRIVILEGES |
                TOKEN_QUERY,
                out token))
        {
            ThrowLastError(
                "OpenProcessToken");
        }


        try
        {
            LUID luid;


            if (!LookupPrivilegeValue(
                    null,
                    privilegeName,
                    out luid))
            {
                ThrowLastError(
                    "LookupPrivilegeValue(" +
                    privilegeName +
                    ")");
            }


            TOKEN_PRIVILEGES tp =
                new TOKEN_PRIVILEGES();


            tp.PrivilegeCount =
                1;


            tp.Privileges =
                new LUID_AND_ATTRIBUTES();


            tp.Privileges.Luid =
                luid;


            tp.Privileges.Attributes =
                SE_PRIVILEGE_ENABLED;


            if (!AdjustTokenPrivileges(
                    token,
                    false,
                    ref tp,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                ThrowLastError(
                    "AdjustTokenPrivileges(" +
                    privilegeName +
                    ")");
            }


            int error =
                Marshal.GetLastWin32Error();


            if (error == ERROR_NOT_ALL_ASSIGNED)
            {
                throw new Win32Exception(
                    error,
                    privilegeName +
                    " is not available in the current token. " +
                    "Run PowerShell as Administrator.");
            }
        }
        finally
        {
            if (token != IntPtr.Zero)
            {
                CloseHandle(token);
            }
        }
    }


    // ============================================================
    // Error helper
    // ============================================================

    private static void ThrowLastError(
        string operation)
    {
        int error =
            Marshal.GetLastWin32Error();


        throw new Win32Exception(
            error,
            operation);
    }
}
'@

}


# ================================================================
# Start collector
# ================================================================

[DbWinCollector]::Start()

try
{
    Write-Host "Listening for OutputDebugString..."
    Write-Host "Press Ctrl+C to stop."
    Write-Host ""

    while ($true)
    {
        Start-Sleep -Milliseconds 500
    }
}
finally
{
    [DbWinCollector]::Stop()
}