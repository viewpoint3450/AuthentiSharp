using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthentiSharp
{
    /// <summary>
    /// Provides abstractions for validating Authenticode Signatures of files.
    /// </summary>
    public static class AuthentiSharp
    {
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust([In] IntPtr hwnd, [In][MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, [In] WINTRUST_DATA pWVTData);

        private const uint WTD_HASH_ONLY_FLAG = 0x200;
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private sealed class WINTRUST_FILE_INFO
        {
            private readonly uint cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>();
            private readonly string pcwszFilePath;
            private readonly IntPtr hFile = new IntPtr(-1);
            private readonly IntPtr pgKnownSubject = IntPtr.Zero;

            public WINTRUST_FILE_INFO(string filePath)
            {
                this.pcwszFilePath = filePath;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private sealed class WINTRUST_DATA
        {
            private readonly uint cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>();
            private readonly IntPtr pPolicyCallbackData = IntPtr.Zero;
            private readonly IntPtr pSIPClientData = IntPtr.Zero;
            private readonly uint dwUIChoice = 2; // WTD_UI_NONE
            private readonly uint fdwRevocationChecks = 0; // WTD_REVOKE_NONE
            private readonly uint dwUnionChoice = 1; // WTD_CHOICE_FILE
            private readonly IntPtr pFile;
            private readonly uint dwStateAction = 0; // WTD_STATEACTION_IGNORE
            private readonly IntPtr hWVTStateData = IntPtr.Zero;
            private readonly string pwszURLReference = null;
            private readonly uint dwProvFlags;
            private readonly uint dwUIContext = 0; // WTD_UICONTEXT_EXECUTE
            private readonly IntPtr pSignatureSettings = IntPtr.Zero;

            public WINTRUST_DATA(IntPtr pFile, uint dwProvFlags)
            {
                this.pFile = pFile;
                this.dwProvFlags = dwProvFlags;
            }
        }

        /// <summary>
        /// Verify a file's Authenticode Signature.
        /// No additional checks are performed.
        /// </summary>
        /// <param name="file">File to check.</param>
        /// <returns>True if the authenticode signature is valid, otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool Verify(FileInfo file) =>
            Verify(file.FullName);

        /// <summary>
        /// Verify a file's Authenticode Signature.
        /// No additional checks are performed.
        /// </summary>
        /// <param name="filePath">Path to the file to check.</param>
        /// <returns>True if the authenticode signature is valid, otherwise False.</returns>
        public static bool Verify(string filePath)
        {
            var fileInfo = new WINTRUST_FILE_INFO(filePath);
            var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            try
            {
                Marshal.StructureToPtr(fileInfo, pFile, false);
                try
                {
                    var trustData = new WINTRUST_DATA(pFile, WTD_HASH_ONLY_FLAG);
                    uint hResult = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, trustData);
                    return hResult == 0x0;
                }
                finally
                {
                    Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pFile);
            }
        }

        /// <summary>
        /// Verifies a certificate's validity via basic validation, and then if valid also performs
        /// Authenticode Signature verfication.
        /// </summary>
        /// <param name="file">File to check.</param>
        /// <returns>True if the certificate passes basic validation, and the Authenticode Signature is also valid. Otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool VerifyFull(FileInfo file)
            => VerifyFull(file.FullName);

        /// <summary>
        /// Verifies a certificate's validity via basic validation, and then if valid also performs
        /// Authenticode Signature verfication.
        /// </summary>
        /// <param name="filePath">Path to the file to check.</param>
        /// <returns>True if the certificate passes basic validation, and the Authenticode Signature is also valid. Otherwise False.</returns>
        public static bool VerifyFull(string filePath)
        {
            using (var cert = LoadAuthenticodeCertificate(filePath))
            {
                if (!cert.Verify())
                    return false;
            }
            return Verify(filePath);
        }

        /// <summary>
        /// Verifies a certificate's validity via user-defined callback, and then if valid also performs
        /// Authenticode Signature verfication.
        /// </summary>
        /// <param name="file">File to check.</param>
        /// <param name="isCertValid">Certificate/Chain validation callback.</param>
        /// <returns>True if both the certificate/chain is valid, and the Authenticode Signature is valid. Otherwise False.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool VerifyFull(FileInfo file, Func<X509Certificate2, X509Chain, bool> isCertValid)
            => VerifyFull(file.FullName, isCertValid);

        /// <summary>
        /// Verifies a certificate's validity via user-defined callback, and then if valid also performs
        /// Authenticode Signature verfication.
        /// </summary>
        /// <param name="filePath">Path to the file to check.</param>
        /// <param name="isCertValid">Certificate/Chain validation callback.</param>
        /// <returns>True if both the certificate/chain is valid, and the Authenticode Signature is valid. Otherwise False.</returns>
        public static bool VerifyFull(string filePath, Func<X509Certificate2, X509Chain, bool> isCertValid)
        {
            using (var cert = LoadAuthenticodeCertificate(filePath))
            using (var chain = new X509Chain())
            {
                if (!isCertValid(cert, chain))
                    return false;
            }
            return Verify(filePath);
        }

        /// <summary>
        /// Load an X509Certificate2 from an Authenticode Signed File.
        /// https://github.com/dotnet/runtime/discussions/108740
        /// </summary>
        /// <param name="path">Path to the file to load the cert info from.</param>
        /// <returns>X509Certificate2</returns>
        /// <exception cref="CryptographicException"></exception>
        private static X509Certificate2 LoadAuthenticodeCertificate(string path)
        {
            if (X509Certificate2.GetCertContentType(path) == X509ContentType.Authenticode)
            {
#pragma warning disable SYSLIB0057
                return new X509Certificate2(path);
#pragma warning restore SYSLIB0057
            }

            throw new CryptographicException("Invalid Authenticode Certificate!");
        }
    }
}