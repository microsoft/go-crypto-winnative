param(
    [ValidateRange(-1, 1)]
    [int]$ExpectedFips = -1
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public sealed class GcmProbeResult {
    public int KeyBits { get; set; }
    public int NonceSize { get; set; }
    public int TagSize { get; set; }
    public string EncryptStatus { get; set; }
    public string DecryptStatus { get; set; }
    public string TamperStatus { get; set; }
    public bool PlaintextMatches { get; set; }
    public bool OutputLengthsMatch { get; set; }
    public string CiphertextHex { get; set; }
    public string TagHex { get; set; }
}

public sealed class GcmProbeReport {
    public bool FipsEnabled { get; set; }
    public uint MinimumTagSize { get; set; }
    public uint MaximumTagSize { get; set; }
    public uint TagSizeIncrement { get; set; }
    public int AuthInfoSize { get; set; }
    public List<GcmProbeResult> Results { get; set; }
}

public static class BCryptGcmProbe {
    [StructLayout(LayoutKind.Sequential)]
    private struct AuthInfo {
        public uint Size;
        public uint Version;
        public IntPtr Nonce;
        public uint NonceSize;
        public IntPtr AuthData;
        public uint AuthDataSize;
        public IntPtr Tag;
        public uint TagSize;
        public IntPtr MacContext;
        public uint MacContextSize;
        public uint AadSize;
        public ulong DataSize;
        public uint Flags;
    }

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr algorithm, string name, string implementation, uint flags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int BCryptSetProperty(IntPtr handle, string property, byte[] input, uint inputSize, uint flags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int BCryptGetProperty(IntPtr handle, string property, byte[] output, uint outputSize, out uint resultSize, uint flags);
    [DllImport("bcrypt.dll", ExactSpelling = true)]
    private static extern int BCryptGetFipsAlgorithmMode(out byte enabled);
    [DllImport("bcrypt.dll", ExactSpelling = true)]
    private static extern int BCryptGenerateSymmetricKey(IntPtr algorithm, out IntPtr key, IntPtr keyObject, uint keyObjectSize, byte[] secret, uint secretSize, uint flags);
    [DllImport("bcrypt.dll", ExactSpelling = true)]
    private static extern int BCryptEncrypt(IntPtr key, byte[] input, uint inputSize, ref AuthInfo info, IntPtr iv, uint ivSize, byte[] output, uint outputSize, out uint resultSize, uint flags);
    [DllImport("bcrypt.dll", ExactSpelling = true)]
    private static extern int BCryptDecrypt(IntPtr key, byte[] input, uint inputSize, ref AuthInfo info, IntPtr iv, uint ivSize, byte[] output, uint outputSize, out uint resultSize, uint flags);
    [DllImport("bcrypt.dll", ExactSpelling = true)]
    private static extern int BCryptDestroyKey(IntPtr key);
    [DllImport("bcrypt.dll", ExactSpelling = true)]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr algorithm, uint flags);

    private static string Status(int status) {
        return "0x" + unchecked((uint)status).ToString("X8");
    }

    private static void Check(string operation, int status) {
        if (status != 0) {
            throw new InvalidOperationException(operation + " failed: " + Status(status));
        }
    }

    private static string Hex(byte[] data) {
        return BitConverter.ToString(data).Replace("-", "").ToLowerInvariant();
    }

    private static AuthInfo NewInfo(IntPtr nonce, int nonceSize, IntPtr tag, int tagSize) {
        return new AuthInfo {
            Size = (uint)Marshal.SizeOf(typeof(AuthInfo)),
            Version = 1,
            Nonce = nonce,
            NonceSize = (uint)nonceSize,
            Tag = tag,
            TagSize = (uint)tagSize
        };
    }

    public static GcmProbeReport Run() {
        byte fips;
        Check("BCryptGetFipsAlgorithmMode", BCryptGetFipsAlgorithmMode(out fips));
        IntPtr algorithm;
        Check("BCryptOpenAlgorithmProvider", BCryptOpenAlgorithmProvider(out algorithm, "AES", "Microsoft Primitive Provider", 0));
        try {
            byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            Check("BCryptSetProperty(ChainingMode)", BCryptSetProperty(algorithm, "ChainingMode", mode, (uint)mode.Length, 0));
            byte[] lengths = new byte[12];
            uint resultSize;
            Check("BCryptGetProperty(AuthTagLength)", BCryptGetProperty(algorithm, "AuthTagLength", lengths, (uint)lengths.Length, out resultSize, 0));
            if (resultSize != lengths.Length) {
                throw new InvalidOperationException("Unexpected AuthTagLength property size: " + resultSize);
            }
            GcmProbeReport report = new GcmProbeReport {
                FipsEnabled = fips != 0,
                MinimumTagSize = BitConverter.ToUInt32(lengths, 0),
                MaximumTagSize = BitConverter.ToUInt32(lengths, 4),
                TagSizeIncrement = BitConverter.ToUInt32(lengths, 8),
                AuthInfoSize = Marshal.SizeOf(typeof(AuthInfo)),
                Results = new List<GcmProbeResult>()
            };
            foreach (int keySize in new int[] {16, 24, 32}) {
                byte[] secret = new byte[keySize];
                IntPtr key;
                Check("BCryptGenerateSymmetricKey", BCryptGenerateSymmetricKey(algorithm, out key, IntPtr.Zero, 0, secret, (uint)secret.Length, 0));
                try {
                    foreach (int nonceSize in new int[] {1, 8, 11, 12, 13, 16, 100}) {
                        foreach (int tagSize in new int[] {12, 13, 14, 15, 16}) {
                            IntPtr nonce = Marshal.AllocHGlobal(nonceSize);
                            try {
                                IntPtr tag = Marshal.AllocHGlobal(tagSize);
                                try {
                                    Marshal.Copy(new byte[nonceSize], 0, nonce, nonceSize);
                                    Marshal.Copy(new byte[tagSize], 0, tag, tagSize);
                                    byte[] plaintext = new byte[16];
                                    byte[] ciphertext = new byte[plaintext.Length];
                                    byte[] decrypted = new byte[plaintext.Length];
                                    AuthInfo info = NewInfo(nonce, nonceSize, tag, tagSize);
                                    uint encryptedSize, decryptedSize;
                                    int enc = BCryptEncrypt(key, plaintext, (uint)plaintext.Length, ref info, IntPtr.Zero, 0, ciphertext, (uint)ciphertext.Length, out encryptedSize, 0);
                                    info = NewInfo(nonce, nonceSize, tag, tagSize);
                                    int dec = BCryptDecrypt(key, ciphertext, (uint)ciphertext.Length, ref info, IntPtr.Zero, 0, decrypted, (uint)decrypted.Length, out decryptedSize, 0);
                                    byte[] tagBytes = new byte[tagSize];
                                    Marshal.Copy(tag, tagBytes, 0, tagSize);
                                    GcmProbeResult row = new GcmProbeResult {
                                        KeyBits = keySize * 8,
                                        NonceSize = nonceSize,
                                        TagSize = tagSize,
                                        EncryptStatus = Status(enc),
                                        DecryptStatus = Status(dec),
                                        PlaintextMatches = enc == 0 && dec == 0 && Array.TrueForAll(decrypted, value => value == 0),
                                        OutputLengthsMatch = enc == 0 && dec == 0 && encryptedSize == plaintext.Length && decryptedSize == plaintext.Length,
                                        CiphertextHex = enc == 0 ? Hex(ciphertext) : null,
                                        TagHex = enc == 0 ? Hex(tagBytes) : null
                                    };
                                    if (enc == 0) {
                                        tagBytes[tagSize - 1] ^= 1;
                                        Marshal.Copy(tagBytes, 0, tag, tagSize);
                                        info = NewInfo(nonce, nonceSize, tag, tagSize);
                                        row.TamperStatus = Status(BCryptDecrypt(key, ciphertext, (uint)ciphertext.Length, ref info, IntPtr.Zero, 0, decrypted, (uint)decrypted.Length, out decryptedSize, 0));
                                    }
                                    report.Results.Add(row);
                                } finally {
                                    Marshal.FreeHGlobal(tag);
                                }
                            } finally {
                                Marshal.FreeHGlobal(nonce);
                            }
                        }
                    }
                } finally {
                    Check("BCryptDestroyKey", BCryptDestroyKey(key));
                }
            }
            return report;
        } finally {
            Check("BCryptCloseAlgorithmProvider", BCryptCloseAlgorithmProvider(algorithm, 0));
        }
    }
}
'@

$report = [BCryptGcmProbe]::Run()
$os = Get-CimInstance Win32_OperatingSystem
$metadata = [ordered]@{
    OS = $os.Caption
    Version = $os.Version
    Build = $os.BuildNumber
    Architecture = $os.OSArchitecture
    Provider = 'Microsoft Primitive Provider'
    BcryptPrimitivesVersion = (Get-Item -LiteralPath "$env:WINDIR\System32\bcryptPrimitives.dll").VersionInfo.FileVersion
    FipsEnabled = $report.FipsEnabled
    MinimumTagSize = $report.MinimumTagSize
    MaximumTagSize = $report.MaximumTagSize
    TagSizeIncrement = $report.TagSizeIncrement
    AuthInfoSize = $report.AuthInfoSize
}
Write-Output ('PROBE_META=' + (ConvertTo-Json -InputObject $metadata -Compress))
foreach ($row in $report.Results) {
    Write-Output ('PROBE_RESULT=' + (ConvertTo-Json -InputObject $row -Compress))
}

if ($ExpectedFips -ne -1 -and $report.FipsEnabled -ne ($ExpectedFips -eq 1)) {
    throw "FIPS mode mismatch: expected $ExpectedFips, got $($report.FipsEnabled)"
}
if ($report.Results.Count -ne 105) {
    throw "Expected 105 parameter combinations, got $($report.Results.Count)"
}
foreach ($row in $report.Results) {
    if ($row.EncryptStatus -eq '0x00000000') {
        if (-not $row.PlaintextMatches -or -not $row.OutputLengthsMatch -or $row.TamperStatus -ne '0xC000A002') {
            throw ('Round-trip or authentication check failed: ' + (ConvertTo-Json -InputObject $row -Compress))
        }
        if ($row.KeyBits -eq 128 -and $row.NonceSize -eq 12) {
            $expectedTag = 'ab6e47d42cec13bdf53a67b21257bddf'.Substring(0, $row.TagSize * 2)
            if ($row.CiphertextHex -ne '0388dace60b6a392f328c2b971b2fe78' -or $row.TagHex -ne $expectedTag) {
                throw 'AES-128 GCM known-answer check failed'
            }
        }
    } elseif ($row.NonceSize -eq 12 -or $row.EncryptStatus -ne '0xC000000D' -or $row.DecryptStatus -ne '0xC000000D') {
        throw ('Unexpected native failure: ' + (ConvertTo-Json -InputObject $row -Compress))
    }
}
Write-Output 'PROBE_VALIDATION=PASS'
