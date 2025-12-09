// ============================================================================
// LG TV VOLUME CONTROLLER FOR CRESTRON
// ============================================================================
//
// WHAT IS THIS MONSTROSITY?
// -------------------------
// This is a C# library that implements LG's proprietary "encryption" protocol
// for controlling LG TVs over the network. If you're reading this, I'm sorry.
// Either you're me, maintaining my own code at 2 AM, or you're some poor soul
// who inherited this project. Either way, grab a drink.
//
// WHY DOES THIS EXIST?
// --------------------
// LG, in their infinite wisdom, decided that sending plaintext commands to a TV
// was too easy. Instead, they implemented AES-128 encryption with PBKDF2 key
// derivation. The "keycode" is that 8-character code you have to fish out of
// your TV's hidden service menu (seriously, who designs this stuff?).
//
// The protocol works as follows:
// 1. Derive a 128-bit AES key from the TV's keycode using PBKDF2-SHA256
//    - 16,384 iterations (because why not make initialization slow?)
//    - A hardcoded salt that LG embedded in their JavaScript (see LgCryptoEngine)
// 2. Generate a random 16-byte IV for each message
// 3. Encrypt the IV using AES-ECB (yes, ECB for the IV, CBC for the message)
// 4. Encrypt the message using AES-CBC with the unencrypted IV
// 5. Concatenate encrypted_iv + encrypted_message and send
//
// Decryption is the reverse: split off first 16 bytes, ECB decrypt to get IV,
// then CBC decrypt the rest.
//
// WHY RIJNDAELMANAGED INSTEAD OF AES CLASS?
// -----------------------------------------
// We're stuck on .NET Framework 3.5 (or whatever ancient version Crestron's
// SimplSharp is using). The modern Aes class either doesn't exist or behaves
// differently. RijndaelManaged is the old-school way of doing AES and it works.
// Don't try to "modernize" this unless you're also willing to test it on actual
// Crestron hardware, which I assume you're not.
//
// WHY IS THE SALT HARDCODED?
// --------------------------
// Because LG hardcoded it in their JavaScript client. That's right - the
// "security" of this entire protocol relies on a fixed, publicly-known salt.
// The only secret is the keycode from your TV. Security theater at its finest.
// I found the salt by decompiling LG's webOS JavaScript code. You're welcome.
//
// PROTOCOL QUIRKS:
// ----------------
// - Messages must end with "\r" (carriage return) - LG's message terminator
// - Commands are formatted as "KEY_ACTION keyname" (e.g., "KEY_ACTION volumeup")
// - The TV will just... not respond if your encryption is wrong. No error, nothing.
//   It's like yelling into the void, except the void costs $2000.
//
// SIMPL+ INTEGRATION NOTES:
// -------------------------
// SIMPL+ strings are NOT Unicode - they're raw byte arrays masquerading as strings.
// We use ISO-8859-1 (Latin-1) encoding for all SIMPL+ string conversions because
// it maps bytes 0x00-0xFF directly to characters, preserving binary data.
// If you try to use UTF-8, your encrypted data will be corrupted and nothing
// will work. Ask me how I know. (I spent 3 hours debugging this.)
//
// WAKE-ON-LAN:
// ------------
// LG TVs support WoL for power-on. We send a magic packet to the broadcast
// address with the TV's MAC. Then we wait 3 seconds (arbitrary but seems to work)
// before trying to connect. If your TV doesn't wake up, check that:
// 1. WoL is enabled in the TV's settings (of course it's buried somewhere)
// 2. The MAC address is correct (duh)
// 3. Your network allows broadcast packets (corporate networks often don't)
//
// THINGS THAT WILL BREAK:
// -----------------------
// - Changing the salt (obviously)
// - Using wrong keycode (TV just ignores you)
// - Sending commands too fast (no flow control, TV might choke)
// - Expecting this to work with non-LG TVs (it won't)
// - Expecting consistent behavior across LG TV models (it varies, of course)
//
// AUTHOR'S NOTE:
// --------------
// If LG ever changes their protocol, this code becomes a beautiful paperweight.
// Reverse engineering this was "fun" and by "fun" I mean "I now have trust issues
// with all consumer electronics."
//
// ============================================================================

using System;
using System.Text;
using Crestron.SimplSharp;
using Crestron.SimplSharp.Cryptography;

namespace LgTvController
{
    // ========================================================================
    // SIMPL+ DELEGATE DEFINITIONS
    // ========================================================================
    // These delegates are the bridge between our civilized C# code and the
    // prehistoric world of SIMPL+. SIMPL+ doesn't understand C# strings,
    // so we have to use SimplSharpString. Yes, it's annoying.
    // ========================================================================

    /// <summary>
    /// Delegate for sending string data back to SIMPL+.
    /// SIMPL+ passes SimplSharpString, not C# string, because of course it does.
    /// </summary>
    /// <param name="data">The string data wrapped in SimplSharpString</param>
    public delegate void SimplPlusStringOutputDelegate(SimplSharpString data);

    /// <summary>
    /// Delegate for digital (boolean) outputs to SIMPL+.
    /// SIMPL+ uses ushort (0/1) for booleans because actual booleans were
    /// apparently too advanced for the 1990s when SIMPL+ was designed.
    /// </summary>
    /// <param name="val">0 for false, 1 for true. That's it. That's the boolean.</param>
    public delegate void SimplPlusDigitalOutputDelegate(ushort val);

    // ========================================================================
    // LG CRYPTO ENGINE
    // ========================================================================
    // This class handles all the encryption/decryption for LG's protocol.
    // It's isolated from the controller logic because separation of concerns
    // is a thing, and also because I wanted to be able to test crypto
    // independently of all the Crestron nonsense.
    // ========================================================================
    public class LgCryptoEngine : IDisposable
    {
        // ====================================================================
        // LG'S "SECRET" SALT
        // ====================================================================
        // This is the fixed salt that LG uses for PBKDF2 key derivation.
        // They call it "DefaultSettings.encryptionKeySalt" in their code.
        // I call it "the reason this protocol isn't actually secure."
        //
        // Found by decompiling LG's webOS JavaScript client. The fact that
        // this is public knowledge and they still use it tells you everything
        // you need to know about LG's security philosophy.
        //
        // Bytes: 63 61 b8 0e 9b dc a6 63 8d 07 20 f2 cc 56 8f b9
        //
        // Static readonly because:
        // 1. It never changes (LG's "security" decision, not mine)
        // 2. We don't want multiple copies in memory
        // 3. readonly prevents accidental modification
        // ====================================================================
        private static readonly byte[] Salt = new byte[]
        {
            0x63, 0x61, 0xb8, 0x0e, 0x9b, 0xdc, 0xa6, 0x63,
            0x8d, 0x07, 0x20, 0xf2, 0xcc, 0x56, 0x8f, 0xb9
        };

        // ====================================================================
        // BINARY-SAFE STRING ENCODING
        // ====================================================================
        // ISO-8859-1 (Latin-1) encoding for SIMPL+ interoperability.
        //
        // WHY NOT UTF-8?
        // UTF-8 is variable-length and will mangle bytes > 0x7F. When you
        // have encrypted data (which is random bytes 0x00-0xFF), UTF-8
        // will interpret some byte sequences as multi-byte characters and
        // corrupt your data. I learned this the hard way.
        //
        // WHY ISO-8859-1?
        // It's a 1:1 mapping between bytes and characters. Byte 0x00 = char 0,
        // byte 0xFF = char 255. No surprises, no corruption, no 3-hour
        // debugging sessions.
        //
        // This is used when:
        // 1. Receiving encrypted data from SIMPL+ (string → bytes)
        // 2. Sending encrypted data to SIMPL+ (bytes → string)
        // ====================================================================
        private static readonly Encoding BinaryEncoding = Encoding.GetEncoding(28591);

        // ====================================================================
        // SHARED RANDOM NUMBER GENERATOR
        // ====================================================================
        // We reuse a single RNG instance across all LgCryptoEngine instances
        // for two reasons:
        //
        // 1. PERFORMANCE: Creating RandomNumberGenerator instances is expensive,
        //    especially on Crestron's anemic processors. Each instance needs
        //    to be seeded from system entropy, which takes time.
        //
        // 2. MEMORY: Crestron processors don't have a lot of RAM. No need to
        //    allocate a new RNG for every crypto operation.
        //
        // The lock object ensures thread-safety because Crestron can (and will)
        // call your code from multiple threads without warning.
        // ====================================================================
        private static readonly RandomNumberGenerator SharedRng = RandomNumberGenerator.Create();
        private static readonly object RngLock = new object();

        // ====================================================================
        // INSTANCE FIELDS
        // ====================================================================

        /// <summary>
        /// The derived AES-128 encryption key.
        /// Generated from the TV's keycode using PBKDF2-SHA256.
        /// This is the only actual secret in the entire protocol.
        /// </summary>
        private readonly byte[] keyBytes;

        /// <summary>
        /// Tracks whether this instance has been disposed.
        /// Attempting to use a disposed instance will throw ObjectDisposedException.
        /// </summary>
        private bool disposed = false;

        /// <summary>
        /// Optional callback for diagnostic logging.
        /// Set this if you want to see what the crypto engine is doing.
        /// Useful for debugging, annoying in production.
        /// </summary>
        public Action<string> LogCallback { get; set; }

        // ====================================================================
        // CONSTRUCTOR
        // ====================================================================
        /// <summary>
        /// Creates a new LgCryptoEngine with the specified keycode.
        /// </summary>
        /// <param name="keycode">
        /// The 8-character keycode from your LG TV's service menu.
        /// To get this:
        /// 1. Go to TV settings → General → About This TV
        /// 2. Mash the "1" button on your remote 7 times (I'm not kidding)
        /// 3. Find "Key Code" in the secret menu that appears
        /// 4. Question your life choices
        /// </param>
        /// <remarks>
        /// Key derivation uses PBKDF2-SHA256 with 16,384 iterations.
        /// This takes a noticeable amount of time on Crestron processors,
        /// so don't call this constructor in a loop.
        /// 
        /// The PBKDF2SHA256 class in SimplSharp doesn't implement IDisposable,
        /// so we can't wrap it in a using statement. This is fine because it
        /// doesn't hold any unmanaged resources (I checked), but it offends
        /// my sensibilities nonetheless.
        /// </remarks>
        public LgCryptoEngine(string keycode)
        {
            // Create PBKDF2 instance for key derivation
            // Parameters:
            // - keycode as ASCII bytes (if you use emoji in your keycode, 
            //   you deserve whatever happens to you)
            // - LG's hardcoded salt (see Salt field above)
            // - 16,384 iterations (LG's choice, not mine)
            PBKDF2SHA256 pb = new PBKDF2SHA256(
                Encoding.ASCII.GetBytes(keycode),
                Salt,
                16384
            );

            // Extract 16 bytes (128 bits) for AES-128 key
            keyBytes = pb.GetBytes(16);

            // Note: pb doesn't implement IDisposable in SimplSharp.
            // If it did, we'd dispose it here. But it doesn't. So we don't.
            // Welcome to Crestron development.
        }

        // ====================================================================
        // LOGGING
        // ====================================================================
        /// <summary>
        /// Sends a message to the log callback if one is registered.
        /// Wrapped in try/catch because we don't want logging failures
        /// to break the actual crypto operations.
        /// </summary>
        /// <param name="message">The message to log</param>
        private void Log(string message)
        {
            if (LogCallback != null)
            {
                try
                {
                    LogCallback(message);
                }
                catch
                {
                    // Logging failed. Oh well. The show must go on.
                    // This happens more often than you'd think when
                    // SIMPL+ delegates are involved.
                }
            }
        }

        // ====================================================================
        // IV GENERATION
        // ====================================================================
        /// <summary>
        /// Generates a cryptographically random 16-byte initialization vector.
        /// </summary>
        /// <returns>A 16-byte array of random data for use as an AES IV</returns>
        /// <remarks>
        /// Uses the shared RNG instance for efficiency. The lock ensures
        /// thread-safety because Crestron's threading model is... creative.
        /// 
        /// A new IV is generated for each message, which is the correct way
        /// to use AES-CBC. At least LG got this part right.
        /// </remarks>
        private byte[] GenerateRandomIv()
        {
            byte[] iv = new byte[16];

            // Thread-safe access to shared RNG
            // Without this lock, concurrent calls could corrupt the RNG state
            lock (RngLock)
            {
                SharedRng.GetBytes(iv);
            }

            Log("Generated random IV: " + BitConverter.ToString(iv).Replace("-", " "));

            return iv;
        }

        // ====================================================================
        // PKCS7 PADDING
        // ====================================================================
        /// <summary>
        /// Applies PKCS7 padding to a message to make its length a multiple
        /// of the AES block size (16 bytes).
        /// </summary>
        /// <param name="message">The unpadded message bytes</param>
        /// <returns>The padded message bytes</returns>
        /// <remarks>
        /// PKCS7 padding works by appending N bytes, each with value N,
        /// where N is the number of bytes needed to reach a block boundary.
        /// 
        /// Examples:
        /// - 15-byte message → add 1 byte with value 0x01
        /// - 14-byte message → add 2 bytes with value 0x02
        /// - 16-byte message → add 16 bytes with value 0x10 (full block of padding)
        /// 
        /// The last case might seem wasteful, but it's necessary to make
        /// unpadding unambiguous. If the original message happened to end
        /// with valid-looking padding bytes, we need to distinguish that
        /// from actual padding.
        /// </remarks>
        private byte[] PadMessage(byte[] message)
        {
            const int blockSize = 16; // AES block size in bytes
            int remainder = message.Length % blockSize;

            // If message is already block-aligned, add a full block of padding
            // Otherwise, add just enough to reach alignment
            int padLength = (remainder == 0) ? blockSize : (blockSize - remainder);

            Log("Padding message: original=" + message.Length + " bytes, padding=" + padLength + " bytes");

            byte[] padded = new byte[message.Length + padLength];
            Buffer.BlockCopy(message, 0, padded, 0, message.Length);

            // Fill padding bytes with the pad length value (PKCS7 standard)
            for (int i = message.Length; i < padded.Length; i++)
            {
                padded[i] = (byte)padLength;
            }

            return padded;
        }

        /// <summary>
        /// Removes PKCS7 padding from a decrypted message.
        /// </summary>
        /// <param name="message">The padded message bytes</param>
        /// <returns>The unpadded message bytes</returns>
        /// <remarks>
        /// This method includes padding validation to detect corruption or
        /// decryption failures. The validation is done in constant-time to
        /// prevent timing attacks (not that anyone is attacking a TV controller,
        /// but good habits die hard).
        /// 
        /// If validation fails, we return the raw data rather than throwing.
        /// This is a deliberate choice - sometimes LG sends weird responses,
        /// and we'd rather see the garbage than crash.
        /// </remarks>
        private byte[] UnpadMessage(byte[] message)
        {
            if (message == null || message.Length == 0)
            {
                Log("UnpadMessage: empty or null input, returning as-is");
                return message;
            }

            // The last byte tells us the padding length
            byte lastByte = message[message.Length - 1];
            int padLength = (int)lastByte;

            Log("UnpadMessage: message length=" + message.Length + ", claimed pad length=" + padLength);

            // Sanity check: pad length must be 1-16 and not exceed message length
            if (padLength < 1 || padLength > 16 || padLength > message.Length)
            {
                Log("PKCS7 unpad: invalid pad length " + padLength + ", returning raw data");
                Log("  (This usually means decryption failed - wrong keycode?)");
                return message;
            }

            // Constant-time padding validation
            // We check ALL padding bytes regardless of whether we find a mismatch.
            // This prevents timing attacks where an attacker could determine the
            // pad length by measuring response time.
            //
            // In practice, no one is timing-attacking a TV controller, but this
            // is the correct way to do it and it costs us nothing.
            int valid = 1;
            for (int i = 0; i < padLength; i++)
            {
                // If byte doesn't match expected padding value, set valid to 0
                // The bitwise AND ensures we don't short-circuit
                valid &= (message[message.Length - 1 - i] == lastByte) ? 1 : 0;
            }

            if (valid == 0)
            {
                Log("PKCS7 unpad: padding bytes mismatch, possible decryption failure or corrupted data");
                Log("  (Expected " + padLength + " bytes of value 0x" + padLength.ToString("X2") + ")");
                return message;
            }

            // Padding is valid - strip it off
            byte[] unpadded = new byte[message.Length - padLength];
            Buffer.BlockCopy(message, 0, unpadded, 0, unpadded.Length);

            Log("UnpadMessage: successfully removed " + padLength + " bytes of padding");

            return unpadded;
        }

        // ====================================================================
        // AES INSTANCE CREATION
        // ====================================================================
        /// <summary>
        /// Creates a configured RijndaelManaged instance for AES operations.
        /// </summary>
        /// <param name="mode">The cipher mode (ECB for IV encryption, CBC for message)</param>
        /// <returns>A configured RijndaelManaged instance. Caller must dispose.</returns>
        /// <remarks>
        /// WHY RIJNDAELMANAGED?
        /// --------------------
        /// We're using RijndaelManaged instead of the Aes class because:
        /// 1. SimplSharp is based on an ancient .NET version where Aes might
        ///    not exist or behaves differently
        /// 2. RijndaelManaged is the underlying implementation of AES anyway
        /// 3. It works, and when something works on Crestron, you don't touch it
        /// 
        /// WHY PADDING = NONE?
        /// -------------------
        /// We handle PKCS7 padding manually (see PadMessage/UnpadMessage).
        /// This gives us more control and allows us to handle padding errors
        /// gracefully instead of getting cryptic exceptions.
        /// 
        /// Configuration:
        /// - KeySize: 128 bits (AES-128)
        /// - BlockSize: 128 bits (standard AES block size)
        /// - Padding: None (we do it ourselves)
        /// - Key: The derived key from constructor
        /// </remarks>
        private RijndaelManaged CreateAes(CipherMode mode)
        {
            Log("Creating AES instance: mode=" + mode);

            RijndaelManaged aes = new RijndaelManaged();
            aes.Mode = mode;
            aes.Padding = PaddingMode.None; // We handle padding manually
            aes.KeySize = 128;              // AES-128
            aes.BlockSize = 128;            // Standard AES block size
            aes.Key = keyBytes;

            return aes;
        }

        /// <summary>
        /// Creates a configured RijndaelManaged instance with an IV for CBC mode.
        /// </summary>
        /// <param name="mode">The cipher mode (should be CBC when using this overload)</param>
        /// <param name="iv">The initialization vector (16 bytes)</param>
        /// <returns>A configured RijndaelManaged instance. Caller must dispose.</returns>
        private RijndaelManaged CreateAes(CipherMode mode, byte[] iv)
        {
            RijndaelManaged aes = CreateAes(mode);
            aes.IV = iv;

            Log("Set IV: " + BitConverter.ToString(iv).Replace("-", " "));

            return aes;
        }

        /// <summary>
        /// Executes a cryptographic transform and ensures proper resource disposal.
        /// </summary>
        /// <param name="transform">The ICryptoTransform to execute</param>
        /// <param name="input">The input bytes to transform</param>
        /// <returns>The transformed bytes</returns>
        /// <remarks>
        /// This helper method ensures that ICryptoTransform instances are always
        /// disposed, even if an exception occurs. We cast to IDisposable explicitly
        /// because the SimplSharp version of ICryptoTransform might not directly
        /// inherit from IDisposable (I've seen weirder things in this SDK).
        /// </remarks>
        private byte[] ExecuteTransform(ICryptoTransform transform, byte[] input)
        {
            try
            {
                Log("Executing transform: input=" + input.Length + " bytes");
                byte[] result = transform.TransformFinalBlock(input, 0, input.Length);
                Log("Transform complete: output=" + result.Length + " bytes");
                return result;
            }
            finally
            {
                // Ensure transform is disposed even if an exception occurs
                IDisposable disposable = transform as IDisposable;
                if (disposable != null)
                {
                    disposable.Dispose();
                }
            }
        }

        // ====================================================================
        // ENCRYPTION
        // ====================================================================
        /// <summary>
        /// Encrypts a plaintext message using LG's protocol.
        /// </summary>
        /// <param name="plain">The plaintext message to encrypt</param>
        /// <returns>The encrypted bytes: [ECB(IV)][CBC(padded_message)]</returns>
        /// <remarks>
        /// LG'S ENCRYPTION PROTOCOL:
        /// -------------------------
        /// 1. Append "\r" to the message (LG's message terminator)
        /// 2. UTF-8 encode the message
        /// 3. Apply PKCS7 padding
        /// 4. Generate random 16-byte IV
        /// 5. Encrypt IV using AES-ECB (yes, really)
        /// 6. Encrypt padded message using AES-CBC with the unencrypted IV
        /// 7. Concatenate: encrypted_iv (16 bytes) + encrypted_message (N bytes)
        /// 
        /// The ECB-encrypted IV is... a choice. Normally you'd just send the IV
        /// in plaintext since IVs don't need to be secret, just unique. But LG
        /// decided to encrypt it anyway. Sure, why not.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">If the engine has been disposed</exception>
        public byte[] Encode(string plain)
        {
            if (disposed)
            {
                throw new ObjectDisposedException("LgCryptoEngine");
            }

            Log("=== ENCODE START ===");
            Log("Original message: \"" + plain + "\"");

            // Step 1: Append LG's message terminator
            // Every message must end with \r or the TV ignores it
            plain = plain + "\r";
            Log("After adding terminator: \"" + plain.Replace("\r", "\\r") + "\"");

            // Step 2: UTF-8 encode
            byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
            Log("UTF-8 encoded: " + plainBytes.Length + " bytes");

            // Step 3: Apply PKCS7 padding
            byte[] paddedBytes = PadMessage(plainBytes);
            Log("After padding: " + paddedBytes.Length + " bytes");

            // Step 4: Generate random IV
            byte[] iv = GenerateRandomIv();

            byte[] encryptedIv;
            byte[] encryptedMsg;

            // Step 5: ECB encrypt the IV
            // This produces a single 16-byte block
            // ECB is normally insecure for multi-block data, but for a single
            // random block it's fine (there are no patterns to exploit)
            Log("Encrypting IV with ECB...");
            using (RijndaelManaged aes = CreateAes(CipherMode.ECB))
            {
                encryptedIv = ExecuteTransform(aes.CreateEncryptor(), iv);
            }
            Log("Encrypted IV: " + BitConverter.ToString(encryptedIv).Replace("-", " "));

            // Step 6: CBC encrypt the message using the unencrypted IV
            Log("Encrypting message with CBC...");
            using (RijndaelManaged aes = CreateAes(CipherMode.CBC, iv))
            {
                encryptedMsg = ExecuteTransform(aes.CreateEncryptor(), paddedBytes);
            }
            Log("Encrypted message: " + encryptedMsg.Length + " bytes");

            // Step 7: Concatenate encrypted_iv + encrypted_message
            byte[] output = new byte[encryptedIv.Length + encryptedMsg.Length];
            Buffer.BlockCopy(encryptedIv, 0, output, 0, encryptedIv.Length);
            Buffer.BlockCopy(encryptedMsg, 0, output, encryptedIv.Length, encryptedMsg.Length);

            Log("Total output: " + output.Length + " bytes");
            Log("=== ENCODE COMPLETE ===");

            return output;
        }

        // ====================================================================
        // DECRYPTION
        // ====================================================================
        /// <summary>
        /// Decrypts an encrypted message from an LG TV.
        /// </summary>
        /// <param name="cipher">The encrypted bytes received from the TV</param>
        /// <returns>The decrypted plaintext message</returns>
        /// <remarks>
        /// LG'S DECRYPTION PROTOCOL:
        /// -------------------------
        /// This is the reverse of Encode():
        /// 1. Split cipher into encrypted_iv (first 16 bytes) and encrypted_message (rest)
        /// 2. ECB decrypt the IV
        /// 3. CBC decrypt the message using the decrypted IV
        /// 4. Remove PKCS7 padding
        /// 5. UTF-8 decode
        /// 6. Strip message terminators (\r, \n, \0)
        /// 
        /// If decryption fails (wrong keycode, corrupted data, etc.), you'll either
        /// get garbage or an empty string. LG doesn't believe in error messages.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">If the engine has been disposed</exception>
        public string Decode(byte[] cipher)
        {
            if (disposed)
            {
                throw new ObjectDisposedException("LgCryptoEngine");
            }

            Log("=== DECODE START ===");
            Log("Input cipher: " + (cipher == null ? 0 : cipher.Length) + " bytes");

            // Sanity check: minimum size is 16 bytes (just the IV)
            if (cipher == null || cipher.Length < 16)
            {
                Log("Input too short (< 16 bytes), returning empty string");
                return "";
            }

            // Step 1: Split off the encrypted IV (first 16 bytes)
            byte[] encryptedIv = new byte[16];
            Buffer.BlockCopy(cipher, 0, encryptedIv, 0, 16);
            Log("Encrypted IV: " + BitConverter.ToString(encryptedIv).Replace("-", " "));

            // Step 1b: Extract the encrypted message (everything after first 16 bytes)
            int msgLen = cipher.Length - 16;
            byte[] encryptedMsg = new byte[msgLen];
            Buffer.BlockCopy(cipher, 16, encryptedMsg, 0, msgLen);
            Log("Encrypted message: " + msgLen + " bytes");

            byte[] iv;
            byte[] decrypted;

            // Step 2: ECB decrypt the IV
            Log("Decrypting IV with ECB...");
            using (RijndaelManaged aes = CreateAes(CipherMode.ECB))
            {
                iv = ExecuteTransform(aes.CreateDecryptor(), encryptedIv);
            }
            Log("Decrypted IV: " + BitConverter.ToString(iv).Replace("-", " "));

            // Step 3: CBC decrypt the message
            Log("Decrypting message with CBC...");
            using (RijndaelManaged aes = CreateAes(CipherMode.CBC, iv))
            {
                decrypted = ExecuteTransform(aes.CreateDecryptor(), encryptedMsg);
            }
            Log("Decrypted (with padding): " + decrypted.Length + " bytes");

            // Step 4: Remove PKCS7 padding
            byte[] unpadded = UnpadMessage(decrypted);
            Log("After unpadding: " + unpadded.Length + " bytes");

            // Step 5: UTF-8 decode
            string raw = Encoding.UTF8.GetString(unpadded, 0, unpadded.Length);
            Log("UTF-8 decoded: \"" + raw.Replace("\r", "\\r").Replace("\n", "\\n") + "\"");

            // Step 6: Strip message terminators
            // LG uses \r as the terminator, but sometimes there's extra junk
            raw = raw.TrimEnd('\0', '\r', '\n');
            Log("After trimming: \"" + raw + "\"");

            Log("=== DECODE COMPLETE ===");

            return raw;
        }

        // ====================================================================
        // SIMPL+ STRING CONVERSION UTILITIES
        // ====================================================================
        // These methods convert between C# byte arrays and SIMPL+ "strings".
        // SIMPL+ strings are actually byte arrays, not Unicode text. Using
        // ISO-8859-1 encoding gives us a 1:1 mapping between bytes and characters.
        // ====================================================================

        /// <summary>
        /// Converts a byte array to a SIMPL+ compatible string using ISO-8859-1 encoding.
        /// </summary>
        /// <param name="data">The byte array to convert</param>
        /// <returns>A string where each character corresponds to one byte</returns>
        /// <remarks>
        /// Use this when sending encrypted data to SIMPL+.
        /// ISO-8859-1 ensures that byte 0x00 becomes character 0, byte 0xFF becomes
        /// character 255, etc. No surprises, no data corruption.
        /// </remarks>
        public static string BytesToSimplString(byte[] data)
        {
            if (data == null)
                return string.Empty;

            return BinaryEncoding.GetString(data, 0, data.Length);
        }

        /// <summary>
        /// Converts a SIMPL+ string back to a byte array using ISO-8859-1 encoding.
        /// </summary>
        /// <param name="data">The SIMPL+ string to convert</param>
        /// <returns>A byte array where each byte corresponds to one character</returns>
        /// <remarks>
        /// Use this when receiving encrypted data from SIMPL+.
        /// </remarks>
        public static byte[] SimplStringToBytes(string data)
        {
            if (data == null)
                return new byte[0]; // Array.Empty<byte>() doesn't exist in old .NET

            return BinaryEncoding.GetBytes(data);
        }

        // ====================================================================
        // IDISPOSABLE IMPLEMENTATION
        // ====================================================================
        // Proper cleanup of sensitive key material. We zero out the key bytes
        // when disposed to minimize the window where the key exists in memory.
        // This isn't bulletproof (the GC might have already moved the array),
        // but it's better than nothing.
        // ====================================================================

        /// <summary>
        /// Disposes the crypto engine and clears sensitive key material from memory.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Protected disposal implementation.
        /// </summary>
        /// <param name="disposing">True if called from Dispose(), false if from finalizer</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    // Clear sensitive key material
                    // This isn't perfect (CLR might have made copies), but it's
                    // better than leaving the key sitting in memory indefinitely
                    if (keyBytes != null)
                    {
                        Array.Clear(keyBytes, 0, keyBytes.Length);
                    }
                }
                disposed = true;
            }
        }

        /// <summary>
        /// Destructor - ensures cleanup even if Dispose() wasn't called.
        /// </summary>
        ~LgCryptoEngine()
        {
            Dispose(false);
        }
    }

    // ========================================================================
    // LG TV VOLUME CONTROLLER
    // ========================================================================
    // This is the main class that SIMPL+ programs interact with.
    // It wraps the crypto engine and provides high-level commands like
    // VolumeUp(), VolumeDown(), PowerOn(), etc.
    //
    // The workflow is:
    // 1. SIMPL+ creates an instance and sets Host, MacAddress, KeyCode
    // 2. SIMPL+ calls Initialize() to set up the crypto engine
    // 3. SIMPL+ manages the TCP connection separately (using a TCP/IP client)
    // 4. When SIMPL+ receives data from TCP, it calls ProcessRx()
    // 5. When this class needs to send data, it calls TxOutput delegate
    // 6. SIMPL+ sends the data out the TCP socket
    //
    // Yes, this is convoluted. Welcome to Crestron development.
    // ========================================================================
    public class LgTvVolumeController : IDisposable
    {
        // ====================================================================
        // SIMPL+ CONFIGURATION PARAMETERS
        // ====================================================================
        // These are set by SIMPL+ before calling Initialize()
        // ====================================================================

        /// <summary>
        /// The IP address or hostname of the LG TV.
        /// Set this from SIMPL+ before calling Initialize().
        /// Example: "192.168.1.100"
        /// </summary>
        public string Host { get; set; }

        /// <summary>
        /// The MAC address of the LG TV for Wake-on-LAN.
        /// Format: "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF"
        /// Set this from SIMPL+ before calling Initialize().
        /// </summary>
        public string MacAddress { get; set; }

        /// <summary>
        /// The 8-character encryption keycode from the TV's service menu.
        /// This is the only "secret" in LG's protocol.
        /// Set this from SIMPL+ before calling Initialize().
        /// 
        /// HOW TO FIND YOUR KEYCODE:
        /// 1. Navigate to Settings → General → About This TV
        /// 2. Press the "1" button on your remote 7 times
        /// 3. A secret menu appears (no, really)
        /// 4. Find "Key Code" - it's an 8-character alphanumeric string
        /// 5. Set this property to that value
        /// </summary>
        public string KeyCode { get; set; }

        // ====================================================================
        // SIMPL+ OUTPUT DELEGATES (STRINGS)
        // ====================================================================
        // These delegates send data back to SIMPL+.
        // Set them from SIMPL+ after creating the instance.
        // ====================================================================

        /// <summary>
        /// Delegate for sending encrypted data to be transmitted over TCP.
        /// SIMPL+ should wire this to the TCP client's TX input.
        /// The string contains raw bytes encoded as ISO-8859-1.
        /// </summary>
        public SimplPlusStringOutputDelegate TxOutput { get; set; }

        /// <summary>
        /// Delegate for sending log messages to SIMPL+ for debugging.
        /// Wire this to a string output for console/debugging.
        /// Messages include timestamps and are newline-terminated.
        /// </summary>
        public SimplPlusStringOutputDelegate LogOutput { get; set; }

        /// <summary>
        /// Delegate for sending decoded response messages from the TV.
        /// These are the actual JSON responses from the TV after decryption.
        /// </summary>
        public SimplPlusStringOutputDelegate DecodedOutput { get; set; }

        // ====================================================================
        // SIMPL+ OUTPUT DELEGATES (DIGITAL)
        // ====================================================================

        /// <summary>
        /// Digital output indicating whether the TV is currently powered on.
        /// 1 = TV is on (or we think it is), 0 = TV is off/standby.
        /// Use this to track power state in SIMPL+.
        /// </summary>
        public SimplPlusDigitalOutputDelegate TvIsOnOutput { get; set; }

        /// <summary>
        /// Digital output that tells SIMPL+ when to connect/disconnect TCP.
        /// 1 = Connect to TV, 0 = Disconnect from TV.
        /// This changes during power on/off sequences.
        /// 
        /// SIMPL+ should wire this to the TCP client's enable/connect input.
        /// We control connection state because:
        /// 1. TV needs time to boot after WoL before accepting connections
        /// 2. TV drops connection when entering standby
        /// 3. Keeping a dead connection wastes resources
        /// </summary>
        public SimplPlusDigitalOutputDelegate ConnectOutput { get; set; }

        // ====================================================================
        // PRIVATE FIELDS
        // ====================================================================

        /// <summary>
        /// The crypto engine instance. Created during Initialize().
        /// </summary>
        private LgCryptoEngine crypto;

        /// <summary>
        /// Tracks whether the TCP connection is currently online.
        /// Set by SIMPL+ via SetOnlineStatus() when TCP state changes.
        /// </summary>
        private ushort online = 0;

        /// <summary>
        /// Tracks whether this controller has been disposed.
        /// </summary>
        private bool disposed = false;

        /// <summary>
        /// Tracks whether we believe the TV is currently powered on.
        /// This is our best guess based on commands and responses.
        /// </summary>
        private bool tvIsOn = false;

        /// <summary>
        /// Timer used during PowerOn() sequence.
        /// We wait a few seconds after WoL before trying to connect,
        /// because the TV's network stack takes time to initialize.
        /// </summary>
        private CTimer connectDelayTimer = null;

        /// <summary>
        /// Public read-only access to online status for SIMPL+.
        /// </summary>
        public ushort IsOnline { get { return online; } }

        // ====================================================================
        // LOGGING
        // ====================================================================
        /// <summary>
        /// Appends a message to the log output.
        /// Each message gets a newline appended for readability.
        /// </summary>
        /// <param name="msg">The message to log</param>
        /// <remarks>
        /// Wrapped in try/catch because SIMPL+ delegates can fail in
        /// mysterious ways, and we don't want logging to break everything.
        /// </remarks>
        private void AppendLog(string msg)
        {
            string line = msg + "\r\n";

            if (LogOutput != null)
            {
                try
                {
                    LogOutput(new SimplSharpString(line));
                }
                catch
                {
                    // If logging fails, there's nothing we can do about it.
                    // Just keep going and hope for the best.
                }
            }
        }

        // ====================================================================
        // POWER STATE MANAGEMENT
        // ====================================================================

        /// <summary>
        /// Updates the TV power state and notifies SIMPL+.
        /// </summary>
        /// <param name="on">True if TV is on, false if off/standby</param>
        private void SetTvIsOn(bool on)
        {
            AppendLog("SetTvIsOn: " + (on ? "ON" : "OFF"));
            tvIsOn = on;

            if (TvIsOnOutput != null)
            {
                TvIsOnOutput((ushort)(on ? 1 : 0));
            }
        }

        /// <summary>
        /// Tells SIMPL+ to connect or disconnect the TCP socket.
        /// </summary>
        /// <param name="on">True to connect, false to disconnect</param>
        private void SetConnect(bool on)
        {
            AppendLog("SetConnect: " + (on ? "CONNECT" : "DISCONNECT"));

            if (ConnectOutput != null)
            {
                ConnectOutput((ushort)(on ? 1 : 0));
            }
        }

        // ====================================================================
        // WAKE-ON-LAN
        // ====================================================================
        /// <summary>
        /// Sends a Wake-on-LAN magic packet to power on the TV.
        /// </summary>
        /// <remarks>
        /// WAKE-ON-LAN PROTOCOL:
        /// ---------------------
        /// The magic packet consists of:
        /// - 6 bytes of 0xFF (sync stream)
        /// - 16 repetitions of the target MAC address (96 bytes)
        /// - Total: 102 bytes
        /// 
        /// The packet is sent via UDP broadcast to port 9 (the "discard" port,
        /// because of course they picked the discard port).
        /// 
        /// REQUIREMENTS FOR WOL TO WORK:
        /// 1. TV's WoL feature must be enabled (buried in TV settings somewhere)
        /// 2. TV must have received at least one packet from this device recently
        ///    (the TV caches the ARP entry and uses it to wake)
        /// 3. Network must allow UDP broadcast (some corporate networks block this)
        /// 4. TV must be in "standby" mode, not completely powered off
        ///    (if you flip the power switch, WoL won't work)
        /// </remarks>
        private void SendWakeOnLan()
        {
            AppendLog("=== WAKE-ON-LAN START ===");

            try
            {
                AppendLog("Target MAC: " + MacAddress);

                // Parse MAC address (accepts : or - as separators)
                string[] macParts = MacAddress.Split(':', '-');
                if (macParts.Length != 6)
                {
                    AppendLog("ERROR: Invalid MAC address format: " + MacAddress);
                    AppendLog("Expected format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF");
                    return;
                }

                byte[] mac = new byte[6];
                for (int i = 0; i < 6; i++)
                {
                    mac[i] = Convert.ToByte(macParts[i], 16);
                }
                AppendLog("Parsed MAC bytes: " + BitConverter.ToString(mac));

                // Build the magic packet (102 bytes total)
                byte[] packet = new byte[102];

                // First 6 bytes: 0xFF (sync stream)
                for (int i = 0; i < 6; i++)
                {
                    packet[i] = 0xFF;
                }
                AppendLog("Added sync stream (6x 0xFF)");

                // Next 96 bytes: MAC address repeated 16 times
                for (int i = 1; i <= 16; i++)
                {
                    Buffer.BlockCopy(mac, 0, packet, i * 6, 6);
                }
                AppendLog("Added 16 repetitions of MAC address");

                // Send UDP broadcast to port 9
                // Using Crestron's UDP server because standard .NET sockets
                // don't work properly on Crestron hardware (surprise!)
                AppendLog("Creating UDP socket for broadcast...");
                Crestron.SimplSharp.CrestronSockets.UDPServer udpServer =
                    new Crestron.SimplSharp.CrestronSockets.UDPServer("255.255.255.255", 9, 1024);

                udpServer.EnableUDPServer();
                AppendLog("UDP server enabled, sending " + packet.Length + " bytes...");

                udpServer.SendData(packet, packet.Length);
                AppendLog("Packet sent!");

                udpServer.DisableUDPServer();
                AppendLog("UDP server disabled");

                AppendLog("=== WAKE-ON-LAN COMPLETE ===");
            }
            catch (Exception ex)
            {
                AppendLog("WOL ERROR: " + ex.Message);
                AppendLog("Stack trace: " + ex.StackTrace);
            }
        }

        // ====================================================================
        // INITIALIZATION
        // ====================================================================
        /// <summary>
        /// Initializes the controller with the configured keycode.
        /// Call this from SIMPL+ after setting Host, MacAddress, and KeyCode.
        /// </summary>
        /// <remarks>
        /// This creates the crypto engine and derives the AES key from the keycode.
        /// Key derivation uses PBKDF2 with 16,384 iterations, so this call takes
        /// a noticeable amount of time on Crestron processors. Don't call it
        /// repeatedly.
        /// 
        /// If called multiple times, the previous crypto engine is disposed first.
        /// This allows re-initialization if the keycode changes.
        /// </remarks>
        public void Initialize()
        {
            AppendLog("=== INITIALIZE START ===");
            AppendLog("Host: " + (Host ?? "(not set)"));
            AppendLog("MacAddress: " + (MacAddress ?? "(not set)"));
            AppendLog("KeyCode: " + (KeyCode ?? "(not set)") + " (length: " + (KeyCode == null ? 0 : KeyCode.Length) + ")");

            try
            {
                // Dispose existing crypto if this is a re-initialization
                if (crypto != null)
                {
                    AppendLog("Disposing existing crypto engine...");
                    crypto.Dispose();
                    crypto = null;
                }

                AppendLog("Creating new crypto engine with keycode...");
                AppendLog("(This may take a few seconds due to PBKDF2 key derivation)");

                crypto = new LgCryptoEngine(KeyCode);

                // Wire up logging from crypto engine to our log output
                // This lets us see detailed crypto operations in the log
                crypto.LogCallback = AppendLog;

                AppendLog("Crypto engine initialized successfully!");
                AppendLog("=== INITIALIZE COMPLETE ===");
            }
            catch (Exception ex)
            {
                AppendLog("INITIALIZATION FAILED: " + ex.Message);
                AppendLog("Stack trace: " + ex.StackTrace);
                AppendLog("=== INITIALIZE FAILED ===");
            }
        }

        // ====================================================================
        // ONLINE STATUS
        // ====================================================================
        /// <summary>
        /// Called by SIMPL+ when the TCP connection status changes.
        /// </summary>
        /// <param name="value">1 if connected, 0 if disconnected</param>
        /// <remarks>
        /// SIMPL+ should call this whenever the TCP client's online status changes.
        /// We use this to gate command sending - no point encrypting and queueing
        /// commands if we're not connected.
        /// </remarks>
        public void SetOnlineStatus(ushort value)
        {
            AppendLog("Online status changed: " + (value == 0 ? "OFFLINE" : "ONLINE"));
            online = value;

            // If we just connected and thought TV was off, update state
            if (value == 1 && !tvIsOn)
            {
                AppendLog("Connection established - assuming TV is on");
                SetTvIsOn(true);
            }

            // If we disconnected unexpectedly, TV might have gone to standby
            if (value == 0 && tvIsOn)
            {
                AppendLog("Connection lost - TV may have entered standby");
                // Don't automatically set tvIsOn=false here, let the user
                // decide if they want to try reconnecting
            }
        }

        // ====================================================================
        // RECEIVE FROM SIMPL+ (TCP RX → DECRYPT)
        // ====================================================================
        /// <summary>
        /// Processes data received from the TV via TCP.
        /// Called by SIMPL+ when the TCP client receives data.
        /// </summary>
        /// <param name="data">
        /// The raw bytes received from TCP, encoded as an ISO-8859-1 string.
        /// SIMPL+ strings are actually byte arrays, not Unicode text.
        /// </param>
        /// <remarks>
        /// Flow:
        /// 1. SIMPL+ TCP client receives encrypted bytes from TV
        /// 2. SIMPL+ calls this method with the data (as a "string")
        /// 3. We convert the string to bytes using ISO-8859-1
        /// 4. We decrypt using the crypto engine
        /// 5. We send the decrypted message to DecodedOutput delegate
        /// 
        /// The decrypted messages are typically JSON responses from the TV
        /// indicating command results, current volume level, etc.
        /// </remarks>
        public void ProcessRx(string data)
        {
            AppendLog("=== PROCESS RX START ===");
            AppendLog("Received " + data.Length + " characters from SIMPL+");

            if (crypto == null)
            {
                AppendLog("ERROR: Crypto engine not initialized!");
                AppendLog("Call Initialize() before processing data.");
                AppendLog("=== PROCESS RX ABORTED ===");
                return;
            }

            try
            {
                // Convert SIMPL+ string to bytes using ISO-8859-1
                // This preserves the raw byte values that SIMPL+ passed us
                AppendLog("Converting SIMPL+ string to bytes...");
                byte[] raw = LgCryptoEngine.SimplStringToBytes(data);
                AppendLog("Got " + raw.Length + " bytes");

                // Decrypt the message
                AppendLog("Decrypting...");
                string msg = crypto.Decode(raw);

                if (msg.Length > 0)
                {
                    AppendLog("Decoded message: \"" + msg + "\"");

                    // If we're receiving messages, the TV is definitely on
                    // Update state if we thought it was off
                    if (!tvIsOn)
                    {
                        AppendLog("Received response from TV - updating state to ON");
                        SetTvIsOn(true);
                        SetConnect(true);
                    }

                    // Send decoded message to SIMPL+
                    if (DecodedOutput != null)
                    {
                        AppendLog("Sending decoded message to SIMPL+...");
                        try
                        {
                            DecodedOutput(new SimplSharpString(msg));
                        }
                        catch (Exception delegateEx)
                        {
                            AppendLog("DecodedOutput delegate failed: " + delegateEx.Message);
                        }
                    }
                    else
                    {
                        AppendLog("WARNING: DecodedOutput delegate not set, message discarded");
                    }
                }
                else
                {
                    AppendLog("Decryption returned empty string");
                    AppendLog("(This usually means wrong keycode or corrupted data)");
                }

                AppendLog("=== PROCESS RX COMPLETE ===");
            }
            catch (Exception ex)
            {
                AppendLog("DECODE ERROR: " + ex.Message);
                AppendLog("Stack trace: " + ex.StackTrace);
                AppendLog("=== PROCESS RX FAILED ===");
            }
        }

        // ====================================================================
        // TRANSMIT TO SIMPL+ (ENCRYPT → TCP TX)
        // ====================================================================
        /// <summary>
        /// Queues an encrypted packet for transmission via SIMPL+.
        /// </summary>
        /// <param name="packet">The encrypted bytes to send</param>
        /// <remarks>
        /// We convert the bytes to a SIMPL+ string using ISO-8859-1 and
        /// pass it to the TxOutput delegate. SIMPL+ should then send this
        /// data out the TCP socket to the TV.
        /// </remarks>
        private void QueueTx(byte[] packet)
        {
            AppendLog("Queueing TX: " + packet.Length + " bytes");

            // Convert bytes to SIMPL+ string using ISO-8859-1
            string s = LgCryptoEngine.BytesToSimplString(packet);
            AppendLog("Converted to " + s.Length + " character string");

            if (TxOutput != null)
            {
                try
                {
                    AppendLog("Sending to TxOutput delegate...");
                    TxOutput(new SimplSharpString(s));
                    AppendLog("TX queued successfully");
                }
                catch (Exception ex)
                {
                    AppendLog("TxOutput delegate failed: " + ex.Message);
                }
            }
            else
            {
                AppendLog("WARNING: TxOutput delegate not set, packet discarded!");
                AppendLog("Make sure to wire up TxOutput in SIMPL+");
            }
        }

        // ====================================================================
        // HIGH-LEVEL COMMANDS
        // ====================================================================
        // These are the methods that SIMPL+ programs typically call.
        // Each one sends a specific key command to the TV.
        // ====================================================================

        /// <summary>
        /// Increases the TV volume by one step.
        /// </summary>
        public void VolumeUp()
        {
            AppendLog(">>> VolumeUp() called");
            SendKey("volumeup");
        }

        /// <summary>
        /// Decreases the TV volume by one step.
        /// </summary>
        public void VolumeDown()
        {
            AppendLog(">>> VolumeDown() called");
            SendKey("volumedown");
        }

        /// <summary>
        /// Toggles the TV mute state.
        /// </summary>
        public void VolumeMute()
        {
            AppendLog(">>> VolumeMute() called");
            SendKey("volumemute");
        }

        /// <summary>
        /// Powers on the TV using Wake-on-LAN.
        /// </summary>
        /// <remarks>
        /// POWER-ON SEQUENCE:
        /// ------------------
        /// 1. Send WoL magic packet to wake the TV
        /// 2. Set TvIsOn=false, Connect=false (TV is booting, not ready yet)
        /// 3. Wait 3 seconds for the TV's network stack to initialize
        /// 4. Set TvIsOn=true, Connect=true (tell SIMPL+ to connect)
        /// 
        /// The 3-second delay is empirically determined. Some TVs might need
        /// more time, some less. If you have connection issues after WoL,
        /// try increasing this delay.
        /// 
        /// If PowerOn() is called while a previous timer is still pending,
        /// the old timer is cancelled and a new one is started.
        /// </remarks>
        public void PowerOn()
        {
            AppendLog(">>> PowerOn() called");
            AppendLog("=== POWER ON SEQUENCE START ===");

            // Step 1: Send Wake-on-LAN packet
            SendWakeOnLan();

            // Step 2: Reset state - TV is booting, not ready for connections
            SetTvIsOn(false);
            SetConnect(false);
            AppendLog("State reset: TvIsOn=false, Connect=false");

            // Cancel any existing timer from a previous PowerOn() call
            if (connectDelayTimer != null)
            {
                AppendLog("Cancelling existing connect delay timer...");
                connectDelayTimer.Stop();
                connectDelayTimer.Dispose();
                connectDelayTimer = null;
            }

            // Step 3: Wait for TV to boot, then connect
            AppendLog("Starting 3-second boot delay timer...");
            connectDelayTimer = new CTimer(_ =>
            {
                AppendLog("Boot delay complete!");
                SetTvIsOn(true);
                SetConnect(true);
                AppendLog("State updated: TvIsOn=true, Connect=true");
                AppendLog("=== POWER ON SEQUENCE COMPLETE ===");
            }, 3000);
        }

        /// <summary>
        /// Powers off the TV (puts it in standby mode).
        /// </summary>
        /// <remarks>
        /// POWER-OFF SEQUENCE:
        /// -------------------
        /// 1. Send the "POWER off" command to the TV
        /// 2. Immediately set TvIsOn=false, Connect=false
        /// 
        /// We use "POWER off" instead of "KEY_ACTION power" because:
        /// 1. It's the proper managed power-off command
        /// 2. KEY_ACTION power is a toggle (could turn TV on if already off)
        /// 3. POWER off is explicit and won't accidentally power on
        /// 
        /// We drop the connection immediately because:
        /// 1. The TV will drop it anyway when entering standby
        /// 2. Keeping a dead connection wastes resources
        /// 3. It gives cleaner state feedback to SIMPL+
        /// </remarks>
        public void PowerOff()
        {
            AppendLog(">>> PowerOff() called");
            AppendLog("=== POWER OFF SEQUENCE START ===");

            // Send the managed power-off command
            // "POWER off" is cleaner than "KEY_ACTION power" because it's
            // not a toggle - it explicitly tells the TV to turn off
            SendRawCommand("POWER off");

            // Immediately update state - TV is going to standby
            AppendLog("Updating state for standby...");
            SetTvIsOn(false);
            SetConnect(false);

            AppendLog("=== POWER OFF SEQUENCE COMPLETE ===");
        }

        /// <summary>
        /// Sends a custom key command to the TV.
        /// </summary>
        /// <param name="key">The key name (e.g., "home", "back", "enter", etc.)</param>
        /// <remarks>
        /// Use this for keys not covered by the convenience methods.
        /// 
        /// KNOWN KEY NAMES (may vary by TV model):
        /// - Navigation: "up", "down", "left", "right", "enter", "back", "home"
        /// - Volume: "volumeup", "volumedown", "volumemute"
        /// - Channel: "channelup", "channeldown"
        /// - Power: "power"
        /// - Numbers: "1", "2", "3", etc.
        /// - Input: "input", "hdmi1", "hdmi2", etc.
        /// - Menu: "menu", "settings", "info"
        /// - Playback: "play", "pause", "stop", "rewind", "fastforward"
        /// 
        /// If a key doesn't work, the TV just ignores it. No error, no feedback.
        /// Classic LG.
        /// </remarks>
        public void SendCustomKey(string key)
        {
            AppendLog(">>> SendCustomKey(\"" + key + "\") called");
            SendKey(key);
        }

        /// <summary>
        /// Sends a raw command string to the TV without any formatting.
        /// </summary>
        /// <param name="command">The complete command string (e.g., "POWER off")</param>
        /// <remarks>
        /// Use this for commands that don't follow the "KEY_ACTION keyname" format.
        /// LG's protocol supports multiple command types:
        /// - KEY_ACTION keyname  (for remote control keys)
        /// - POWER off           (for managed power-off, cleaner than KEY_ACTION power)
        /// - Various other undocumented commands (good luck finding them)
        /// 
        /// The command is encrypted and sent as-is, so make sure you know
        /// what you're doing. The TV will silently ignore invalid commands
        /// because of course it will.
        /// </remarks>
        private void SendRawCommand(string command)
        {
            AppendLog("SendRawCommand: \"" + command + "\"");

            // Check if we're connected
            if (online == 0)
            {
                AppendLog("ABORTED: Not online (TCP disconnected)");
                return;
            }

            // Check if crypto is initialized
            if (crypto == null)
            {
                AppendLog("ABORTED: Crypto engine not initialized");
                return;
            }

            try
            {
                AppendLog("Encrypting raw command...");
                byte[] enc = crypto.Encode(command);
                AppendLog("Encrypted to " + enc.Length + " bytes");

                QueueTx(enc);
                AppendLog("SendRawCommand complete");
            }
            catch (Exception ex)
            {
                AppendLog("SendRawCommand EXCEPTION: " + ex.Message);
                AppendLog("Stack trace: " + ex.StackTrace);
            }
        }

        /// <summary>
        /// Internal method that actually sends key commands.
        /// </summary>
        /// <param name="key">The key name to send</param>
        /// <remarks>
        /// COMMAND FORMAT:
        /// ---------------
        /// Commands are formatted as "KEY_ACTION keyname".
        /// For example: "KEY_ACTION volumeup"
        /// 
        /// The message is then encrypted using the crypto engine and
        /// queued for transmission via SIMPL+.
        /// 
        /// This method checks for online status and crypto initialization
        /// before attempting to send. If either is missing, the command
        /// is logged but not sent.
        /// </remarks>
        private void SendKey(string key)
        {
            AppendLog("SendKey: \"" + key + "\"");

            // Check if we're connected
            if (online == 0)
            {
                AppendLog("ABORTED: Not online (TCP disconnected)");
                AppendLog("Wait for connection or call PowerOn() first");
                return;
            }

            // Check if crypto is initialized
            if (crypto == null)
            {
                AppendLog("ABORTED: Crypto engine not initialized");
                AppendLog("Call Initialize() first");
                return;
            }

            try
            {
                // Build the command string
                string cmd = "KEY_ACTION " + key;
                AppendLog("Command string: \"" + cmd + "\"");

                // Encrypt and queue for transmission
                AppendLog("Encrypting...");
                byte[] enc = crypto.Encode(cmd);
                AppendLog("Encrypted to " + enc.Length + " bytes");

                QueueTx(enc);
                AppendLog("SendKey complete");
            }
            catch (Exception ex)
            {
                AppendLog("SendKey EXCEPTION: " + ex.Message);
                AppendLog("Stack trace: " + ex.StackTrace);
            }
        }

        // ====================================================================
        // IDISPOSABLE IMPLEMENTATION
        // ====================================================================
        /// <summary>
        /// Disposes the controller and all associated resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Protected disposal implementation.
        /// </summary>
        /// <param name="disposing">True if called from Dispose(), false if from finalizer</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    AppendLog("Disposing LgTvVolumeController...");

                    // Dispose the connect delay timer if it's still pending
                    if (connectDelayTimer != null)
                    {
                        AppendLog("Stopping and disposing connect delay timer...");
                        connectDelayTimer.Stop();
                        connectDelayTimer.Dispose();
                        connectDelayTimer = null;
                    }

                    // Dispose the crypto engine
                    if (crypto != null)
                    {
                        AppendLog("Disposing crypto engine...");
                        crypto.Dispose();
                        crypto = null;
                    }

                    AppendLog("Disposal complete");
                }
                disposed = true;
            }
        }

        /// <summary>
        /// Destructor - ensures cleanup even if Dispose() wasn't called.
        /// </summary>
        ~LgTvVolumeController()
        {
            Dispose(false);
        }
    }
}