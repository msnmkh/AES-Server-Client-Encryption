using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace clientConsole
{
    class Encryption
    {
        public enum Padding
        {
            ZERO, PKCS7, NONE
        }

        public enum Mode
        {
            ECB, CBC
        }

        private static bool Invert = true; // Used on invertable functions

        public static byte[] Encrypt(byte[] buf, byte[] key, Mode mode = Mode.ECB,
                                     byte[] iv = null, Padding padding = Padding.PKCS7)
        {
            if (mode == Mode.CBC)
            {
                if (iv == null || iv.Length < 16) 
                    return null;
            }
            int keysize = key.Length * 8;
            if ((keysize != 128) & (keysize != 192) & (keysize != 256))
                return null;
            uint[] ek = ExpandKey(key, keysize);
            var bin = new MemoryStream(PadBuffer(buf, 16, padding));
            var bout = new MemoryStream();
            var block = new byte[16];
            int c;
            byte[,] state;
            byte[] cblock = iv;
            while ((c = bin.Read(block, 0, 16)) > 0)
            {
                switch (mode)
                {
                    case Mode.ECB:
                        state = LoadState(block);
                        EncryptBlock(state, ek, keysize);
                        bout.Write(DumpState(state), 0, c);
                        break;
                    case Mode.CBC:
                        block = XorBytes(block, cblock);
                        state = LoadState(block);
                        EncryptBlock(state, ek, keysize);
                        cblock = DumpState(state);
                        bout.Write(cblock, 0, c);
                        break;
                    default:
                        return null;
                }
            }
            return bout.ToArray();
        }

        // Decrypt Message
        public static byte[] Decrypt(byte[] buf, byte[] key, Mode mode = Mode.ECB,
            byte[] iv = null, Padding padding = Padding.PKCS7)
        {
            if (mode == Mode.CBC)
            {
                if (iv == null)
                    return null;
                if (iv.Length < 16)
                    return null;
            }
            int keysize = key.Length * 8;
            if ((keysize != 128) & (keysize != 192) & (keysize != 256))
                return null;
            uint[] ek = ExpandKey(key, keysize);
            var bin = new MemoryStream(buf);
            var bout = new MemoryStream();
            var block = new byte[16];
            int c;
            byte[,] state;
            byte[] cblock = iv;
            while ((c = bin.Read(block, 0, 16)) > 0)
            {
                switch (mode)
                {
                    case Mode.ECB:
                        state = LoadState(block);
                        DecryptBlock(state, ek, keysize);
                        block = DumpState(state);
                        bout.Write(block, 0, c);
                        break;
                    case Mode.CBC:
                        state = LoadState(block);
                        DecryptBlock(state, ek, keysize);
                        byte[] pblock = DumpState(state);
                        pblock = XorBytes(pblock, cblock);
                        cblock = (byte[])block.Clone();
                        bout.Write(pblock, 0, c);
                        break;
                    default:
                        return null;
                }
            }
            byte[] b1 = bout.ToArray();
            c = GetPadCount(b1, padding);
            byte[] b2 = new byte[b1.Length - c];
            Buffer.BlockCopy(b1, 0, b2, 0, b1.Length - c);
            return b2;
        }

        // Decrypt a block loaded into a state with expanded key.
        private static void DecryptBlock(byte[,] state, uint[] key, int keysize)
        {
            int rounds;
            switch (keysize)
            {
                case 128:
                    rounds = 10;
                    break;
                case 192:
                    rounds = 12;
                    break;
                case 256:
                    rounds = 14;
                    break;
                default:
                    return;
            }
            AddRoundKey(state, GetUIntBlock(key, rounds));
            for (int i = 1; i <= rounds; i++)
            {
                ShiftRows(state, Invert);
                SubBytes(state, Invert);
                AddRoundKey(state, GetUIntBlock(key, rounds - i));
                if (i != rounds)
                    MixColumns(state, Invert);
            }
        }


        // Returns the number of bytes padding at the end of the buffer.
        private static int GetPadCount(byte[] buf, Padding padding = Padding.PKCS7)
        {
            if (padding == Padding.NONE)
                return 0;
            int c = 0;
            bool keepgoing = true;
            for (int i = (buf.Length - 1); (i >= 0) && keepgoing; i--)
                switch (padding)
                {
                    case Padding.PKCS7:
                        if ((buf[i] == buf[buf.Length - 1]))
                            c++;
                        else keepgoing = false;
                        break;
                    case Padding.ZERO:
                        if (buf[i] == 0)
                            c++;
                        else keepgoing = false;
                        break;
                }
            switch (padding)
            {
                case Padding.PKCS7:
                    if (c > buf[buf.Length - 1])
                        return buf[buf.Length - 1];
                    if (buf[buf.Length - 1] != c)
                        return 0;
                    break;
            }
            return c;
        }

        // Expand key to a subkey for each round of en(de)cryption
        private static uint[] ExpandKey(byte[] key, int keysize = 0)
        {
            if (keysize == 0)
                keysize = key.Length * 8;
            int numWords, count, init;
            switch (keysize)
            {
                case 128:
                    numWords = 44;
                    count = 4;
                    init = 4;
                    break;
                case 192:
                    numWords = 52;
                    count = 6;
                    init = 6;
                    break;
                case 256:
                    numWords = 60;
                    count = 4;
                    init = 8;
                    break;
                default:
                    return null;
            }
            uint[] expandedKey = new uint[numWords];
            int iteration = 1;

            for (int i = 0; i < init; i++)
            {
                expandedKey[i] = GetWord(key, i * 4);
            }
            int counter = 0;
            for (int i = init; i < numWords; i += count)
            {
                uint tmp = expandedKey[i - 1];
                // 256 bit keys are a special case.
                // This is implemented as making every other pass handle the extra phase and
                // doubling the passes for 256 bit keys. Note that iteration only happens on
                // the key schedule core pass.
                if ((keysize == 256) & ((counter % 2) == 1))
                {
                    tmp = SubstituteWord(tmp);
                }
                else
                {
                    tmp = KeyScheduleCore(tmp, iteration);
                    iteration++;
                }
                counter++;
                for (int j = 0; j < count; j++)
                {
                    if ((i + j) >= numWords) // Special case for 192 bit keys
                        break;
                    tmp ^= expandedKey[i - init + j];
                    expandedKey[i + j] = tmp;
                }
            }
            return expandedKey;
        }

        // Return 32 bit uint at b[offset]
        private static uint GetWord(byte[] b, int offset = 0)
        {
            uint ret = 0;
            for (int i = 0; i < 4; i++)
            {
                ret <<= 8;
                ret |= b[i + offset];
            }
            return ret;
        }

        // Passes a 32 bit unsigned int through the Rijndael S-box
        private static uint SubstituteWord(uint word)
        {
            return (uint)(Sbox.SBOX[word & 0x000000FF] |
                (Sbox.SBOX[(word >> 8) & 0x000000FF] << 8) |
                (Sbox.SBOX[(word >> 16) & 0x000000FF] << 16) |
                (Sbox.SBOX[(word >> 24) & 0x000000FF] << 24));
        }

        // Key schedule core (http://en.wikipedia.org/wiki/Rijndael_key_schedule)
        // This operation is used as an inner loop in the key schedule, and is done in the following manner:
        // The input is a 32-bit word and at an iteration number i. The output is a 32-bit word.
        // Copy the input over to the output.
        // Use the above described rotate operation to rotate the output eight bits to the left
        // Apply Rijndael's S-box on all four individual bytes in the output word
        // On just the first (leftmost) byte of the output word, exclusive OR the byte with 2 to the power 
        // of (i-1). In other words, perform the rcon operation with i as the input, and exclusive or the 
        // rcon output with the first byte of the output word
        private static uint KeyScheduleCore(uint word, int iteration)
        {
            uint wOut = SubstituteWord(RotateByteLeft(word));
            wOut ^= (uint)(CalcRcon((byte)iteration) << 24);
            return wOut;
        }

        // Rotates the value of a 32 bit unsigned int to the left 1 byte.
        private static uint RotateByteLeft(uint x)
        {
            return ((x << 8) | (x >> 24));
        }

        // Rcon is what the Rijndael documentation calls the exponentiation of 2 to a user-specified 
        // value. Note that this operation is not performed with regular integers, but in Rijndael's 
        // finite field. (http://en.wikipedia.org/wiki/Rijndael_key_schedule)
        // Rcon(0) is 0x8d because 0x8d multiplied by 0x02 is 0x01 in the finite field.
        // (http://crypto.stackexchange.com/questions/10682/rijndael-explanation-of-rcon-on-wikipedia/10683)
        // CalcRcon is based on code by Sam Trenholme (http://www.samiam.org/key-schedule.html)
        // Typically implemented as a lookup table.
        private static byte CalcRcon(byte bin)
        {
            if (bin == 0)
                return 0x8d;
            byte b1 = 1;
            while (bin != 1)
            {
                byte b2;
                b2 = (byte)(b1 & 0x80);
                b1 <<= 1;
                if (b2 == 0x80)
                    b1 ^= 0x1b;
                bin--;
            }
            return b1;
        }

        // Pads buffer with filler using various padding styles 
        private static byte[] PadBuffer(byte[] buf, int padfrom, int padto, Padding padding = Padding.PKCS7)
        {
            if ((padto < buf.Length) | ((padto - padfrom) > 255))
                return buf;
            byte[] b = new byte[padto];
            Buffer.BlockCopy(buf, 0, b, 0, padfrom);
            for (int i = padfrom; i < padto; i++)
            {
                switch (padding)
                {
                    case Padding.PKCS7:
                        b[i] = (byte)(padto - padfrom);
                        break;
                    case Padding.ZERO:
                    case Padding.NONE:
                        b[i] = 0;
                        break;
                    default:
                        return buf;
                }
            }
            return b;
        }


        // This pads to an extra block on length % blocksize = 0 for PKCS7 (this is necessary per the standard)
        // and Zero Padding (this is implementation dependent and deliberate, but really doesn't matter as
        // no matter how many nulls are added, they will be stripped). 
        // No extra block will be added on Padding.NONE, but the last block will still be zero filled.
        public static byte[] PadBuffer(byte[] buf, int blocksize, Padding padding = Padding.PKCS7)
        {
            int extraBlock = (buf.Length % blocksize) == 0 && padding == Padding.NONE ? 0 : 1;
            return PadBuffer(buf, buf.Length, ((buf.Length / blocksize) + extraBlock) * blocksize, padding);
        }

        // This will load from a flat array into the state array starting at the 
        // block of 16 at "offset". 0 for the first block of 16, 1 for the second, 2 for the third, etc...
        private static byte[,] LoadState(byte[] buf, int offset = 0)
        {
            byte[,] state = new byte[4, 4];
            int c = 0;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                {
                    state[j, i] = buf[c + (offset * 16)];
                    c++;
                }
            return state;
        }

        // Dump state to byte array.
        private static byte[] DumpState(byte[,] state)
        {
            byte[] b = new byte[16];
            int c = 0;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                {
                    b[c] = state[j, i];
                    c++;
                }
            return b;
        }

        // Get column[index] of state
        private static byte[] GetColumn(byte[,] state, int index)
        {
            byte[] b = new byte[4];
            for (int i = 0; i < 4; i++)
                b[i] = state[i, index];
            return b;
        }

        // Copy b to column[index] of state
        private static void PutColumn(byte[,] state, byte[] b, int index)
        {
            for (int i = 0; i < 4; i++)
                state[i, index] = b[i];
        }

        // Encrypt a block loaded into a state with expanded key.
        private static void EncryptBlock(byte[,] state, uint[] key, int keysize)
        {
            int rounds;
            switch (keysize)
            {
                case 128:
                    rounds = 10;
                    break;
                case 192:
                    rounds = 12;
                    break;
                case 256:
                    rounds = 14;
                    break;
                default:
                    return;
            }
            AddRoundKey(state, GetUIntBlock(key));
            for (int i = 1; i <= rounds; i++)
            {
                SubBytes(state);
                ShiftRows(state);
                if (i != rounds)
                    MixColumns(state);
                AddRoundKey(state, GetUIntBlock(key, i));
            }
        }

        // Xor bytes of b1 with b2, circling through b2 as many times as necessary
        private static byte[] XorBytes(byte[] b1, byte[] b2)
        {
            byte[] rb = new byte[b1.Length];
            for (int i = 0; i < b1.Length; i++)
                rb[i] = (byte)(b1[i] ^ b2[i % b2.Length]);
            return rb;
        }

        // Returns a byte array representing the uint at "index" offset of key.
        private static byte[] GetByteBlock(uint[] key, int offset = 0)
        {
            return new byte[] {
                (byte) ((key[offset] >> 24) & 0xFF),
                (byte) ((key[offset] >> 16) & 0xFF),
                (byte) ((key[offset] >> 8) & 0xFF),
                (byte) (key[offset] & 0xFF)
            };
        }

        // Returns a uint array 4 wide starting at the index "offset" of key.
        private static uint[] GetUIntBlock(uint[] key, int offset = 0)
        {
            uint[] tmp = new uint[4];
            for (int i = 0; i < 4; i++)
                tmp[i] = key[i + (offset * 4)];
            return tmp;
        }

        // AddRoundKey xors the state by a block of key data. Inverse is itself.	
        private static void AddRoundKey(byte[,] state, uint[] key)
        {
            for (int i = 0; i < 4; i++)
            {
                var kb = GetByteBlock(key, i);
                for (int j = 0; j < 4; j++)
                    state[j, i] ^= kb[j];
            }
        }

        // Takes the state array and the sbox array. Set invert = true for inverse.
        private static void SubBytes(byte[,] state, bool invert = false)
        {
            byte[] sb;
            if (invert)
                sb = Sbox.iSBOX;
            else
                sb = Sbox.SBOX;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[j, i] = sb[state[j, i]];
        }

        private static void _ShiftRows(byte[,] state)
        {
            for (int j = 0; j < 4; j++)
                for (int i = 0; i < j; i++)
                {
                    byte b = state[j, 0];
                    for (int c = 1; c < 4; c++)
                        state[j, c - 1] = state[j, c];
                    state[j, 3] = b;
                }
        }

        private static void _InvShiftRows(byte[,] state)
        {
            for (int j = 0; j < 4; j++)
                for (int i = 0; i < j; i++)
                {
                    byte b = state[j, 3];
                    for (int c = 3; c > 0; c--)
                        state[j, c] = state[j, c - 1];
                    state[j, 0] = b;
                }
        }

        // Shift rows left n columns where n is the row's index. Set invert = true for inverse.
        private static void ShiftRows(byte[,] state, bool invert = false)
        {
            if (invert)
                _InvShiftRows(state);
            else
                _ShiftRows(state);
        }

        // Mulitplication in the Galois Field. Typically implemented with lookup tables.
        // gmul is based on code by Sam Trenholme (http://www.samiam.org/galois.html)
        private static byte gmul(byte a, byte b)
        {
            byte p = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 0x01) == 0x01)
                    p ^= a;
                byte hibit = (byte)(a & 0x80);
                a <<= 1;
                if (hibit == 0x80)
                    a ^= 0x1b;
                b >>= 1;
            }
            return p;
        }

        private static void _MixColumn(byte[] r)
        {
            byte[] a = new byte[4];
            for (int i = 0; i < 4; i++)
                a[i] = r[i];
            r[0] = (byte)(gmul(a[0], 2) ^ a[3] ^ a[2] ^ gmul(a[1], 3));
            r[1] = (byte)(gmul(a[1], 2) ^ a[0] ^ a[3] ^ gmul(a[2], 3));
            r[2] = (byte)(gmul(a[2], 2) ^ a[1] ^ a[0] ^ gmul(a[3], 3));
            r[3] = (byte)(gmul(a[3], 2) ^ a[2] ^ a[1] ^ gmul(a[0], 3));
        }

        private static void _InvMixColumn(byte[] r)
        {
            byte[] a = new byte[4];
            for (int i = 0; i < 4; i++)
                a[i] = r[i];
            r[0] = (byte)(gmul(a[0], 14) ^ gmul(a[3], 9) ^ gmul(a[2], 13) ^ gmul(a[1], 11));
            r[1] = (byte)(gmul(a[1], 14) ^ gmul(a[0], 9) ^ gmul(a[3], 13) ^ gmul(a[2], 11));
            r[2] = (byte)(gmul(a[2], 14) ^ gmul(a[1], 9) ^ gmul(a[0], 13) ^ gmul(a[3], 11));
            r[3] = (byte)(gmul(a[3], 14) ^ gmul(a[2], 9) ^ gmul(a[1], 13) ^ gmul(a[0], 11));
        }

        private static void MixColumn(byte[,] state, int index, bool invert = false)
        {
            byte[] col = GetColumn(state, index);
            if (invert)
                _InvMixColumn(col);
            else
                _MixColumn(col);
            PutColumn(state, col, index);
        }

        // Each byte in the column is indivdually mixed with the other bytes in the column
        // via Galois Field addition and multiplication.
        // Set invert = true for inverse.
        private static void MixColumns(byte[,] state, bool invert = false)
        {
            for (int i = 0; i < 4; i++)
                MixColumn(state, i, invert);
        }

    }
}
