using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace clientConsole
{
    class MixColumnn
    {
        // Each byte in the column is indivdually mixed with the other bytes in the column
        // via Galois Field addition and multiplication.
        // Set invert = true for inverse.
        public static void MixColumns(ref byte[,] state, bool invert = false)
        {
            for (int i = 0; i < 4; i++)
                MixColumn(state, i, invert);
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

    }
}
