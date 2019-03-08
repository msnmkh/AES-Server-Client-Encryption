using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace clientConsole
{
    class SubBytes
    {
        public static void SubBytesMatrix(ref byte[,] state, bool invert = false)
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
    }
}
