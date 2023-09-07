using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;


namespace NmcApcUtil
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("NmcApcUtil.exe <source-pfx> <pfx-password> <destinationfile>");
                return;
            }
            var pfxBlob = File.ReadAllBytes(args[0]);
            var pw = args[1];
            var dest = args[2];

            Console.WriteLine("Loading pfx..");
            var store = new Pkcs12StoreBuilder().Build();
            store.Load(new MemoryStream(pfxBlob), pw.ToCharArray());
            Console.WriteLine("... loaded");

            Console.WriteLine("Getting cert & key..");
            var cert = store.GetCertificate(store.Aliases.First());
            var key = store.GetKey(store.Aliases.First());
            Console.WriteLine("... got cert and key");

            var rsaParameters = (RsaPrivateCrtKeyParameters)key.Key;


            Console.WriteLine("Init crypt");
            crypt.Init();

            Console.WriteLine("Create context");
            int cryptContext = crypt.CreateContext(crypt.UNUSED, crypt.CRYPT_ALGO_RSA);

            Console.WriteLine("Set label name");
            crypt.SetAttributeString(cryptContext, 1016, Encoding.UTF8.GetBytes("Private key"));

            MemoryStream msRSA = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(msRSA);
            bw.Write((Int32)0);
            WriteBuf(bw, rsaParameters.Modulus.ToByteArray());
            WriteBuf(bw, rsaParameters.PublicExponent.ToByteArray());
            WriteBuf(bw, rsaParameters.Exponent.ToByteArray());
            WriteBuf(bw, rsaParameters.P.ToByteArray());
            WriteBuf(bw, rsaParameters.Q.ToByteArray());
            WriteBuf(bw, rsaParameters.QInv.ToByteArray());
            WriteBuf(bw, rsaParameters.DP.ToByteArray());
            WriteBuf(bw, rsaParameters.DQ.ToByteArray());
            Console.WriteLine("Set private key");
            crypt.SetAttributeString(cryptContext, 1013, msRSA.ToArray());

            Console.WriteLine("Import certificate");
            var certHandle = crypt.ImportCert(cert.Certificate.GetEncoded(), crypt.UNUSED);

            Console.WriteLine("Create keyset");
            var keySet = crypt.KeysetOpen(crypt.UNUSED, 1, dest, 2);
            crypt.AddPrivateKey(keySet, cryptContext, "user");
            crypt.AddPublicKey(keySet, certHandle);
            crypt.KeysetClose(keySet);
            Console.WriteLine("Keyset created");


            Console.WriteLine("Adding APC specific header");
            NMCHeader header = new NMCHeader();
            byte[] collection = File.ReadAllBytes(dest);
            List<byte> list = new List<byte>();
            if (File.Exists(dest))
            {
                list.InsertRange(0, collection);
                header.headerVersion = 1;
                header.appVersion = 1;
                header.appVersionStr = "NMCSecurityWizardCLI101".PadRight(200, '\0').ToCharArray();
                header.fileVersion = 1;
                header.fileType = (int)1;
                header.fileSize = list.Count;
                header.fileCrc = BitConverter.ToInt32(NMCHeader.ComputeRhodesChecksum(collection), 0);
                header.headerCrc = BitConverter.ToInt32(NMCHeader.ComputeRhodesChecksum(header.CreateByteArray(false)), 0);
                byte[] buffer2 = header.CreateByteArray(true);
                using (FileStream stream = new FileStream(dest, FileMode.Create))
                {
                    int index = 0;
                    while (true)
                    {
                        if (index >= buffer2.Length)
                        {
                            for (int i = 0; i < collection.Length; i++)
                            {
                                stream.WriteByte(collection[i]);
                            }
                            break;
                        }
                        stream.WriteByte(buffer2[index]);
                        index++;
                    }
                }
            }
            Console.WriteLine("Finished");

        }

        private static void WriteBuf(BinaryWriter bw, byte[] data)
        {
            int MAXPKC = 512;
            byte[] buf = new byte[MAXPKC];
            Array.Copy(data, 0, buf, 0, data.Length);
            bw.Write(buf);
            bw.Write((Int32)data.Length * 8);
        }
    }
}