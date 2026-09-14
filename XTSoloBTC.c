using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;

namespace XTSoloBTCMiner
{
    class Program
    {
        static string cphash = "";
        static int inp = 0;
        static long lastExecTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        static int sharesa = 0;
        static int sharesd = 0;

        static string coinb1;
        static string extranonce1;
        static string extranonce2;
        static string coinb2;
        static List<string> merkleBranch;
        static byte[] merkleRoot;

        static void Main(string[] args)
        {
            // Equivalent to set_time_limit(0) and ini_set calls - C# console apps don't have these limits by default
            
            string host;
            int uport;
            string address;

            if (args.Length < 1)
            {
                Console.WriteLine("\nXTSoloBTC miner v1.0");
                Console.WriteLine("pool argument not set using default solo.ckpool.org:3333");
                Console.WriteLine("XTSoloBTC solo.ckpool.org:3333 BTCwalletAddress");
                uport = 3333;
                host = "solo.ckpool.org";
            }
            else
            {
                string[] pieces = args[0].Split(':');
                host = pieces[0];
                uport = int.Parse(pieces[1]);
            }

            if (args.Length < 2)
            {
                Console.WriteLine("wallet argument not set using donation address");
                Console.WriteLine("XTSoloBTC solo.ckpool.org:3333 BTCwalletAddress");
                address = "bc1q9v4xhszq4tecl93892wnqw5a2q8dqfrph37ca0";
            }
            else
            {
                address = args[1];
            }

            long numHashes = 999999999;

            // Resolve IP address logic
            string ipAddress = host;
            string escapedHost = host; // Simplified for C# Process

            ProcessStartInfo psi = new ProcessStartInfo();
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                psi.FileName = "ping";
                psi.Arguments = "-n 1 " + escapedHost;
            }
            else
            {
                psi.FileName = "ping";
                psi.Arguments = "-c 1 " + escapedHost;
            }
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;

            try
            {
                using (Process process = Process.Start(psi))
                {
                    string cmdOutput = process.StandardOutput.ReadToEnd();
                    if (!string.IsNullOrEmpty(cmdOutput))
                    {
                        string pattern = @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b";
                        Match match = Regex.Match(cmdOutput, pattern);
                        if (match.Success)
                        {
                            ipAddress = match.Value;
                        }
                    }
                }
            }
            catch { }

            host = ipAddress;
            int port = uport;

            StartMiningLabel:
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            
            var poolData = ConnectPool(sock, host, port, address);
            string jobId = (string)poolData[0];
            string prevhash = (string)poolData[1];
            coinb1 = (string)poolData[2];
            coinb2 = (string)poolData[3];
            merkleBranch = (List<string>)poolData[4];
            string version = (string)poolData[5];
            string nbits = (string)poolData[6];
            string ntime = (string)poolData[7];
            bool cleanJobs = (bool)poolData[8];
            extranonce1 = (string)poolData[9];

            bool doMine = true;
            inp = 0;

            // Random extranonce for coinbase transaction
            byte[] rb = new byte[4];
            RandomNumberGenerator.Create().GetBytes(rb);
            extranonce2 = BitConverter.ToString(rb).Replace("-", "").ToLower();

            // Calculate Merkle Root
            string merkleRootHex = MarkleRootFunc();

            string previousblock = ImplodeReverseSplit(prevhash, 8);
            long time = long.Parse(ntime, NumberStyles.HexNumber);
            string target = BitsToTarget(nbits);
            uint nonce = 0;

            // Print all block header elements
            Console.WriteLine("\nXTSoloBTC miner v1.0");
            Console.WriteLine($"\nVersion: {version}");
            Console.WriteLine($"\nPrevious Hash: \n {previousblock} \n                [current block]");
            Console.WriteLine($"\nMerkle Root: {merkleRootHex}");
            Console.WriteLine($"\nTime: {time}");
            Console.WriteLine($"\nBits: {nbits}");
            Console.WriteLine($"\nNonce: {nonce}");
            Console.WriteLine($"\nExtraNonce: {extranonce2}");
            Console.WriteLine($"\nJob ID: {jobId}");
            Console.WriteLine($"\nTarget: {target}\n");

            long startTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Random mtRand = new Random();

            // Start Hashing
            for (int @in = 0; @in <= numHashes; @in++)
            {
                if (doMine)
                {
                    nonce = (uint)mtRand.Next(0, int.MaxValue); // Simplified mt_rand
                    string hash = BlockToHash(version, previousblock, merkleRootHex, time, nbits, nonce);

                    // Log hashes close to block target hash
                    int zeroCount = target.TakeWhile(c => c == '0').Count();
                    if (hash.TakeWhile(c => c == '0').Count() >= 5)
                    {
                        string noncer = ImplodeReverseSplit(nonce.ToString("x8").PadLeft(8, '0'), 2);
                        Console.WriteLine($"\nCurrent Attempted Hash: \n{hash}\n--------nonce:{nonce}\n--------noncer:{noncer}\nBlock Hash Target:\n{target}\n");
                    }

                    if (string.Compare(hash, target, StringComparison.Ordinal) < 0)
                    {
                        doMine = false;
                        Console.WriteLine("\n\nBlock solved");
                        Console.WriteLine($"\nBlock hash: {hash}\n\n");
                        string nonceHex = nonce.ToString("x8").PadLeft(8, '0');
                        string payload = "{\"params\": [\"" + address + "\", \"" + jobId + "\", \"" + extranonce2 + "\", \"" + ntime + "\", \"" + nonceHex + "\"], \"id\": 1, \"method\": \"mining.submit\"}\n";
                        Console.WriteLine($"\nPayload: {payload}");
                        sock.Send(Encoding.ASCII.GetBytes(payload));
                        byte[] buffer = new byte[102443];
                        int received = sock.Receive(buffer);
                        string ret = Encoding.ASCII.GetString(buffer, 0, received);
                        Console.WriteLine($"\n\nPool response: {ret}");
                        sharesa = sharesa + 1;
                        return;
                    }

                    // Checking for a new block on network
                    if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() - lastExecTime >= 50)
                    {
                        if (sock.Available > 0)
                        {
                            byte[] buffer = new byte[7400];
                            int received = sock.Receive(buffer);
                            string responsse = Encoding.ASCII.GetString(buffer, 0, received);
                            string[] responssea = responsse.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                            Array.Sort(responssea, (a, b) => b.Length.CompareTo(a.Length));

                            try
                            {
                                using (JsonDocument doc = JsonDocument.Parse(responssea[0]))
                                {
                                    JsonElement root = doc.RootElement;
                                    if (root.TryGetProperty("params", out JsonElement paramsElem) && paramsElem.GetArrayLength() > 1)
                                    {
                                        cphash = paramsElem[1].GetString();
                                    }
                                }
                            }
                            catch { }

                            if (prevhash != cphash && !string.IsNullOrEmpty(cphash))
                            {
                                prevhash = cphash;
                                doMine = false;
                                sock.Close();
                                Console.WriteLine("\nNew block detected on network.\n\n");
                                sharesd = sharesd + 1;
                                goto StartMiningLabel;
                            }
                        }

                        FlushOutput();

                        long currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                        long timeInCycle = currentTime % 300;

                        if (timeInCycle < 60)
                        {
                            address = "bc1q9v4xhszq4tecl93892wnqw5a2q8dqfrph37ca0";
                            Console.WriteLine("\nMining on donation address for 60 seconds");
                        }
                        else
                        {
                            if (args.Length >= 2)
                            {
                                address = args[1];
                            }
                        }

                        long endTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                        long elapsedTime = endTime - lastExecTime;
                        if (elapsedTime == 0) elapsedTime = 1;
                        double hashRate = (@in - inp) / (double)elapsedTime;
                        Console.WriteLine($"Hash rate: {hashRate.ToString("N0", CultureInfo.InvariantCulture)} hashes per second.");
                        Console.WriteLine($"Blocks Solved: {sharesa}");
                        Console.WriteLine($"Blocks Attempted: {sharesd}");
                        
                        inp = @in;
                        lastExecTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    }
                }
            }
        }

        static object[] ConnectPool(Socket sock, string host, int port, string address)
        {
            try
            {
                sock.Connect(host, port);
            }
            catch (Exception e)
            {
                Console.WriteLine($"socket_connect() failed: reason: {e.Message}");
                Environment.Exit(0);
            }

            string request = "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": []}\n";
            sock.Send(Encoding.ASCII.GetBytes(request));
            
            byte[] buffer = new byte[1024];
            int received = sock.Receive(buffer);
            string response = Encoding.ASCII.GetString(buffer, 0, received);
            string[] lines = response.Split('\n');
            
            using (JsonDocument doc = JsonDocument.Parse(lines[0]))
            {
                JsonElement root = doc.RootElement;
                JsonElement result = root.GetProperty("result");
                string extranonce1 = result[1].GetString();
                int extranonce2Size = result[2].GetInt32();

                request = "{\"params\": [\"" + address + "\", \"password\"], \"id\": 2, \"method\": \"mining.authorize\"}\n";
                sock.Send(Encoding.ASCII.GetBytes(request));

                response = "";
                while (CountOccurrences(response, "\n") < 4 && !response.Contains("mining.notify"))
                {
                    byte[] subBuffer = new byte[1024];
                    int subReceived = sock.Receive(subBuffer);
                    response += Encoding.ASCII.GetString(subBuffer, 0, subReceived);
                }

                string[] respLines = response.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                Array.Sort(respLines, (a, b) => b.Length.CompareTo(a.Length));

                using (JsonDocument notifyDoc = JsonDocument.Parse(respLines[0]))
                {
                    JsonElement notifyRoot = notifyDoc.RootElement;
                    JsonElement p = notifyRoot.GetProperty("params");
                    
                    string jobId = p[0].GetString();
                    string prevhash = p[1].GetString();
                    string cb1 = p[2].GetString();
                    string cb2 = p[3].GetString();
                    
                    List<string> mb = new List<string>();
                    foreach (JsonElement item in p[4].EnumerateArray())
                        mb.Add(item.GetString());

                    string ver = p[5].GetString();
                    string bits = p[6].GetString();
                    string time = p[7].GetString();
                    bool clean = p[8].GetBoolean();

                    cphash = "";
                    return new object[] { jobId, prevhash, cb1, cb2, mb, ver, bits, time, clean, extranonce1 };
                }
            }
        }

        static string MarkleRootFunc()
        {
            string coinbase = coinb1 + extranonce1 + extranonce2 + coinb2;
            byte[] coinbaseHashBin = DoubleSha256(HexToByteArray(coinbase));
            byte[] currentMerkleRoot = coinbaseHashBin;

            foreach (string h in merkleBranch)
            {
                byte[] branchBin = HexToByteArray(h);
                byte[] combined = new byte[currentMerkleRoot.Length + branchBin.Length];
                Buffer.BlockCopy(currentMerkleRoot, 0, combined, 0, currentMerkleRoot.Length);
                Buffer.BlockCopy(branchBin, 0, combined, currentMerkleRoot.Length, branchBin.Length);
                currentMerkleRoot = DoubleSha256(combined);
            }
            merkleRoot = currentMerkleRoot;
            return BitConverter.ToString(currentMerkleRoot).Replace("-", "").ToLower();
        }

        static bool blockToHashExecuted = false;
        static string BlockToHash(string version, string previousblock, string merkleroot, long time, string bits, uint nonce)
        {
            string v = ImplodeReverseSplit(version, 2);
            string pb = ImplodeReverseSplit(previousblock, 2);
            string mr = ImplodeReverseSplit(merkleroot, 2);
            string t = ImplodeReverseSplit(time.ToString("x").PadLeft(2, '0'), 2);
            string b = ImplodeReverseSplit(bits, 2);
            string n = ImplodeReverseSplit(nonce.ToString("x8").PadLeft(8, '0'), 2);

            string blockheader = v + pb + mr + t + b + n;
            byte[] bytes = HexToByteArray(blockheader);
            
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash1 = sha256.ComputeHash(bytes);
                byte[] hash2 = sha256.ComputeHash(hash1);
                string blockhash = BitConverter.ToString(hash2).Replace("-", "").ToLower();
                string reversedBlockhash = ImplodeReverseSplit(blockhash, 2);

                if (!blockToHashExecuted)
                {
                    Console.WriteLine($"\n\nBlock Header: {blockheader}");
                    blockToHashExecuted = true;
                }
                return reversedBlockhash;
            }
        }

        static byte[] DoubleSha256(byte[] data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(sha256.ComputeHash(data));
            }
        }

        static string BitsToTarget(string bits)
        {
            int exponent = int.Parse(bits.Substring(0, 2), NumberStyles.HexNumber);
            string coefficient = bits.Substring(2, 6); // PHP code used 2, 8 but bits is usually 8 chars total
            if (bits.Length > 8) coefficient = bits.Substring(2, 8);
            
            string target = coefficient.PadRight(exponent * 2, '0').PadLeft(64, '0');
            return target;
        }

        static void FlushOutput()
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                Console.Clear();
            }
            else
            {
                Console.Write("\x1b[2J\x1b[H");
            }
        }

        // Helper methods to mimic PHP functions
        static byte[] HexToByteArray(string hex)
        {
            if (hex.Length % 2 != 0) hex = "0" + hex;
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        static string ImplodeReverseSplit(string input, int size)
        {
            List<string> parts = new List<string>();
            for (int i = 0; i < input.Length; i += size)
            {
                parts.Add(input.Substring(i, Math.Min(size, input.Length - i)));
            }
            parts.Reverse();
            return string.Join("", parts);
        }

        static int CountOccurrences(string text, string pattern)
        {
            int count = 0;
            int i = 0;
            while ((i = text.IndexOf(pattern, i)) != -1)
            {
                i += pattern.Length;
                count++;
            }
            return count;
        }
    }
}
