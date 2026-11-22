// Compiled locally into an immutable runtime, never installed over Codex.
// The job owns only the Python runner and its descendants. Stopping this shim
// cannot kill another desktop/engine, and cannot leave its upstream requests.
using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

internal static class Entry {
    [StructLayout(LayoutKind.Sequential)] struct Startup {
        public uint cb; public string reserved, desktop, title;
        public uint x, y, width, height, countX, countY, fill, flags;
        public ushort show, reservedSize; public IntPtr reservedPtr, input, output, error;
    }
    [StructLayout(LayoutKind.Sequential)] struct Child {
        public IntPtr process, thread; public uint pid, tid;
    }
    [StructLayout(LayoutKind.Sequential)] struct Basic {
        public long processTime, jobTime; public uint flags;
        public UIntPtr minimum, maximum; public uint processes;
        public UIntPtr affinity; public uint priority, scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct Limits {
        public Basic basic;
        public ulong readOps, writeOps, otherOps, readBytes, writeBytes, otherBytes;
        public UIntPtr processMemory, jobMemory, peakProcessMemory, peakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcess(string app, StringBuilder command, IntPtr pa, IntPtr ta,
        bool inherit, uint flags, IntPtr env, string cwd, ref Startup startup, out Child child);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int type, ref Limits data, uint size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int kind);

    static string Quote(string value) {
        var text = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') text.Append('\\', slashes * 2 + 1);
            else text.Append('\\', slashes);
            slashes = 0; text.Append(c);
        }
        return text.Append('\\', slashes * 2).Append('"').ToString();
    }
    static void Check(bool ok) { if (!ok) throw new Win32Exception(); }
    static int Main(string[] args) {
        IntPtr job = IntPtr.Zero; Child child = new Child();
        try {
            string folder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string python = @@PYTHON@@;
            var command = new StringBuilder(Quote(python));
            foreach (string arg in new string[] {"-B", "-X", "utf8", Path.Combine(folder, "transport_runner.py"),
                "--engine", Path.Combine(folder, "codex.exe"), "--timeout-ms", @@TIMEOUT@@, "--"})
                command.Append(' ').Append(Quote(arg));
            foreach (string arg in args) command.Append(' ').Append(Quote(arg));
            job = CreateJobObject(IntPtr.Zero, null); Check(job != IntPtr.Zero);
            var limits = new Limits(); limits.basic.flags = 0x2000; // KILL_ON_JOB_CLOSE
            Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits)));
            var startup = new Startup(); startup.cb = (uint)Marshal.SizeOf(startup);
            startup.flags = 0x100; // USESTDHANDLES: preserve Electron's stdio pipes.
            startup.input = GetStdHandle(-10); startup.output = GetStdHandle(-11); startup.error = GetStdHandle(-12);
            Check(CreateProcess(python, command, IntPtr.Zero, IntPtr.Zero, true, 0x08000004,
                IntPtr.Zero, null, ref startup, out child)); // NO_WINDOW | SUSPENDED
            Check(AssignProcessToJobObject(job, child.process));
            Check(ResumeThread(child.thread) != 0xffffffff);
            Check(WaitForSingleObject(child.process, 0xffffffff) == 0);
            uint code; Check(GetExitCodeProcess(child.process, out code));
            return unchecked((int)code);
        } catch (Exception) {
            if (child.process != IntPtr.Zero) TerminateProcess(child.process, 1);
            Console.Error.WriteLine("Codex HTTP timeout launcher failed; child job closed.");
            return 1;
        } finally {
            if (child.thread != IntPtr.Zero) CloseHandle(child.thread);
            if (child.process != IntPtr.Zero) CloseHandle(child.process);
            if (job != IntPtr.Zero) CloseHandle(job);
        }
    }
}
