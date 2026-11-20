using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace WhitelistGuard;

internal static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        try
        {
            if (args.Contains("--dns-service"))
            {
                DnsFilter.Run();
                return;
            }
            if (args.Contains("--install"))
            {
                Installer.Install();
                return;
            }
            if (args.Contains("--uninstall"))
            {
                Installer.Uninstall();
                return;
            }

            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Whitelist Guard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}

internal static class Store
{
    public static readonly string Dir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WhitelistGuard");
    public static readonly string Config = Path.Combine(Dir, "allowed-sites.txt");
    public static readonly string LogFile = Path.Combine(Dir, "dns.log");

    public static void Ensure()
    {
        Directory.CreateDirectory(Dir);
        if (!File.Exists(Config)) File.WriteAllText(Config, "# One domain per line\r\n");
    }

    public static string? Normalize(string input)
    {
        var s = input.Trim().ToLowerInvariant();
        s = Regex.Replace(s, @"^https?://", "");
        s = s.Split('/', '?', '#')[0];
        if (s.StartsWith("*.")) s = s[2..];
        s = s.TrimEnd('.');
        if (s.Length > 253 || !s.Contains('.')) return null;
        foreach (var label in s.Split('.'))
        {
            if (label.Length is < 1 or > 63 ||
                !Regex.IsMatch(label, @"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"))
                return null;
        }
        return s;
    }

    public static List<string> Read()
    {
        Ensure();
        return File.ReadAllLines(Config)
            .Select(x => x.Trim())
            .Where(x => x.Length > 0 && !x.StartsWith("#"))
            .Select(Normalize)
            .Where(x => x != null)
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x)
            .ToList();
    }

    public static void Write(IEnumerable<string> values)
    {
        Ensure();
        File.WriteAllLines(Config, new[] { "# One domain per line. Subdomains are included." }
            .Concat(values.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x)));
    }

    public static void Log(string line)
    {
        try
        {
            Ensure();
            File.AppendAllText(LogFile, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {line}{Environment.NewLine}");
        }
        catch { }
    }
}

internal sealed class MainForm : Form
{
    private readonly DataGridView grid = new();
    private readonly TextBox domainBox = new();
    private readonly Label status = new();

    public MainForm()
    {
        Text = "Whitelist Guard";
        Width = 850;
        Height = 650;
        MinimumSize = new System.Drawing.Size(720, 520);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = System.Drawing.Color.FromArgb(246, 248, 250);
        Font = new System.Drawing.Font("Segoe UI", 10);

        var title = new Label {
            Text = "Whitelist Guard", Left = 26, Top = 20, Width = 500, Height = 42,
            Font = new System.Drawing.Font("Segoe UI Semibold", 23),
            ForeColor = System.Drawing.Color.FromArgb(20, 36, 58)
        };
        Controls.Add(title);

        var subtitle = new Label {
            Text = "Only domains in your allowlist are resolved by this PC.",
            Left = 28, Top = 65, Width = 650, Height = 24,
            ForeColor = System.Drawing.Color.DimGray
        };
        Controls.Add(subtitle);

        status.SetBounds(28, 100, 780, 26);
        status.ForeColor = System.Drawing.Color.DarkGreen;
        Controls.Add(status);

        domainBox.SetBounds(28, 140, 550, 36);
        domainBox.Font = new System.Drawing.Font("Segoe UI", 11);
        domainBox.PlaceholderText = "Enter domain, e.g. company.com";
        Controls.Add(domainBox);

        var add = Button("Allow website", 590, 138, 210, 40);
        add.Click += (_, _) => AddDomain();
        Controls.Add(add);

        grid.SetBounds(28, 195, 772, 300);
        grid.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.ReadOnly = true;
        grid.MultiSelect = true;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.RowHeadersVisible = false;
        grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        grid.BackgroundColor = System.Drawing.Color.White;
        grid.Columns.Add("domain", "ALLOWED DOMAIN");
        grid.Columns.Add("scope", "ACCESS");
        grid.Columns[0].FillWeight = 65;
        grid.Columns[1].FillWeight = 35;
        Controls.Add(grid);

        var remove = Button("Remove selected", 28, 510, 175, 42);
        remove.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        remove.Click += (_, _) => RemoveSelected();
        Controls.Add(remove);

        var import = Button("Import TXT", 215, 510, 145, 42);
        import.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        import.Click += (_, _) => ImportTxt();
        Controls.Add(import);

        var export = Button("Export TXT", 372, 510, 145, 42);
        export.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        export.Click += (_, _) => ExportTxt();
        Controls.Add(export);

        var install = Button("Install protection", 550, 510, 155, 42);
        install.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        install.Click += (_, _) => RunElevated("--install");
        Controls.Add(install);

        var uninstall = Button("Uninstall", 715, 510, 85, 42);
        uninstall.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        uninstall.Click += (_, _) => RunElevated("--uninstall");
        Controls.Add(uninstall);

        var note = new Label {
            Text = "Allowing example.com also allows its subdomains. VPNs and private encrypted DNS may bypass DNS filtering.",
            Left = 28, Top = 565, Width = 780, Height = 32,
            Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
            ForeColor = System.Drawing.Color.DimGray
        };
        Controls.Add(note);

        Store.Ensure();
        RefreshGrid();
        UpdateStatus();
    }

    private Button Button(string text, int x, int y, int w, int h) => new()
    {
        Text = text, Left = x, Top = y, Width = w, Height = h,
        FlatStyle = FlatStyle.Flat, BackColor = System.Drawing.Color.FromArgb(230, 237, 244),
        ForeColor = System.Drawing.Color.FromArgb(25, 45, 65),
        Font = new System.Drawing.Font("Segoe UI Semibold", 9.5f)
    };

    private void AddDomain()
    {
        var domain = Store.Normalize(domainBox.Text);
        if (domain == null)
        {
            MessageBox.Show("Enter a valid domain, e.g. company.com", "Invalid domain");
            return;
        }
        var items = Store.Read();
        if (!items.Contains(domain, StringComparer.OrdinalIgnoreCase)) items.Add(domain);
        Store.Write(items);
        domainBox.Clear();
        RefreshGrid();
    }

    private void RemoveSelected()
    {
        if (grid.SelectedRows.Count == 0)
        {
            MessageBox.Show("Select one or more website rows first.");
            return;
        }
        var selected = grid.SelectedRows.Cast<DataGridViewRow>()
            .Select(r => Convert.ToString(r.Cells[0].Value)!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (MessageBox.Show("Remove selected domains from the allowlist?\r\n\r\n" +
            string.Join("\r\n", selected), "Confirm removal",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

        Store.Write(Store.Read().Where(x => !selected.Contains(x)));
        RefreshGrid();
    }

    private void ImportTxt()
    {
        using var dialog = new OpenFileDialog { Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*" };
        if (dialog.ShowDialog() != DialogResult.OK) return;
        var values = Store.Read();
        foreach (var line in File.ReadAllLines(dialog.FileName))
        {
            var s = line.Trim();
            if (s.Length == 0 || s.StartsWith("#")) continue;
            var d = Store.Normalize(s);
            if (d != null && !values.Contains(d, StringComparer.OrdinalIgnoreCase)) values.Add(d);
        }
        Store.Write(values);
        RefreshGrid();
    }

    private void ExportTxt()
    {
        using var dialog = new SaveFileDialog { Filter = "Text files (*.txt)|*.txt", FileName = "allowed-sites.txt" };
        if (dialog.ShowDialog() == DialogResult.OK)
            File.WriteAllLines(dialog.FileName, Store.Read());
    }

    private void RefreshGrid()
    {
        grid.Rows.Clear();
        foreach (var domain in Store.Read())
            grid.Rows.Add(domain, "Domain + subdomains");
        UpdateStatus();
    }

    private void UpdateStatus()
    {
        status.Text = $"Allowlist: {Store.Read().Count} domains  |  Config: {Store.Config}";
    }

    private void RunElevated(string arg)
    {
        try
        {
            var start = new ProcessStartInfo(Application.ExecutablePath, arg)
            {
                UseShellExecute = true,
                Verb = "runas"
            };
            using var p = Process.Start(start);
            p?.WaitForExit();
            MessageBox.Show(arg == "--install"
                ? "Install command finished. Restart Windows and test one PC."
                : "Uninstall command finished. Restart Windows.", "Whitelist Guard");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Could not run elevated");
        }
    }
}

internal static class Installer
{
    private static string ExePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WhitelistGuard", "WhitelistGuard.exe");

    public static void Install()
    {
        if (!IsAdmin()) throw new InvalidOperationException("Run Install protection as Administrator.");
        Store.Ensure();
        Directory.CreateDirectory(Path.GetDirectoryName(ExePath)!);
        var current = Application.ExecutablePath;
        if (!string.Equals(current, ExePath, StringComparison.OrdinalIgnoreCase))
            File.Copy(current, ExePath, true);

        RunPowerShell($@"
$ErrorActionPreference = 'Stop'
$Data = '{Store.Dir.Replace("'", "''")}'
New-Item -ItemType Directory -Force -Path $Data | Out-Null
& icacls.exe $Data /grant '*S-1-5-32-545:(OI)(CI)M' /T | Out-Null

# Configure Chrome and Edge to disable built-in DNS-over-HTTPS.
New-Item 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Force | Out-Null
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name DnsOverHttpsMode -Value 'off' -PropertyType String -Force | Out-Null
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name DnsOverHttpsMode -Value 'off' -PropertyType String -Force | Out-Null

Get-NetFirewallRule -DisplayName 'WhitelistGuard DNS *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'WhitelistGuard DNS UDP' -Direction Outbound -Action Block -Protocol UDP -RemotePort 53,853 -Profile Any | Out-Null
New-NetFirewallRule -DisplayName 'WhitelistGuard DNS TCP' -Direction Outbound -Action Block -Protocol TCP -RemotePort 53,853 -Profile Any | Out-Null

# Do not change Windows DNS until the local resolver is confirmed running.
if (Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 -ErrorAction SilentlyContinue) {{
    throw 'Port 53 on 127.0.0.1 is already in use. No DNS adapter settings were changed.'
}}

$task = 'WhitelistGuard-DNS'
$exe = '{ExePath.Replace("'", "''")}'
$action = New-ScheduledTaskAction -Execute $exe -Argument '--dns-service'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 20 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $task
Start-Sleep -Seconds 3
if (-not (Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 -ErrorAction SilentlyContinue)) {{
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    throw 'DNS service did not start on 127.0.0.1:53. Windows DNS settings were NOT changed.'
}}

Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {{
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses '127.0.0.1'
}}
");
        Store.Log("Installer completed; DNS set to loopback.");
    }

    public static void Uninstall()
    {
        if (!IsAdmin()) throw new InvalidOperationException("Run Uninstall as Administrator.");
        RunPowerShell(@"
$ErrorActionPreference = 'Continue'
Stop-ScheduledTask -TaskName 'WhitelistGuard-DNS' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'WhitelistGuard-DNS' -Confirm:$false -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName 'WhitelistGuard DNS *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
}
Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
");
        Store.Log("Uninstalled; adapters reset to DHCP DNS.");
    }

    private static bool IsAdmin()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static void RunPowerShell(string script)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encoded)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        };
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start PowerShell.");
        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException("Windows setup failed:\r\n" + stderr + "\r\n" + stdout);
    }
}

internal static class DnsFilter
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(8) };
    private const string DnsOverHttps = "https://cloudflare-dns.com/dns-query";

    public static void Run()
    {
        Store.Ensure();
        Store.Log("DNS service starting on 127.0.0.1:53");
        var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 53));
        var tcp = new TcpListener(IPAddress.Loopback, 53);
        tcp.Start();

        _ = Task.Run(async () =>
        {
            while (true)
            {
                var result = await udp.ReceiveAsync();
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var response = await Process(result.Buffer);
                        await udp.SendAsync(response, result.RemoteEndPoint);
                    }
                    catch (Exception ex) { Store.Log("UDP error: " + ex.Message); }
                });
            }
        });

        while (true)
        {
            var client = tcp.AcceptTcpClient();
            _ = Task.Run(async () => await HandleTcp(client));
        }
    }

    private static async Task HandleTcp(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var header = new byte[2];
                await ReadExact(stream, header);
                int length = (header[0] << 8) | header[1];
                var packet = new byte[length];
                await ReadExact(stream, packet);
                var response = await Process(packet);
                await stream.WriteAsync(new byte[] { (byte)(response.Length >> 8), (byte)response.Length });
                await stream.WriteAsync(response);
            }
            catch (Exception ex) { Store.Log("TCP error: " + ex.Message); }
        }
    }

    private static async Task ReadExact(NetworkStream stream, byte[] buffer)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset));
            if (read == 0) throw new IOException("Client disconnected.");
            offset += read;
        }
    }

    private static async Task<byte[]> Process(byte[] packet)
    {
        if (packet.Length < 17) return packet;
        string? qname = ReadQuestionName(packet);
        if (qname == null) return MakeNxDomain(packet);

        bool allowed = Store.Read().Any(d =>
            qname.Equals(d, StringComparison.OrdinalIgnoreCase) ||
            qname.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));

        if (!allowed)
        {
            Store.Log("BLOCK " + qname);
            return MakeNxDomain(packet);
        }

        try
        {
            using var content = new ByteArrayContent(packet);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
            using var request = new HttpRequestMessage(HttpMethod.Post, DnsOverHttps) { Content = content };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
            using var response = await Http.SendAsync(request);
            response.EnsureSuccessStatusCode();
            var data = await response.Content.ReadAsByteArrayAsync();
            Store.Log("ALLOW " + qname);
            return data;
        }
        catch (Exception ex)
        {
            Store.Log("UPSTREAM ERROR " + qname + ": " + ex.Message);
            return MakeServFail(packet);
        }
    }

    private static string? ReadQuestionName(byte[] packet)
    {
        try
        {
            int pos = 12;
            var labels = new List<string>();
            while (pos < packet.Length)
            {
                int len = packet[pos++];
                if (len == 0) break;
                if ((len & 0xC0) != 0 || len > 63 || pos + len > packet.Length) return null;
                labels.Add(Encoding.ASCII.GetString(packet, pos, len));
                pos += len;
            }
            return labels.Count == 0 ? null : string.Join(".", labels);
        }
        catch { return null; }
    }

    private static byte[] MakeNxDomain(byte[] query) => MakeError(query, 3);
    private static byte[] MakeServFail(byte[] query) => MakeError(query, 2);

    private static byte[] MakeError(byte[] query, int rcode)
    {
        var response = (byte[])query.Clone();
        if (response.Length < 12) return response;
        response[2] = (byte)((response[2] | 0x80) & 0xFB); // QR=1, TC=0
        response[3] = (byte)((response[3] & 0xF0) | 0x80 | rcode); // RA=1, RCODE
        for (int i = 6; i < 12; i++) response[i] = 0;
        return response;
    }
}
