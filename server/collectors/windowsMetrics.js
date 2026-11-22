/**
 * Windows units (platform: "windows"): the SSH server hands every command to
 * cmd.exe or PowerShell, so the Linux shell pipelines (/proc, bash, grep) are
 * replaced with two small PowerShell scripts. Each prints plain sections
 * separated by "---" lines, which the parsers below turn into the same shapes
 * the Linux collectors return.
 *
 * Commands are sent as -EncodedCommand (base64 of UTF-16LE), so quoting is the
 * same under cmd.exe, PowerShell and WSL-less OpenSSH defaults. cmd.exe limits a
 * command line to 8191 characters, which keeps each script short (see test).
 */

const PREAMBLE = [
  "$ErrorActionPreference='SilentlyContinue'",
  "[Console]::OutputEncoding=[Text.Encoding]::UTF8",
];

/**
 * GPU Engine utilization is instantaneous; inference leaves idle gaps between
 * kernels. Sampling twice catches a burst, but each WMI query costs ~1 s on the
 * first call and ~0.3 s after. One sample is the lightest; override with
 * SPARKDASH_WINDOWS_GPU_SAMPLES (1-5) when a smoother gauge matters more.
 */
const WINDOWS_GPU_SAMPLES = Math.min(
  5,
  Math.max(1, Number.parseInt(process.env.SPARKDASH_WINDOWS_GPU_SAMPLES || "1", 10) || 1)
);

/** `_x000D_` escapes and XML entities back to the characters they stand for. */
function unescapeClixml(body) {
  return String(body)
    .replace(/_x([0-9A-Fa-f]{4})_/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/&#x([0-9A-Fa-f]+);/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(Number(dec)))
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    // Last: an escaped ampersand must not re-create one of the entities above.
    .replace(/&amp;/g, "&");
}

/**
 * Decode PowerShell's CLIXML error stream.
 *
 * With stderr redirected — which is how every command sparkDash runs on a Windows
 * unit arrives — PowerShell serialises its error and warning streams instead of
 * writing plain text, so a failure reaches the dashboard as the unreadable
 * `#< CLIXML <Objs …><S S="Error">…</S></Objs>`. This returns the stream text in
 * order, as one line; `null` when the input is not CLIXML, and `""` when it is
 * CLIXML that carries no stream text (progress records only).
 *
 * @param {unknown} text
 * @returns {string | null}
 */
export function decodeClixml(text) {
  const raw = String(text ?? "");
  if (!/^\s*#<\s*CLIXML/.test(raw)) return null;
  const parts = [];
  // One <S> element per line written to a stream, tagged with the stream name.
  for (const [, stream, body] of raw.matchAll(/<S(?:\s+S="([^"]*)")?[^>]*>([\s\S]*?)<\/S>/g)) {
    // Keep what a reader needs; drop verbose/debug/progress chatter.
    if (stream && !/^(error|warning|information)$/i.test(stream)) continue;
    parts.push(unescapeClixml(body));
  }
  return parts.join("").replace(/\s+/g, " ").trim();
}

/** Wrap a script so it runs the same way under cmd.exe, PowerShell or any default shell. */
export function powershellCommand(script) {
  const encoded = Buffer.from(String(script), "utf16le").toString("base64");
  return `powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${encoded}`;
}

/**
 * nvidia-smi: per-GPU stats, memory, compute apps. Same queries the Linux
 * collector uses. On a machine without nvidia-smi installed (an AMD-iGPU Windows
 * host, e.g. a Strix Halo) the same sections are produced from the GPU Engine /
 * GPU Adapter Memory performance counters instead, so the parser needs no
 * Windows- or vendor-specific branch. An NVIDIA PC whose nvidia-smi is installed
 * but failing stays empty (a broken driver must not look like a working AMD GPU):
 *   - utilization: busiest engine per physical adapter, sampled 3× 300 ms apart
 *     (the counter is instantaneous and inference leaves idle gaps between
 *     kernels), clamped to 100 — AMD engines can report >100%;
 *   - memory: Dedicated + Shared adapter usage in MB, total from the driver's
 *     registry memory size (the BIOS carve-out on unified-memory iGPUs).
 *     Remote/virtual display adapters are skipped so the perf-counter adapter
 *     index lines up with the physical controller whose registry key holds it;
 *   - a final MemTotal/MemAvailable section feeds _getRemoteGpu's meminfo
 *     fallback (empty for NVIDIA, which reports its own memory.total).
 * Temperature/power stay empty: AMD does not publish them to Windows, and the
 * parser reads empty fields as null → 0.
 */
export const WINDOWS_GPU_SCRIPT = [
  ...PREAMBLE,
  "$s=(Get-Command nvidia-smi|Select-Object -First 1).Source",
  "if(-not $s){$p=\"$env:ProgramFiles\\NVIDIA Corporation\\NVSMI\\nvidia-smi.exe\";if(Test-Path $p){$s=$p}}",
  "$gpu=@();$mem=@();$apps=@();$names=@();$meminfo=@()",
  "if($s){",
  "  $gpu = & $s '--query-gpu=temperature.gpu,utilization.gpu,power.draw,power.limit,clocks.current.sm,clocks.max.sm,clocks_throttle_reasons.hw_thermal_slowdown,clocks_throttle_reasons.sw_thermal_slowdown,clocks_throttle_reasons.hw_slowdown,clocks_throttle_reasons.sw_power_cap,index,name,uuid' '--format=csv,noheader,nounits' 2>$null",
  "  $mem = & $s '--query-gpu=memory.used,memory.total' '--format=csv,noheader,nounits' 2>$null",
  "  $apps = & $s '--query-compute-apps=pid,process_name,used_gpu_memory,gpu_uuid' '--format=csv,noheader,nounits' 2>$null",
  "  $names = & $s '--query-gpu=name,driver_version' '--format=csv,noheader,nounits' 2>$null",
  "}",
  "if(-not $s){",
  `  $eng = 1..${WINDOWS_GPU_SAMPLES} | % { gcim Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine | ? { $_.UtilizationPercentage -gt 0 -and $_.Name -match '_phys_(\\d+)' } | % { [pscustomobject]@{P=[int]$Matches[1];U=[double]$_.UtilizationPercentage} }; if ($_ -lt ${WINDOWS_GPU_SAMPLES}) { sleep -m 150 } }`,
  "  $vc=@(gcim Win32_VideoController | ? { $_.Name -notmatch 'NVIDIA|Remote Display|Basic Display|Virtual' })",
  "  $rs=@{}",
  "  gci 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue | ? { $_.PSChildName -match '^\\d{4}$' } | % { $p=gp $_.PSPath -ErrorAction SilentlyContinue; if($p -and $p.'HardwareInformation.qwMemorySize'){$rs[[string]$p.'DriverDesc']=[long]$p.'HardwareInformation.qwMemorySize'} }",
  "  $ad=@{}",
  "  gcim Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory | ? { $_.Name -match '_phys_(\\d+)' } | % { $ad[[int]$Matches[1]]=$_ }",
  "  $gpu=@();$mem=@()",
  "  $bp=@($eng | group P)",
  "  $adapters = if($bp.Count -gt 0){$bp}else{@(@{Name=0})}",
  "  $i=0",
  "  foreach($g in $adapters){",
  "    $u=0",
  "    if($bp.Count -gt 0){ $u=[int](($g.Group | measure U -Maximum).Maximum); if($u -gt 100){$u=100} }",
  "    $name=if($i -lt $vc.Count -and $vc[$i].Name){$vc[$i].Name}else{\"GPU $i\"}",
  "    $tot=0; if($rs.ContainsKey($name)){$tot=[int]($rs[$name]/1MB)}",
  "    $used=0; $a=$ad[[int]$g.Name]; if($a){$used=[int](($a.DedicatedUsage+$a.SharedUsage)/1MB)}",
  "    $gpu+=\"0,$u,,0,0,0,,,,,0,$name\"; $mem+=\"$used,$tot\"; $i++",
  "  }",
  "  $apps=@()",
  "  $names=@($vc | % { \"$($_.Name),$($_.DriverVersion)\" })",
  "  $o=gcim Win32_OperatingSystem",
  "  if($o){ $meminfo=@(\"MemTotal: $([long]$o.TotalVisibleMemorySize) kB\",\"MemAvailable: $([long]$o.FreePhysicalMemory) kB\") }",
  "}",
  "$gpu; '---'; $mem; '---'; $apps; '---'; $names; '---'; $meminfo; '---'",
  // A failed native command must not make powershell exit 1 (sshExec treats that as a dead host).
  "exit 0",
].join("\n");

/**
 * Memory, uptime, CPU load, disks and network adapters in one round trip.
 * Fields are joined with a TAB (a volume label or adapter name may contain `|`);
 * `-join` stringifies with the invariant culture, unlike `-f`, so a decimal
 * never turns into `12,5`. Statistics and addresses are fetched once, not per adapter.
 */
export const WINDOWS_SYSTEM_SCRIPT = [
  ...PREAMBLE,
  "$t=[char]9",
  "function Cl($v){([string]$v) -replace '[\\t\\r\\n]',' '}",
  // One PDH sample. WMI's PerfOS/Tcpip/PerfDisk provider is unreliable on some
  // hosts (and a standard user over a network logon cannot read those classes),
  // while the PDH counters stay readable. The WMI classes below are stable.
  "$p=(Get-Counter -Counter @('\\Memory\\Available MBytes','\\System\\System Up Time','\\Processor(_Total)\\% Processor Time','\\Network Interface(*)\\Bytes Received/sec','\\Network Interface(*)\\Bytes Sent/sec','\\LogicalDisk(*)\\Disk Read Bytes/sec','\\LogicalDisk(*)\\Disk Write Bytes/sec') -SampleInterval 1 -MaxSamples 1).CounterSamples",
  "$ma=0;$ut=0;$cl=0;$rx=@{};$tx=@{};$rd=@{};$wr=@{}",
  "foreach($s in $p){$x=$s.Path;if($x -match '\\\\memory\\\\available mbytes$'){$ma=$s.CookedValue}elseif($x -match '\\\\system\\\\system up time$'){$ut=$s.CookedValue}elseif($x -match '\\\\processor\\(_total\\)\\\\% processor time$'){$cl=$s.CookedValue}elseif($x -match '\\\\network interface\\((.+)\\)\\\\bytes (received|sent)/sec$'){$k=$Matches[1];$d=$Matches[2].ToLower();if($d -eq 'received'){$rx[$k]=[long]$s.CookedValue}else{$tx[$k]=[long]$s.CookedValue}}elseif($x -match '\\\\logicaldisk\\(([a-z]:)\\)\\\\disk (read|write) bytes/sec$'){$k=$Matches[1].ToUpper();$d=$Matches[2].ToLower();if($d -eq 'read'){$rd[$k]=[long]$s.CookedValue}else{$wr[$k]=[long]$s.CookedValue}}}",
  "$cs=Get-CimInstance Win32_ComputerSystem -Property TotalPhysicalMemory",
  "@([long]($cs.TotalPhysicalMemory/1KB),[long]($ma*1024),[long]$ut) -join $t",
  "'---'",
  "$name=(Get-ItemProperty 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0').ProcessorNameString",
  "@([int][math]::Round($cl),(Cl $name),[Environment]::ProcessorCount) -join $t",
  "'---'",
  "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|%{@((Cl $_.DeviceID),(Cl $_.VolumeName),$_.Size,$_.FreeSpace) -join $t}",
  "'---'",
  "$r=(route print -4|Select-String '^\\s*0\\.0\\.0\\.0\\s+0\\.0\\.0\\.0\\s+\\S+\\s+(\\S+)'|Select-Object -First 1);if($r){$r.Matches.Groups[1].Value}",
  "'---'",
  "$ip=@{};Get-CimInstance Win32_NetworkAdapterConfiguration|?{$_.IPEnabled}|%{$v4=@($_.IPAddress|?{$_ -match '^\\d{1,3}(\\.\\d{1,3}){3}$'});if($v4.Count){$ip[$_.InterfaceIndex]=$v4[0]}}",
  "$names=@{};Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}' -ErrorAction SilentlyContinue|%{$q=Get-ItemProperty (Join-Path $_.PSPath 'Connection') -ErrorAction SilentlyContinue;if($q.Name){$names[$_.PSChildName]=$q.Name}}",
  "Get-CimInstance Win32_NetworkAdapter|?{$_.PhysicalAdapter}|%{$d=$_.Description;$k=$null;foreach($i in $rx.Keys){if($i -ieq $d){$k=$i;break}};if(-not $k){foreach($i in $tx.Keys){if($i -ieq $d){$k=$i;break}}};$a=if($k){$rx[$k]}else{0};$b=if($k){$tx[$k]}else{0};$v=if($_.NetEnabled -and $_.Speed -lt 1000000000000){$_.Speed}else{0};$z=if($_.Description -match 'Wintun|Tunnel|Virtual|Hyper-V|Loopback|vEthernet'){'True'}else{'False'};@((Cl $names[$_.GUID]),$(if($_.NetEnabled){'Up'}else{'Disconnected'}),$v,$a,$b,$ip[$_.InterfaceIndex],$z) -join $t}",
  "'---'",
  // Bytes per second per drive, so no host-side delta state is needed.
  "$d=@($rd.Keys+$wr.Keys|Sort-Object -Unique);foreach($i in $d){@($i,[long]$rd[$i],[long]$wr[$i]) -join $t}",
  "exit 0",
].join("\n");

const num = (value) => {
  const text = String(value ?? "").trim();
  if (!text) return null;
  const n = Number(text);
  return Number.isFinite(n) ? n : null;
};

/**
 * @param {string} output  WINDOWS_SYSTEM_SCRIPT output
 */
export function parseWindowsSystem(output) {
  const sections = String(output ?? "").split(/^---\s*$/m).map((s) => s.trim());
  const [mem = "", cpu = "", disks = "", route = "", nets = "", io = ""] = sections;

  const [totalKB, freeKB, uptime] = mem.split("\t").map(num);
  const cpuParts = cpu.split("\t");
  const load = num(cpuParts[0]);

  const diskRows = [];
  for (const line of disks.split(/\r?\n/)) {
    const [id, label, size, free] = line.replace(/\r$/, "").split("\t");
    const total = num(size);
    const avail = num(free);
    if (!id || total == null || total <= 0 || avail == null) continue;
    diskRows.push({ id, label: label || "", totalBytes: total, freeBytes: avail });
  }

  const adapters = [];
  for (const line of nets.split(/\r?\n/)) {
    const p = line.replace(/\r$/, "").split("\t");
    if (p.length < 7 || !p[0]) continue;
    adapters.push({
      name: p[0],
      status: p[1],
      linkBps: num(p[2]),
      rxBytes: num(p[3]),
      txBytes: num(p[4]),
      ip: p[5] || null,
      virtual: /^true$/i.test(p[6]),
    });
  }

  // Read/write bytes per second per drive letter (PDH rates, not cumulative).
  const diskIo = new Map();
  for (const line of io.split(/\r?\n/)) {
    const [name, read, written] = line.replace(/\r$/, "").split("\t");
    const r = num(read);
    const w = num(written);
    if (name && r != null && w != null) diskIo.set(name.toUpperCase(), { readBytes: r, writtenBytes: w });
  }

  // The route section is the default route's interface IP; map it to the
  // adapter alias from the network section. Fall back to the raw value when
  // the route is absent or the IP does not match a listed adapter.
  const defaultIp = route.trim().split(/\r?\n/)[0]?.trim() || null;
  const defaultInterface = defaultIp
    ? adapters.find((a) => a.ip === defaultIp)?.name ?? defaultIp
    : null;

  return {
    totalMB: totalKB != null ? Math.round(totalKB / 1024) : 0,
    availableMB: freeKB != null ? Math.round(freeKB / 1024) : 0,
    uptimeSec: uptime != null && uptime >= 0 ? Math.floor(uptime) : null,
    cpuLoad: load != null ? Math.min(100, Math.max(0, Math.round(load))) : null,
    cpuName: (cpuParts[1] || "").trim() || null,
    logicalCpus: num(cpuParts[2]),
    disks: diskRows,
    diskIo,
    defaultInterface,
    adapters,
  };
}

/** Split WINDOWS_GPU_SCRIPT output into the pieces the shared GPU parser expects. */
export function splitWindowsGpuOutput(output) {
  const sections = String(output ?? "").split(/^---\s*$/m).map((s) => s.trim());
  return { gpu: sections[0] || "", memory: sections[1] || "", apps: sections[2] || "", names: sections[3] || "", meminfo: sections[4] || "" };
}

/** Linux-shaped output for `_getRemoteGpu`, so the shared parser needs no Windows branch. */
export function windowsGpuAsLinuxOutput(output) {
  const { gpu, memory, apps, meminfo } = splitWindowsGpuOutput(output);
  return [gpu, "---", memory, "---", apps, "---", meminfo].join("\n");
}
