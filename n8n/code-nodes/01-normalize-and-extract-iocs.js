// n8n Code node: Normalize Wazuh Alert & Extract IOCs

const root = $json;
const alert = root.body?.body ?? root.body ?? root;

function pushIOC(list, type, value, source) {
  if (!value) return;
  if (typeof value !== "string") value = String(value);
  value = value.trim();
  if (!value) return;

  const exists = list.some(i => i.type === type && i.value === value);
  if (!exists) list.push({ type, value, source });
}

function mapSeverity(level) {
  level = Number(level || 0);
  if (level >= 13) return "critical";
  if (level >= 10) return "high";
  if (level >= 6) return "medium";
  return "low";
}

function isIPv4(value) {
  if (!value || typeof value !== "string") return false;
  const ip = value.trim();
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;

  const parts = ip.split(".").map(Number);
  return parts.every(n => n >= 0 && n <= 255);
}

function isPrivateOrLocalIP(ip) {
  if (!ip || typeof ip !== "string") return true;
  ip = ip.trim();

  return (
    ip === "127.0.0.1" ||
    ip === "::1" ||
    ip === "0.0.0.0" ||
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
    ip.startsWith("169.254.")
  );
}

function normalizeDomain(value) {
  if (!value || typeof value !== "string") return null;
  const v = value.trim().toLowerCase().replace(/\.$/, "");
  return v || null;
}

function cleanUrl(url) {
  return String(url).trim().replace(/[),.;]+$/, "");
}

function getHostFromUrl(url) {
  if (!url || typeof url !== "string") return null;

  const cleaned = url.trim();

  try {
    const host = new URL(cleaned).hostname;
    if (host) return host.trim().toLowerCase();
  } catch {}

  const m = cleaned.match(/^https?:\/\/([^\/:\s]+)(?::\d{1,5})?(?:\/|$)/i);
  if (m && m[1]) {
    return m[1].trim().toLowerCase();
  }

  return null;
}

function pushDerivedHostIOC(list, host, source) {
  if (!host) return;

  if (isIPv4(host)) {
    if (!isPrivateOrLocalIP(host)) {
      pushIOC(list, "ip", host, source);
    }
  } else {
    const d = normalizeDomain(host);
    if (d) {
      pushIOC(list, "domain", d, source);
    }
  }
}

function extractDomainsFromText(text, excludedHosts = []) {
  if (!text || typeof text !== "string") return [];

  const matches = text.match(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g) || [];
  const excludedTlds = new Set([
    "exe", "dll", "sys", "bat", "cmd", "ps1", "msi", "lnk", "tmp", "dat", "log",
    "vbs", "vbe", "ini", "txt", "json", "xml", "csv", "js", "html", "css", "py",
    "webclient"
  ]);
  const excluded = new Set(excludedHosts.map(v => String(v).toLowerCase()));

  return [...new Set(matches
    .map(m => normalizeDomain(m))
    .filter(Boolean)
    .filter(d => {
      const last = d.split(".").pop();
      if (excludedTlds.has(last)) return false;
      if (excluded.has(d)) return false;
      return true;
    })
  )];
}

function extractIPsFromText(text) {
  if (!text || typeof text !== "string") return [];

  const matches = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  return [...new Set(matches.filter(isIPv4))];
}

const iocs = [];
const ruleLevel = Number(alert.rule?.level || 0);

// Hashes
pushIOC(iocs, "sha256", alert.syscheck?.sha256_after, "syscheck.sha256_after");
pushIOC(iocs, "sha1", alert.syscheck?.sha1_after, "syscheck.sha1_after");
pushIOC(iocs, "md5", alert.syscheck?.md5_after, "syscheck.md5_after");

// IPs
const candidateIPs = [
  { value: alert.data?.srcip, source: "data.srcip" },
  { value: alert.data?.dstip, source: "data.dstip" },
  { value: alert.data?.win?.eventdata?.destinationIp, source: "win.eventdata.destinationIp" },
  { value: alert.data?.win?.eventdata?.sourceIp, source: "win.eventdata.sourceIp" },
];

for (const item of candidateIPs) {
  if (item.value && isIPv4(String(item.value)) && !isPrivateOrLocalIP(String(item.value))) {
    pushIOC(iocs, "ip", item.value, item.source);
  }
}

// Domains
const structuredDomains = [
  { value: alert.data?.hostname, source: "data.hostname" },
  { value: alert.data?.win?.eventdata?.queryName, source: "win.eventdata.queryName" },
  { value: alert.data?.win?.eventdata?.destinationHostname, source: "win.eventdata.destinationHostname" },
];

for (const item of structuredDomains) {
  const d = normalizeDomain(item.value);
  if (d && d.includes(".")) pushIOC(iocs, "domain", d, item.source);
}

// URLs
const structuredUrls = [
  { value: alert.data?.url, source: "data.url" },
  { value: alert.data?.win?.eventdata?.targetUrl, source: "win.eventdata.targetUrl" },
  { value: alert.data?.win?.eventdata?.url, source: "win.eventdata.url" },
  { value: alert.data?.win?.eventdata?.destinationUrl, source: "win.eventdata.destinationUrl" },
  { value: alert.data?.win?.eventdata?.requestUrl, source: "win.eventdata.requestUrl" },
];

for (const item of structuredUrls) {
  if (!item.value) continue;
  const u = cleanUrl(item.value);
  pushIOC(iocs, "url", u, item.source);
  const host = getHostFromUrl(u);
  if (!host) continue;
  pushDerivedHostIOC(iocs, host, `derived_from_${item.source}_url`);
}

// Free Text Sources
const freeTextSources = [
  { value: alert.data?.win?.eventdata?.commandLine, source: "win.eventdata.commandLine" },
  { value: alert.data?.win?.eventdata?.parentCommandLine, source: "win.eventdata.parentCommandLine" },
];

const urlRegex = /\bhttps?:\/\/(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::\d{1,5})?(?:\/[^\s"'<>\\]*)?/gi;
const extractedUrlHosts = [];

for (const item of freeTextSources) {
  if (!item.value || typeof item.value !== "string") continue;
  const matches = item.value.match(urlRegex);
  if (!matches) continue;
  for (let match of matches) {
    const u = cleanUrl(match);
    pushIOC(iocs, "url", u, item.source);
    const host = getHostFromUrl(u);
    if (!host) continue;
    extractedUrlHosts.push(host);
    pushDerivedHostIOC(iocs, host, `derived_from_${item.source}_url`);
  }
}

for (const item of freeTextSources) {
  if (!item.value || typeof item.value !== "string") continue;
  const ips = extractIPsFromText(item.value);
  for (const ip of ips) {
    if (!isPrivateOrLocalIP(ip)) {
      pushIOC(iocs, "ip", ip, item.source);
    }
  }
}

const domainTextSources = [
  { value: alert.data?.win?.eventdata?.commandLine, source: "win.eventdata.commandLine" },
  { value: alert.data?.win?.eventdata?.parentCommandLine, source: "win.eventdata.parentCommandLine" },
  { value: alert.full_log, source: "full_log" },
];

for (const item of domainTextSources) {
  const domains = extractDomainsFromText(item.value, extractedUrlHosts);
  for (const d of domains) {
    pushIOC(iocs, "domain", d, item.source);
  }
}

const priority = ["sha256", "md5", "sha1", "url", "domain", "ip"];
let primary = null;
for (const p of priority) {
  const found = iocs.find(i => i.type === p);
  if (found) {
    primary = found;
    break;
  }
}


return [{
  json: {
    alert_id: alert.id || null,
    timestamp: alert.timestamp || null,

    agent_name: alert.agent?.name || "N/A",
    agent_id: alert.agent?.id || "N/A",
    agent_ip: alert.agent?.ip || null,

    rule_id: alert.rule?.id || null,
    rule_level: ruleLevel,
    rule_description: alert.rule?.description || "N/A",
    severity_label: mapSeverity(ruleLevel),

    decoder_name: alert.decoder?.name || null,
    location: alert.location || null,
    full_log: alert.full_log || "",

    process_name: alert.data?.win?.eventdata?.image || null,
    command_line: alert.data?.win?.eventdata?.commandLine || null,
    parent_process: alert.data?.win?.eventdata?.parentImage || null,
    parent_command_line: alert.data?.win?.eventdata?.parentCommandLine || null,

    path: alert.syscheck?.path || null,
    event_action: alert.syscheck?.event || null,
    value_name: alert.syscheck?.value_name || null,

    iocs,
    ioc_count: iocs.length,
    primary_ioc_type: primary?.type || null,
    primary_ioc_value: primary?.value || null,
    primary_ioc_source: primary?.source || null,

    should_search_misp: iocs.length > 0,
    should_create_alert: ruleLevel >= 7 || iocs.length > 0,

    webhook_url: root.webhookUrl || null,
    execution_mode: root.executionMode || null,

    raw_alert: alert
  }
}];