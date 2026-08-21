// n8n Code node: Build TheHive Alert Payload

const item = $json;

const matches = Array.isArray(item.matches) ? item.matches : [];
const iocs = Array.isArray(item.iocs)
  ? item.iocs
  : (item.iocs && typeof item.iocs === "object" ? [item.iocs] : []);

function splitTags(tagString) {
  if (!tagString) return [];
  if (Array.isArray(tagString)) return tagString.filter(Boolean);
  return String(tagString)
    .split(",")
    .map(t => t.trim())
    .filter(Boolean);
}

function normalizeObservableFromIOC(ioc) {
  if (!ioc || !ioc.type || !ioc.value) return null;

  const t = String(ioc.type).toLowerCase();
  const v = String(ioc.value).trim();
  if (!v) return null;

  if (t === "ip") {
    return {
      key: `ip:${v}`,
      dataType: "ip",
      data: v,
      messages: [`Extracted from Wazuh (${ioc.source || "unknown source"})`],
      tags: ["source:wazuh"]
    };
  }

  if (t === "domain") {
    return {
      key: `domain:${v}`,
      dataType: "domain",
      data: v,
      messages: [`Extracted from Wazuh (${ioc.source || "unknown source"})`],
      tags: ["source:wazuh"]
    };
  }

  if (t === "url") {
    return {
      key: `url:${v}`,
      dataType: "url",
      data: v,
      messages: [`Extracted from Wazuh (${ioc.source || "unknown source"})`],
      tags: ["source:wazuh"]
    };
  }

  if (t === "sha256" || t === "sha1" || t === "md5") {
    return {
      key: `hash:${v}`,
      dataType: "hash",
      data: v,
      messages: [`Extracted from Wazuh (${t})`],
      tags: ["source:wazuh", `hash:${t}`]
    };
  }

  return null;
}

function normalizeObservableFromMatch(match) {
  if (!match || !match.matched_ioc_value || !match.matched_ioc_type) return null;

  const t = String(match.matched_ioc_type).toLowerCase();
  const raw = String(match.matched_ioc_value).trim();
  if (!raw) return null;

  if (t.includes("ip")) {
    const ip = raw.includes("|") ? raw.split("|")[0].trim() : raw;

    return {
      key: `ip:${ip}`,
      dataType: "ip",
      data: ip,
      messages: [
        [
          match.matched_ioc_comment,
          match.matched_event_info,
          raw !== ip ? `raw:${raw}` : null
        ].filter(Boolean).join(" | ")
      ],
      tags: [
        "source:misp",
        match.matched_tag,
        match.matched_event_info
      ].filter(Boolean)
    };
  }

  if (t.includes("domain") || t.includes("hostname")) {
    return {
      key: `domain:${raw}`,
      dataType: "domain",
      data: raw,
      messages: [[match.matched_ioc_comment, match.matched_event_info].filter(Boolean).join(" | ")],
      tags: ["source:misp", match.matched_tag, match.matched_event_info].filter(Boolean)
    };
  }

  if (t.includes("url")) {
    return {
      key: `url:${raw}`,
      dataType: "url",
      data: raw,
      messages: [[match.matched_ioc_comment, match.matched_event_info].filter(Boolean).join(" | ")],
      tags: ["source:misp", match.matched_tag, match.matched_event_info].filter(Boolean)
    };
  }

  if (t.includes("sha256") || t.includes("sha1") || t.includes("md5")) {
    return {
      key: `hash:${raw}`,
      dataType: "hash",
      data: raw,
      messages: [[match.matched_ioc_comment, match.matched_event_info].filter(Boolean).join(" | ")],
      tags: ["source:misp", match.matched_tag, match.matched_event_info, `hash:${t}`].filter(Boolean)
    };
  }

  return null;
}

const observableMap = new Map();

function upsertObservable(obs) {
  if (!obs) return;

  if (!observableMap.has(obs.key)) {
    observableMap.set(obs.key, {
      dataType: obs.dataType,
      data: obs.data,
      messages: [...new Set(obs.messages || [])],
      tags: [...new Set(obs.tags || [])]
    });
    return;
  }

  const existing = observableMap.get(obs.key);
  existing.messages = [...new Set([...(existing.messages || []), ...(obs.messages || [])])];
  existing.tags = [...new Set([...(existing.tags || []), ...(obs.tags || [])])];
  observableMap.set(obs.key, existing);
}

for (const ioc of iocs) {
  upsertObservable(normalizeObservableFromIOC(ioc));
}

for (const match of matches) {
  upsertObservable(normalizeObservableFromMatch(match));
}

const observables = Array.from(observableMap.values()).map(obs => ({
  dataType: obs.dataType,
  data: obs.data,
  message: obs.messages.join(" || "),
  tags: obs.tags.join(",")
}));

const isMispPath = (item.match_count || 0) > 0;
const isSeverityPath = !isMispPath && Number(item.rule_level || 0) >= 12;

const tags = [
  "source:wazuh",
  "workflow:n8n",
  `rule:${item.rule_id || "unknown"}`,
  `severity:${item.severity_label || "unknown"}`,
  `decoder:${item.decoder_name || "unknown"}`
];

if (isMispPath) {
  tags.push("source:misp", "misp-match");
}

if (isSeverityPath) {
  tags.push("high-severity", "severity-threshold:12");
}

for (const m of matches) {
  if (m.matched_tag) tags.push(`malware:${m.matched_tag}`);
}

const uniqueTags = [...new Set(tags)];

const lines = [];
lines.push(
  isMispPath
    ? "Wazuh alert enriched by MISP."
    : "High severity Wazuh alert escalated automatically."
);
lines.push("");
lines.push(`Agent: ${item.agent_name || "N/A"} (${item.agent_ip || "N/A"})`);
lines.push(`Rule ID: ${item.rule_id || "N/A"}`);
lines.push(`Rule Level: ${item.rule_level ?? "N/A"}`);
lines.push(`Rule: ${item.rule_description || "N/A"}`);
lines.push(`Severity: ${item.severity_label || "N/A"}`);
lines.push(`Decoder: ${item.decoder_name || "N/A"}`);
lines.push(`Location: ${item.location || "N/A"}`);
lines.push(`Path: ${item.path || "N/A"}`);
lines.push(`Event Action: ${item.event_action || "N/A"}`);
lines.push(`MISP Matches Count: ${item.match_count || 0}`);
lines.push(`Unique Observables Count: ${observables.length}`);
lines.push("");

if (matches.length > 0) {
  lines.push("Matched observables:");
  matches.forEach((m, idx) => {
    lines.push(`${idx + 1}. ${m.matched_ioc_value || "N/A"} | ${m.matched_ioc_type || "N/A"} | ${m.matched_tag || "N/A"} | ${m.matched_event_info || "N/A"}`);
  });
  lines.push("");
}

if (iocs.length > 0) {
  lines.push("Extracted IOCs:");
  iocs.forEach((ioc, idx) => {
    lines.push(`${idx + 1}. ${ioc.value || "N/A"} | ${ioc.type || "N/A"} | ${ioc.source || "N/A"}`);
  });
  lines.push("");
}

lines.push("Original log:");
lines.push(item.full_log || "N/A");

const titlePrefix = isMispPath ? "MISP Match" : "High Severity Alert";

// =========================================================================
// التعديل الجديد: توليد بصمة فريدة تمنع التكرار في نفس الدقيقة (Deduplication)
// =========================================================================
const safeTime = (item.timestamp || "").substring(0, 16).replace(/:/g, "-");
const primaryIoc = item.primary_ioc_value || item.rule_id || "Alert";
const customSourceRef = `${item.agent_name || "NA"}-${primaryIoc}-${safeTime}`;
// =========================================================================

return [{
  json: {
    ...item,
    thehive_title: `${titlePrefix} | ${item.agent_name || "N/A"} | Rule ${item.rule_id || "N/A"} | ${observables.length} unique observables`,
    thehive_description: lines.join("\n"),
    thehive_tags: uniqueTags,
    thehive_observables: observables,
    thehive_source_ref: customSourceRef // تمرير البصمة الجاهزة للخطوة التالية
  }
}];