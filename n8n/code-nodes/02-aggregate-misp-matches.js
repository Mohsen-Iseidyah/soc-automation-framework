// n8n Code node: Aggregate MISP Matches & Rebuild IOC Context

const items = $input.all().map(i => i.json);

if (items.length === 0) {
  return [];
}

// عنصر السياق العام
const contextItem =
  items.find(item =>
    item.alert_id ||
    item.rule_id ||
    item.agent_name ||
    item.full_log
  ) || items[0];

// اجمع كل IOCs القادمة من Wazuh من كل العناصر
const allIocs = [];
const iocSeen = new Set();

function pushIOC(type, value, source) {
  if (!type || !value) return;
  const t = String(type).trim().toLowerCase();
  const v = String(value).trim();
  const s = source ? String(source).trim() : null;
  if (!t || !v) return;

  const key = `${t}:${v}`;
  if (iocSeen.has(key)) return;
  iocSeen.add(key);

  allIocs.push({
    type: t,
    value: v,
    source: s
  });
}

for (const item of items) {
  // إذا iocs مصفوفة
  if (Array.isArray(item.iocs)) {
    for (const ioc of item.iocs) {
      pushIOC(ioc?.type, ioc?.value, ioc?.source);
    }
  }
  // إذا iocs object واحد
  else if (item.iocs && typeof item.iocs === "object") {
    pushIOC(item.iocs.type, item.iocs.value, item.iocs.source);
  }

  // احتياط: لو الـ Split Out جعل الـ IOC نفسها في الحقول المباشرة
  if (item.type && item.value && item.source && !item.alert_id) {
    pushIOC(item.type, item.value, item.source);
  }
}

// اجمع فقط نتائج MISP الحقيقية
const mispItems = items.filter(item =>
  item &&
  (
    item.value ||
    item.type ||
    item.comment ||
    item.Event?.info ||
    item.Tag?.[0]?.name
  )
);

const matches = mispItems.map(item => ({
  matched_ioc_value: item.value || null,
  matched_ioc_type: item.type || null,
  matched_ioc_comment: item.comment || null,
  matched_event_info: item.Event?.info || null,
  matched_tag: item.Tag?.[0]?.name || null,
  to_ids: item.to_ids ?? null
}));

const originalTimestamp =
  contextItem.raw_alert?.timestamp ||
  contextItem.timestamp ||
  null;

const ruleLevel = Number(contextItem.rule_level || 0);
const hasMispMatch = matches.length > 0;
const highSeverity = ruleLevel >= 12;

let alert_reason = "none";
if (hasMispMatch) {
  alert_reason = "misp";
} else if (highSeverity) {
  alert_reason = "severity";
}

return [{
  json: {
    ...contextItem,
    timestamp: originalTimestamp,
    iocs: allIocs,
    ioc_count: allIocs.length,
    match_count: matches.length,
    matches,
    has_misp_match: hasMispMatch,
    high_severity: highSeverity,
    alert_reason
  }
}];