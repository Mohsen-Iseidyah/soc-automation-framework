// n8n Code node: Build High Severity Alert Payload

const item = $json;

const tags = [
  "source:wazuh",
  "workflow:n8n",
  "high-severity",
  `rule:${item.rule_id || "unknown"}`,
  `severity:${item.severity_label || "unknown"}`,
  `decoder:${item.decoder_name || "unknown"}`
];

const lines = [];
lines.push("Critical Wazuh alert (rule level >= 12) escalated automatically.");
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
lines.push(`Primary IOC Type: ${item.primary_ioc_type || "N/A"}`);
lines.push(`Primary IOC Value: ${item.primary_ioc_value || "N/A"}`);
lines.push("");
lines.push("Original log:");
lines.push(item.full_log || "N/A");

return [{
  json: {
    ...item,
    thehive_title: `High Severity Alert | ${item.agent_name || "N/A"} | Rule ${item.rule_id || "N/A"} | Level ${item.rule_level ?? "N/A"}`,
    thehive_description: lines.join("\n"),
    thehive_tags: [...new Set(tags)]
  }
}];