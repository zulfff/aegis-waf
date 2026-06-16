use crate::config::AegisConfig;
use crate::error::{AegisError, Result};
use crate::metrics::METRICS;
use hyper::header::{
    ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_SECURITY_POLICY, CONTENT_TYPE, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS, X_XSS_PROTECTION,
};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::convert::Infallible;
use std::net::SocketAddr;

pub struct Dashboard {
    #[allow(dead_code)]
    config: AegisConfig,
}

fn security_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (ACCESS_CONTROL_ALLOW_ORIGIN.as_str(), "*"),
        (X_CONTENT_TYPE_OPTIONS.as_str(), "nosniff"),
        (X_FRAME_OPTIONS.as_str(), "DENY"),
        (X_XSS_PROTECTION.as_str(), "1; mode=block"),
        (
            CONTENT_SECURITY_POLICY.as_str(),
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
        ),
        (
            STRICT_TRANSPORT_SECURITY.as_str(),
            "max-age=31536000; includeSubDomains",
        ),
    ]
}

fn json_response(body: String) -> Response<Body> {
    let mut resp = Response::new(Body::from(body));
    resp.headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().unwrap());
    for (key, value) in security_headers() {
        resp.headers_mut().insert(
            hyper::header::HeaderName::from_static(key),
            value.parse().unwrap(),
        );
    }
    resp
}

fn html_response(body: String) -> Response<Body> {
    let mut resp = Response::new(Body::from(body));
    resp.headers_mut()
        .insert(CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());
    for (key, value) in security_headers() {
        resp.headers_mut().insert(
            hyper::header::HeaderName::from_static(key),
            value.parse().unwrap(),
        );
    }
    resp
}

fn not_found() -> Response<Body> {
    let mut resp = Response::new(Body::from(r#"{"error": "Not Found"}"#));
    *resp.status_mut() = StatusCode::NOT_FOUND;
    resp.headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().unwrap());
    for (key, value) in security_headers() {
        resp.headers_mut().insert(
            hyper::header::HeaderName::from_static(key),
            value.parse().unwrap(),
        );
    }
    resp
}

fn handle_api_route(path: &str) -> Option<Response<Body>> {
    match path {
        "/api/status" => {
            let status = serde_json::json!({
                "system": "aegis-waf",
                "version": env!("CARGO_PKG_VERSION"),
                "status": "operational",
                "protection": "active",
                "uptime_seconds": METRICS.get_uptime_secs(),
                "requests_total": METRICS.get_requests_per_sec() as u64,
                "attacks_blocked": METRICS.get_attacks_blocked(),
                "active_connections": METRICS.get_active_connections(),
                "bytes_processed": METRICS.get_bytes_processed(),
                "threat_level": compute_threat_level(),
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            Some(json_response(
                serde_json::to_string_pretty(&status).unwrap(),
            ))
        }
        "/api/attack-stats" => {
            let stats = METRICS.get_attack_stats();
            let result = serde_json::json!({
                "total_attacks": METRICS.get_attacks_blocked(),
                "by_type": stats,
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            Some(json_response(
                serde_json::to_string_pretty(&result).unwrap(),
            ))
        }
        "/api/connection-stats" => {
            let result = serde_json::json!({
                "active": METRICS.get_active_connections(),
                "total_requests": METRICS.get_requests_per_sec() as u64,
                "bytes_processed": METRICS.get_bytes_processed(),
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            Some(json_response(
                serde_json::to_string_pretty(&result).unwrap(),
            ))
        }
        "/api/violations" => {
            let violations = METRICS.get_violations();
            let result = serde_json::json!({
                "count": violations.len(),
                "violations": violations,
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            Some(json_response(
                serde_json::to_string_pretty(&result).unwrap(),
            ))
        }
        "/metrics" => {
            let metrics = serde_json::json!({
                "aegis_waf_requests_total": METRICS.get_requests_per_sec() as u64,
                "aegis_waf_attacks_blocked_total": METRICS.get_attacks_blocked(),
                "aegis_waf_active_connections": METRICS.get_active_connections(),
                "aegis_waf_bytes_processed_total": METRICS.get_bytes_processed(),
                "aegis_waf_uptime_seconds": METRICS.get_uptime_secs()
            });
            Some(json_response(
                serde_json::to_string_pretty(&metrics).unwrap(),
            ))
        }
        _ => None,
    }
}

fn compute_threat_level() -> &'static str {
    let attacks = METRICS.get_attacks_blocked();
    if attacks > 1000 {
        "critical"
    } else if attacks > 500 {
        "high"
    } else if attacks > 100 {
        "elevated"
    } else if attacks > 10 {
        "moderate"
    } else {
        "low"
    }
}

fn get_threat_level_class() -> &'static str {
    match compute_threat_level() {
        "critical" => "threat-critical",
        "high" => "threat-high",
        "elevated" => "threat-elevated",
        "moderate" => "threat-moderate",
        _ => "threat-low",
    }
}

fn dashboard_html() -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aegis WAF - Security Dashboard</title>
<style>
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}}
  .header{{background:#161b22;border-bottom:1px solid #21262d;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100}}
  .header h1{{font-size:1.4rem;font-weight:600;color:#58a6ff;letter-spacing:0.5px}}
  .header h1 span{{color:#f78166}}
  .header-right{{display:flex;align-items:center;gap:16px}}
  .threat-badge{{padding:6px 16px;border-radius:20px;font-size:0.8rem;font-weight:700;text-transform:uppercase;letter-spacing:1px}}
  .threat-critical{{background:#da3633;color:#fff;animation:pulse 2s infinite}}
  .threat-high{{background:#d29922;color:#000}}
  .threat-elevated{{background:#d29922;color:#000;opacity:0.8}}
  .threat-moderate{{background:#238636;color:#fff}}
  .threat-low{{background:#1f6feb;color:#fff}}
  @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:0.7}}}}
  .uptime{{font-size:0.8rem;color:#8b949e}}
  .container{{max-width:1400px;margin:0 auto;padding:24px}}
  .stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:24px}}
  .stat-card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;transition:border-color 0.2s}}
  .stat-card:hover{{border-color:#30363d}}
  .stat-card .label{{font-size:0.75rem;text-transform:uppercase;letter-spacing:1px;color:#8b949e;margin-bottom:8px}}
  .stat-card .value{{font-size:2rem;font-weight:700;color:#58a6ff;line-height:1.2}}
  .stat-card .sub{{font-size:0.8rem;color:#8b949e;margin-top:4px}}
  .stat-attacks .value{{color:#f78166}}
  .stat-connections .value{{color:#3fb950}}
  .main-grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:24px}}
  @media(max-width:900px){{.main-grid{{grid-template-columns:1fr}}}}
  .panel{{background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden}}
  .panel-header{{background:#1c2128;padding:14px 20px;border-bottom:1px solid #21262d;display:flex;justify-content:space-between;align-items:center}}
  .panel-header h3{{font-size:0.9rem;font-weight:600;color:#c9d1d9}}
  .panel-header .badge{{font-size:0.7rem;padding:3px 10px;border-radius:12px;background:#238636;color:#fff}}
  .panel-body{{padding:20px;max-height:400px;overflow-y:auto}}
  .module-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}}
  .module-card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;text-align:center}}
  .module-card .mod-name{{font-size:0.85rem;font-weight:600;margin-bottom:8px}}
  .module-card .mod-status{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}}
  .mod-active{{background:#3fb950;box-shadow:0 0 8px #3fb95088}}
  .mod-warning{{background:#d29922;box-shadow:0 0 8px #d2992288}}
  .mod-error{{background:#da3633;box-shadow:0 0 8px #da363388}}
  table{{width:100%;border-collapse:collapse;font-size:0.82rem}}
  th{{text-align:left;padding:10px 12px;border-bottom:1px solid #21262d;color:#8b949e;font-weight:500;text-transform:uppercase;font-size:0.7rem;letter-spacing:0.5px}}
  td{{padding:10px 12px;border-bottom:1px solid #21262d22}}
  tr:hover{{background:#1c2128}}
  .sev-critical{{color:#da3633;font-weight:600}}
  .sev-high{{color:#d29922;font-weight:600}}
  .sev-medium{{color:#d29922}}
  .sev-low{{color:#8b949e}}
  .chart-placeholder{{height:200px;display:flex;align-items:flex-end;gap:4px;padding:10px 0}}
  .bar{{flex:1;background:#238636;border-radius:4px 4px 0 0;min-height:4px;transition:height 0.3s;position:relative}}
  .bar:hover{{filter:brightness(1.3)}}
  .bar-label{{position:absolute;bottom:-20px;left:50%;transform:translateX(-50%);font-size:0.6rem;color:#8b949e;white-space:nowrap}}
  .footer{{text-align:center;padding:20px;color:#484f58;font-size:0.75rem;border-top:1px solid #21262d;margin-top:24px}}
  .footer span{{color:#58a6ff}}
  .refresh-indicator{{font-size:0.7rem;color:#8b949e}}
  ::-webkit-scrollbar{{width:8px}}
  ::-webkit-scrollbar-track{{background:#0d1117}}
  ::-webkit-scrollbar-thumb{{background:#30363d;border-radius:4px}}
</style>
</head>
<body>
<div class="header">
  <h1>&#x1f6e1; AEGIS<span>WAF</span></h1>
  <div class="header-right">
    <span class="threat-badge {}" id="threatBadge">THREAT: {}</span>
    <span class="uptime" id="uptimeDisplay">Uptime: 0s</span>
  </div>
</div>
<div class="container">
  <div class="stats-grid">
    <div class="stat-card">
      <div class="label">Requests/sec</div>
      <div class="value" id="reqSec">0</div>
      <div class="sub">Total: <span id="reqTotal">0</span></div>
    </div>
    <div class="stat-card stat-attacks">
      <div class="label">Attacks Blocked</div>
      <div class="value" id="attBlocked">0</div>
      <div class="sub">Threat: <span id="threatLvl">{}</span></div>
    </div>
    <div class="stat-card stat-connections">
      <div class="label">Active Connections</div>
      <div class="value" id="actConns">0</div>
      <div class="sub">Bytes: <span id="bytesProc">0</span></div>
    </div>
    <div class="stat-card">
      <div class="label">CPU / Memory</div>
      <div class="value" id="cpuMem">--</div>
      <div class="sub">System Load: <span id="sysLoad">--</span></div>
    </div>
  </div>

  <div class="main-grid">
    <div class="panel">
      <div class="panel-header"><h3>Attack Timeline</h3><span class="badge" id="attackCount">0 attacks</span></div>
      <div class="panel-body">
        <div class="chart-placeholder" id="attackChart"></div>
        <table><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Source</th><th>Action</th></tr></thead>
        <tbody id="attackTableBody"><tr><td colspan="5" style="text-align:center;color:#8b949e">No attacks recorded</td></tr></tbody></table>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><h3>Recent Violations</h3><span class="badge" id="violCount">0</span></div>
      <div class="panel-body">
        <table><thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Source</th><th>Details</th></tr></thead>
        <tbody id="violTableBody"><tr><td colspan="5" style="text-align:center;color:#8b949e">No violations recorded</td></tr></tbody></table>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header"><h3>Module Status</h3></div>
    <div class="panel-body">
      <div class="module-grid" id="moduleGrid">
        <div class="module-card"><div class="mod-name">Rate Limiter</div><span class="mod-status mod-active"></span> Active</div>
        <div class="module-card"><div class="mod-name">IP Reputation</div><span class="mod-status mod-active"></span> Active</div>
        <div class="module-card"><div class="mod-name">SQL Injection</div><span class="mod-status mod-active"></span> Active</div>
        <div class="module-card"><div class="mod-name">XSS Filter</div><span class="mod-status mod-active"></span> Active</div>
        <div class="module-card"><div class="mod-name">Geo Block</div><span class="mod-status mod-active"></span> Active</div>
        <div class="module-card"><div class="mod-name">DDoS Shield</div><span class="mod-status mod-active"></span> Active</div>
        <div class="module-card"><div class="mod-name">Bot Detection</div><span class="mod-status mod-active"></span> Active</div>
        <div class="module-card"><div class="mod-name">WAF Engine</div><span class="mod-status mod-active"></span> Active</div>
      </div>
    </div>
  </div>
</div>
<div class="footer">
  &#x1f6e1; Aegis WAF v<span>{}</span> | Protection Active | <span id="footerUptime">Uptime: 0s</span>
</div>
<script>
(function(){{

  function formatBytes(b){{if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB'}}

  function formatUptime(s){{var d=Math.floor(s/86400);var h=Math.floor((s%86400)/3600);var m=Math.floor((s%3600)/60);var sec=s%60;var p=[];if(d>0)p.push(d+'d');if(h>0)p.push(h+'h');if(m>0)p.push(m+'m');p.push(sec+'s');return p.join(' ')}}

  function sevClass(s){{s=s.toLowerCase();if(s==='critical')return'sev-critical';if(s==='high')return'sev-high';if(s==='medium')return'sev-medium';return'sev-low'}}

  function threatClass(l){{return'threat-'+l}}

  var maxBars=20;
  var attackHistory=[];
  var reqDelta=0;

  function updateAttackChart(attacks){{var chart=document.getElementById('attackChart');if(!attacks||attacks.length===0){{chart.innerHTML='<div style="color:#8b949e;text-align:center;width:100%">No attack data</div>';return}}
    var recent=attacks.slice(-maxBars);
    var maxCount=0;
    var typeMap={{}};
    recent.forEach(function(a){{var k=a.attack_type;typeMap[k]=(typeMap[k]||0)+1;if(typeMap[k]>maxCount)maxCount=typeMap[k]}});
    var html='';
    var keys=Object.keys(typeMap);
    keys.forEach(function(k){{var h=Math.max(4,(typeMap[k]/Math.max(maxCount,1))*180);html+='<div class="bar" style="height:'+h+'px" title="'+k+': '+typeMap[k]+'"><span class="bar-label">'+k.substring(0,8)+'</span></div>'}});
    if(html==='')html='<div style="color:#8b949e;text-align:center;width:100%">No attack data</div>';
    chart.innerHTML=html;
  }}

  function renderAttackTable(attacks){{var tb=document.getElementById('attackTableBody');document.getElementById('attackCount').textContent=attacks.length+' attacks';
    attackHistory=attacks;
    if(attacks.length===0){{tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:#8b949e">No attacks recorded</td></tr>';return}}
    var latest=attacks.slice(-15).reverse();
    tb.innerHTML=latest.map(function(a){{return'<tr><td>'+a.timestamp+'</td><td>'+a.attack_type+'</td><td class="'+sevClass(a.severity)+'">'+a.severity+'</td><td>'+a.source_ip+'</td><td>'+a.action+'</td></tr>'}}).join('');
  }}

  function renderViolations(viols){{var tb=document.getElementById('violTableBody');document.getElementById('violCount').textContent=viols.length;
    if(viols.length===0){{tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:#8b949e">No violations recorded</td></tr>';return}}
    var latest=viols.slice(-20).reverse();
    tb.innerHTML=latest.map(function(v){{return'<tr><td>'+v.timestamp+'</td><td>'+v.attack_type+'</td><td class="'+sevClass(v.severity)+'">'+v.severity+'</td><td>'+v.source_ip+'</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+v.details+'">'+v.details+'</td></tr>'}}).join('');
  }}

  function updateStats(status){{document.getElementById('reqSec').textContent=status.requests_per_sec||'--';
    document.getElementById('reqTotal').textContent=status.requests_per_sec||'0';
    document.getElementById('attBlocked').textContent=status.attacks_blocked||'0';
    document.getElementById('actConns').textContent=status.active_connections||'0';
    document.getElementById('bytesProc').textContent=formatBytes(status.bytes_processed||0);
    document.getElementById('threatLvl').textContent=status.threat_level||'low';
    var badge=document.getElementById('threatBadge');
    badge.textContent='THREAT: '+(status.threat_level||'low').toUpperCase();
    badge.className='threat-badge '+threatClass(status.threat_level||'low');
    document.getElementById('uptimeDisplay').textContent='Uptime: '+formatUptime(status.uptime_seconds||0);
    document.getElementById('footerUptime').textContent='Uptime: '+formatUptime(status.uptime_seconds||0);
    document.getElementById('cpuMem').textContent='--';
    document.getElementById('sysLoad').textContent='--';
  }}

  function fetchAll(){{fetch('/api/status').then(function(r){{return r.json()}}).then(function(d){{updateStats(d)}}).catch(function(){{}});
    fetch('/api/attack-stats').then(function(r){{return r.json()}}).then(function(d){{renderAttackTable(d.by_type||[])}}).catch(function(){{}});
    fetch('/api/violations').then(function(r){{return r.json()}}).then(function(d){{renderViolations(d.violations||[]);updateAttackChart(d.violations||[])}}).catch(function(){{}});
  }}

  fetchAll();
  setInterval(fetchAll,5000);
}})();
</script>
</body>
</html>"#,
        get_threat_level_class(),
        compute_threat_level().to_uppercase(),
        compute_threat_level(),
        env!("CARGO_PKG_VERSION"),
    )
}

async fn handle_request(req: Request<Body>) -> Result<Response<Body>> {
    let path = req.uri().path().to_string();

    match (req.method(), path.as_str()) {
        (&Method::GET, "/") => Ok(html_response(dashboard_html())),
        (&Method::GET, path) if path.starts_with("/api/") => {
            Ok(handle_api_route(path).unwrap_or_else(not_found))
        }
        (&Method::GET, "/metrics") => Ok(handle_api_route("/metrics").unwrap_or_else(not_found)),
        _ => Ok(not_found()),
    }
}

pub async fn start_dashboard(config: &AegisConfig) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", "0.0.0.0", config.dashboard.port)
        .parse()
        .map_err(|e| AegisError::Server(format!("Invalid bind address: {}", e)))?;

    tracing::info!("Dashboard starting on http://{}", addr);

    let make_svc =
        make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle_request)) });

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        return Err(AegisError::Server(format!("Dashboard server error: {}", e)));
    }

    Ok(())
}
