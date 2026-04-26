// =============== Cloudflare Manager - 完整版 ===============
// 支持多账号管理、批量创建、域名管理

export default {
  async fetch(request, env, ctx) {
    return await handleRequest(request, env);
  }
};

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';

// ---------------- Router ----------------
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const p = url.pathname;

  if (p === '/static.js' && request.method === 'GET') {
    return new Response(renderStaticJS(env), { 
      headers: { 
        'content-type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate'
      } 
    });
  }

  if (request.method === 'GET' && (p === '/' || p === '/index.html')) {
    return Response.redirect(`${url.origin}/login`, 302);
  }
  if (request.method === 'GET' && (p === '/login' || p === '/login/')) {
    return new Response(renderLoginHTML(), { headers: { 'content-type': 'text/html; charset=utf-8' } });
  }
  if (request.method === 'GET' && p.startsWith('/workers')) {
    return new Response(renderAppHTML(), { headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  if (p === '/api' && request.method === 'POST') {
    return handleAPI(request, env);
  }

  return new Response('Not Found', { status: 404 });
}

// ---------------- API handler ----------------
async function handleAPI(req, env) {
  const payload = await safeJSON(req);
  const action = payload.action;
  if (!action) return json({ success: false, error: 'action required' }, 400);

  // 账号存储
  const ACCOUNTS_KEY = 'cf_accounts';

  // 获取账号列表
  if (action === 'get-accounts') {
    const accounts = await env.MY_KV?.get(ACCOUNTS_KEY, 'json') || [];
    return json({ success: true, accounts: accounts.map(a => ({ email: a.email, alias: a.alias || a.email })) });
  }

  // 保存账号
  if (action === 'save-account') {
    const { email, key, alias } = payload;
    if (!email || !key) return json({ success: false, error: '缺少必要参数' }, 400);
    
    let accounts = await env.MY_KV?.get(ACCOUNTS_KEY, 'json') || [];
    const existingIndex = accounts.findIndex(a => a.email === email);
    const account = { email, key, alias: alias || email, updatedAt: Date.now() };
    
    if (existingIndex >= 0) {
      accounts[existingIndex] = account;
    } else {
      accounts.push(account);
    }
    
    await env.MY_KV?.put(ACCOUNTS_KEY, JSON.stringify(accounts));
    return json({ success: true, message: '账号保存成功' });
  }

  // 删除账号
  if (action === 'delete-account') {
    const { email } = payload;
    let accounts = await env.MY_KV?.get(ACCOUNTS_KEY, 'json') || [];
    accounts = accounts.filter(a => a.email !== email);
    await env.MY_KV?.put(ACCOUNTS_KEY, JSON.stringify(accounts));
    return json({ success: true });
  }

  // 验证凭据
  if (action === 'validate-credentials') {
    const { email, key } = payload;
    const r = await cfAny('GET', '/accounts', email, key);
    if (!r.success && !r.result) {
      return json({ success: false, error: r.errors?.[0]?.message || '验证失败' });
    }
    return json({ success: true, result: r.result });
  }

  // 获取单个账号的账户ID
  if (action === 'get-account-id') {
    const { email, key } = payload;
    try {
      const r = await cfAny('GET', '/accounts', email, key);
      if (r.success && r.result && r.result.length > 0) {
        return json({ success: true, accountId: r.result[0].id });
      }
      return json({ success: false, error: '无法获取账户ID' });
    } catch (e) {
      return json({ success: false, error: e.message });
    }
  }

  // 获取脚本内容
  if (action === 'fetch-external-script') {
    const { url } = payload;
    if (!url) return json({ success: false, error: 'url required' });
    try {
      const resp = await fetch(url, { headers: { 'User-Agent': 'CF-Worker-Manager' } });
      if (!resp.ok) return json({ success: false, error: 'Fetch failed: ' + resp.status });
      const text = await resp.text();
      return json({ success: true, content: text });
    } catch (e) {
      return json({ success: false, error: e.message });
    }
  }

  // 需要 Cloudflare 凭据的操作
  const needsCreds = new Set([
    'list-accounts', 'list-workers', 'get-worker-script', 'deploy-worker',
    'list-kv-namespaces', 'list-d1', 'put-worker-variables', 'get-worker-variables',
    'get-workers-subdomain', 'put-workers-subdomain', 'delete-worker',
    'create-kv-namespace', 'delete-kv-namespace', 'put-kv-value', 'get-kv-value', 'delete-kv-value',
    'list-kv-keys', 'create-d1-database', 'delete-d1-database', 'execute-d1-query',
    'list-zones', 'create-zone', 'delete-zone', 'list-dns-records', 'create-dns-record',
    'delete-dns-record', 'update-dns-record', 'toggle-worker-subdomain', 'add-worker-domain',
    'delete-worker-domain', 'get-worker-analytics', 'get-usage-today'
  ]);

  if (needsCreds.has(action)) {
    if (!payload.email || !payload.key) {
      return json({ success: false, error: 'email & key required' }, 400);
    }
  }

  try {
    switch(action) {
      case 'list-accounts':
        return json(await cfGet('/accounts', payload.email, payload.key));

      case 'list-workers': {
        if (!payload.accountId) return json({ success: false, error: 'accountId required' }, 400);
        const result = await cfGet(`/accounts/${payload.accountId}/workers/scripts`, payload.email, payload.key);
        
        let workersSubdomain = null;
        try {
          const subdomainResult = await cfGet(`/accounts/${payload.accountId}/workers/subdomain`, payload.email, payload.key);
          if (subdomainResult.success) workersSubdomain = subdomainResult.result.subdomain;
        } catch (e) {}
        
        if (result.success && result.result) {
          for (let worker of result.result) {
            try {
              const domainsResult = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${worker.id}/domains`, payload.email, payload.key);
              worker.domains = domainsResult.success ? (domainsResult.result || []) : [];
              
              try {
                const bindingsResult = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${worker.id}/bindings`, payload.email, payload.key);
                worker.bindings = (bindingsResult.success && bindingsResult.result) ? bindingsResult.result : [];
              } catch (e) { worker.bindings = []; }

              try {
                const subdomainStatus = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${worker.id}/subdomain`, payload.email, payload.key);
                worker.subdomainEnabled = subdomainStatus.success ? subdomainStatus.result.enabled : true;
              } catch (e) { worker.subdomainEnabled = true; }
              
              if (workersSubdomain) {
                worker.defaultDomain = {
                  hostname: `${worker.id}.${workersSubdomain}.workers.dev`,
                  type: 'workers_dev',
                  enabled: worker.subdomainEnabled !== false
                };
              }
            } catch (e) {
              worker.domains = [];
              worker.bindings = [];
              worker.subdomainEnabled = true;
            }
          }
        }
        return json(result);
      }

      case 'get-worker-script': {
        return await getWorkerScriptInternal(payload.email, payload.key, payload.accountId, payload.scriptName);
      }

      case 'deploy-worker': {
        const { scriptName, scriptSource, metadataBindings, usage_model } = payload;
        if (!scriptName) return json({ success: false, error: 'scriptName required' }, 400);
        
        let accountId = payload.accountId;
        if (!accountId) {
          accountId = await getAccountId(payload.email, payload.key);
        }

        let currentBindings = [];
        try {
          const bindingsRes = await cfGet(`/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, payload.email, payload.key);
          if (bindingsRes && bindingsRes.success) {
            currentBindings = bindingsRes.result;
          }
        } catch (e) {}

        const normalizedNewBindings = (metadataBindings || []).map((b) => {
          const copy = JSON.parse(JSON.stringify(b));
          if (copy.type === 'kv_namespace') {
            if (copy.namespace) { copy.namespace_id = copy.namespace; delete copy.namespace; }
            if (!copy.namespace_id && copy.id) copy.namespace_id = copy.id;
            delete copy.id; 
          }
          if (copy.type === 'd1_database' || copy.type === 'd1') {
             copy.type = 'd1'; 
             if (copy.database_id) { copy.id = copy.database_id; delete copy.database_id; }
             if (!copy.id && copy.namespace_id) { copy.id = copy.namespace_id; delete copy.namespace_id; }
             delete copy.database_name; 
             delete copy.preview_database_id;
          }
          return copy;
        });

        const finalBindings = [...currentBindings];
        normalizedNewBindings.forEach(newB => {
            const idx = finalBindings.findIndex(oldB => oldB.name === newB.name);
            if (idx !== -1) finalBindings[idx] = newB;
            else finalBindings.push(newB);
        });

        const cleanedBindings = finalBindings.map(b => {
            if(b.type === 'd1' || b.type === 'd1_database') return { type: 'd1', id: b.id || b.database_id, name: b.name };
            if(b.type === 'kv_namespace') return { type: 'kv_namespace', namespace_id: b.namespace_id || b.id, name: b.name };
            delete b.last_deployed_from;
            return b;
        });

        let finalScript = scriptSource;
        if (typeof finalScript !== 'string' || finalScript.trim().length === 0) {
             finalScript = "export default { async fetch() { return new Response('Deployed via Manager'); } };";
        }

        const isModule = finalScript.includes('export default') || finalScript.includes('export {');
        
        const form = new FormData();
        const metadata = { 
          bindings: cleanedBindings,
          usage_model: usage_model || 'standard'
        };

        if (isModule) {
            metadata.main_module = 'worker.js';
            form.append('metadata', JSON.stringify(metadata));
            form.append('worker.js', new Blob([finalScript], { type: 'application/javascript+module' }), 'worker.js');
        } else {
            metadata.body_part = 'script';
            form.append('metadata', JSON.stringify(metadata));
            form.append('script', new Blob([finalScript], { type: 'application/javascript' }), 'worker.js');
        }

        const uploadUrl = `${CF_API_BASE}/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}`;
        const resp = await fetch(uploadUrl, { 
          method: 'PUT', 
          headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key }, 
          body: form 
        });
        
        let text = "";
        try { text = await resp.text(); } catch(e) { text = "{}"; }
        
        let uploadRes;
        try { uploadRes = JSON.parse(text); } catch { uploadRes = { errors: [{ message: text }] }; }

        if (!resp.ok) return json({ success: false, error: '部署失败: ' + (uploadRes.errors?.[0]?.message || 'Unknown') }, 200); 
        return json({ success: true, message: 'Worker 部署成功' });
      }

      case 'get-worker-variables': {
        const { scriptName } = payload;
        if (!scriptName || !payload.accountId) return json({ success: false }, 400);
        const r = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, payload.email, payload.key);
        const vars = [];
        if (r.success && r.result) r.result.forEach(b => { 
          if (b.type === 'plain_text' || b.type === 'secret_text') 
            vars.push({ name: b.name, type: b.type, value: b.text || '' }); 
        });
        return json({ success: true, result: { vars } });
      }

      // 修复：更可靠的请求数获取
      case 'get-usage-today': { 
        if (!payload.accountId) return json({ success: false, error: 'accountId required' }, 400); 
        const { accountId, email, key: apikey } = payload; 
        
        try {
          const now = new Date();
          const end = now.toISOString();
          now.setUTCHours(0, 0, 0, 0);
          const start = now.toISOString();
          
          let workersTotal = 0;
          
          // 方法1: 通过 Workers 列表获取每个脚本的 analytics
          try {
            const scriptsRes = await cfGet(`/accounts/${accountId}/workers/scripts`, email, apikey);
            if (scriptsRes.success && scriptsRes.result) {
              for (const script of scriptsRes.result) {
                try {
                  const analyticsUrl = `${CF_API_BASE}/accounts/${accountId}/workers/scripts/${script.id}/analytics/summary?since=${start}&until=${end}`;
                  const analyticsRes = await fetch(analyticsUrl, {
                    headers: { 'X-Auth-Email': email, 'X-Auth-Key': apikey }
                  });
                  if (analyticsRes.ok) {
                    const data = await analyticsRes.json();
                    if (data.result && data.result.requests) {
                      workersTotal += data.result.requests || 0;
                    }
                  }
                } catch (e) {}
              }
            }
          } catch (e) {}
          
          // 方法2: 通过 GraphQL 获取（备选）
          let graphqlTotal = 0;
          try {
            const graphqlRes = await fetch("https://api.cloudflare.com/client/v4/graphql", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-Auth-Email": email,
                "X-Auth-Key": apikey
              },
              body: JSON.stringify({
                query: `query {
                  viewer {
                    accounts(filter: {accountTag: "${accountId}"}) {
                      workersInvocationsAdaptive(limit: 100, filter: {datetime_geq: "${start}", datetime_lt: "${end}"}) {
                        sum { requests }
                      }
                    }
                  }
                }`
              })
            });
            
            if (graphqlRes.ok) {
              const data = await graphqlRes.json();
              const invocations = data?.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive;
              if (invocations && invocations.length > 0) {
                graphqlTotal = invocations.reduce((sum, inv) => sum + (inv.sum?.requests || 0), 0);
              }
            }
          } catch (e) {}
          
          const total = Math.max(workersTotal, graphqlTotal);
          const percentage = Math.min(100, (total / 100000) * 100);
          
          return json({ 
            success: true, 
            data: { 
              total: total, 
              workers: total, 
              pages: 0, 
              percentage: percentage 
            } 
          });
        } catch(e) { 
          return json({ 
            success: true, 
            data: { total: 0, workers: 0, pages: 0, percentage: 0 }
          }); 
        }
      }

      // 子域名开关
      case 'toggle-worker-subdomain': 
        return json(await cfPost(`/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(payload.scriptName)}/subdomain`, payload.email, payload.key, { enabled: payload.enabled }));

      // 添加自定义域名
      case 'add-worker-domain': {
        const { scriptName, hostname } = payload;
        const cleanHost = hostname.replace(/^https?:\/\//, '').replace(/\/$/, '').trim();
        const zonesRes = await cfGet('/zones', payload.email, payload.key);
        const zone = zonesRes.success ? zonesRes.result.find(z => cleanHost === z.name || cleanHost.endsWith('.' + z.name)) : null;
        if (!zone) return json({ success: false, error: '未找到匹配的 Zone，请确保域名已添加到 Cloudflare' });
        const res = await cfPutRaw(`/zones/${zone.id}/workers/domains`, payload.email, payload.key, { 
          environment: "production", 
          hostname: cleanHost, 
          service: scriptName, 
          zone_id: zone.id 
        });
        return json({ success: res.success || !!res.result, error: res.errors?.[0]?.message });
      }

      // 删除自定义域名
      case 'delete-worker-domain': {
        const url = `${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(payload.scriptName)}/domains/${payload.domainId}`;
        const r = await fetch(url, { 
          method: 'DELETE', 
          headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key } 
        });
        return json({ success: r.ok });
      }

      // 删除 Worker
      case 'delete-worker': {
        const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(payload.scriptName)}`, { 
          method: 'DELETE', 
          headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key } 
        });
        return json({ success: r.ok });
      }

      // KV 命名空间
      case 'list-kv-namespaces': 
        return json(await cfGet(`/accounts/${payload.accountId}/storage/kv/namespaces`, payload.email, payload.key));
      
      case 'create-kv-namespace': 
        return json(await cfPost(`/accounts/${payload.accountId}/storage/kv/namespaces`, payload.email, payload.key, { title: payload.title }));
      
      case 'delete-kv-namespace': 
        return json(await cfDelete(`/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}`, payload.email, payload.key));
      
      case 'list-kv-keys': 
        return json(await cfGet(`/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}/keys`, payload.email, payload.key));

      // D1 数据库
      case 'list-d1': 
        return json(await cfGet(`/accounts/${payload.accountId}/d1/database`, payload.email, payload.key));
      
      case 'create-d1-database': 
        return json(await cfPost(`/accounts/${payload.accountId}/d1/database`, payload.email, payload.key, { name: payload.name }));
      
      case 'delete-d1-database': 
        return json(await cfDelete(`/accounts/${payload.accountId}/d1/database/${payload.databaseId}`, payload.email, payload.key));
      
      case 'execute-d1-query': 
        return json(await cfPost(`/accounts/${payload.accountId}/d1/database/${payload.databaseId}/query`, payload.email, payload.key, { sql: payload.query }));

      // 子域名设置
      case 'get-workers-subdomain': 
        return json(await cfGet(`/accounts/${payload.accountId}/workers/subdomain`, payload.email, payload.key));
      
      case 'put-workers-subdomain': 
        return json(await cfPutRaw(`/accounts/${payload.accountId}/workers/subdomain`, payload.email, payload.key, { subdomain: payload.subdomain }));

      // DNS 管理
      case 'list-zones': 
        return json(await cfGet('/zones', payload.email, payload.key));
      
      case 'create-zone': 
        return json(await cfPost('/zones', payload.email, payload.key, { name: payload.name }));
      
      case 'delete-zone': 
        return json(await cfDelete(`/zones/${payload.zoneId}`, payload.email, payload.key));
      
      case 'list-dns-records': 
        return json(await cfGet(`/zones/${payload.zoneId}/dns_records`, payload.email, payload.key));
      
      case 'create-dns-record': 
        return json(await cfPost(`/zones/${payload.zoneId}/dns_records`, payload.email, payload.key, { 
          type: payload.type, name: payload.name, content: payload.content, ttl: payload.ttl || 1, proxied: payload.proxied || false 
        }));
      
      case 'update-dns-record': 
        return json(await cfPut(`/zones/${payload.zoneId}/dns_records/${payload.recordId}`, payload.email, payload.key, { 
          type: payload.type, name: payload.name, content: payload.content, ttl: payload.ttl || 1, proxied: payload.proxied || false 
        }));
      
      case 'delete-dns-record': 
        return json(await cfDelete(`/zones/${payload.zoneId}/dns_records/${payload.recordId}`, payload.email, payload.key));

      default:
        return json({ success: false, error: 'unknown action: ' + action }, 400);
    }
  } catch(e) {
    return json({ success: false, error: String(e) }, 500);
  }
}

async function getWorkerScriptInternal(email, key, accountId, scriptName) {
  if (!scriptName) return json({ success: false, error: 'scriptName required' }, 400);
  const accId = accountId || await getAccountId(email, key);
  const url = `${CF_API_BASE}/accounts/${accId}/workers/scripts/${encodeURIComponent(scriptName)}`;
  const resp = await fetch(url, { 
    method: 'GET', 
    headers: { 'X-Auth-Email': email, 'X-Auth-Key': key }
  });
  
  if (resp.status === 404) {
    return json({ ok: false, status: 404, rawScript: "export default { async fetch() { return new Response('New Worker'); } };" });
  }

  const text = await resp.text();
  const contentType = resp.headers.get('content-type') || '';
  let scriptContent = null;

  if (contentType.includes('multipart/form-data')) {
    const boundaryMatch = contentType.match(/boundary=(.*)/);
    const boundary = boundaryMatch ? boundaryMatch[1].split(';')[0].trim() : null;
    if (boundary) {
      const parts = text.split(new RegExp(`--${boundary}(?:--)?`));
      for (const part of parts) {
        if (part.includes('Content-Type: application/javascript') || 
            part.includes('filename="worker.js"') || 
            part.includes('name="script"')) {
          const bodyMatch = part.match(/\r?\n\r?\n([\s\S]*)/);
          if (bodyMatch && bodyMatch[1]) {
            scriptContent = bodyMatch[1].trim();
            break;
          }
        }
      }
    }
  } else if (!text.trim().startsWith('{')) {
    scriptContent = text;
  }

  if (scriptContent) {
    return json({ ok: true, status: 200, rawScript: scriptContent });
  }
  return json({ ok: true, status: 200, rawScript: text }); 
}

async function getAccountId(email, key) {
  const r = await cfGet('/accounts', email, key);
  const arr = r.result || (r.data && r.data.result) || r;
  if (Array.isArray(arr) && arr.length) return arr[0].id;
  throw new Error('Cannot find accountId');
}

async function cfGet(path, email, key) { return cfAny('GET', path, email, key); }
async function cfPost(path, email, key, body) { return cfAny('POST', path, email, key, body); }
async function cfPut(path, email, key, body) { return cfAny('PUT', path, email, key, body); }
async function cfDelete(path, email, key) { return cfAny('DELETE', path, email, key); }

async function cfPutRaw(path, email, key, body) {
  const url = path.startsWith('http') ? path : CF_API_BASE + path;
  const res = await fetch(url, { 
    method: 'PUT', 
    headers: { 'X-Auth-Email': email, 'X-Auth-Key': key, 'Content-Type': 'application/json' }, 
    body: JSON.stringify(body) 
  });
  try { return await res.json(); } catch { return { success: res.ok }; }
}

async function cfAny(method, path, email, key, body = null) {
  const url = path.startsWith('http') ? path : CF_API_BASE + path;
  const headers = { 'X-Auth-Email': email, 'X-Auth-Key': key };
  const opts = { method, headers };
  if (body !== null) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  try { return await res.json(); } catch { return { success: res.ok }; }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), { 
    status, 
    headers: { 'content-type': 'application/json' } 
  });
}

async function safeJSON(req) { 
  try { return await req.json(); } catch { return {}; } 
}

// =============== HTML 渲染函数 ===============

function renderLoginHTML() {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloudflare Manager - 登录</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', system-ui, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 20px;
  }
  .container { max-width: 500px; margin: 40px auto; }
  .card { background: white; border-radius: 20px; padding: 32px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
  h2 { margin-bottom: 8px; color: #1a202c; }
  .subtitle { color: #718096; margin-bottom: 24px; font-size: 14px; }
  .form-group { margin-bottom: 16px; }
  label { display: block; margin-bottom: 8px; font-weight: 500; color: #2d3748; font-size: 14px; }
  input, select { width: 100%; padding: 12px; border: 2px solid #e2e8f0; border-radius: 10px; font-size: 14px; }
  input:focus, select:focus { outline: none; border-color: #667eea; }
  button { width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 8px; }
  button:hover { transform: translateY(-2px); transition: transform 0.2s; }
  .account-item { display: flex; justify-content: space-between; align-items: center; padding: 12px; border: 1px solid #eef2f6; border-radius: 10px; margin-bottom: 8px; }
  .account-item:hover { background: #f8fafc; }
  .account-email { font-weight: 500; }
  .account-actions { display: flex; gap: 8px; }
  .btn-icon { background: none; border: none; cursor: pointer; font-size: 18px; padding: 4px 8px; width: auto; margin: 0; }
  .btn-icon:hover { transform: none; background: #f1f5f9; border-radius: 6px; }
  .error { color: #e53e3e; font-size: 13px; margin-top: 8px; display: none; }
  .success { color: #10b981; font-size: 13px; margin-top: 8px; display: none; }
  hr { margin: 20px 0; border: none; border-top: 1px solid #eef2f6; }
</style>
</head>
<body>
<div class="container">
  <div class="card">
    <h2>🔐 Cloudflare Manager</h2>
    <div class="subtitle">管理多个 Cloudflare 账号</div>
    
    <div id="accountsList"></div>
    
    <hr>
    
    <div style="font-weight: 600; margin-bottom: 12px;">添加新账号</div>
    <div class="form-group">
      <label>邮箱地址</label>
      <input type="email" id="newEmail" placeholder="your@email.com">
    </div>
    <div class="form-group">
      <label>Global API Key</label>
      <input type="password" id="newKey" placeholder="您的 API Key">
      <div class="note" style="font-size: 12px; color: #718096; margin-top: 4px;">可在 Cloudflare 控制台 → 我的资料 → API 令牌中获取</div>
    </div>
    <div class="form-group">
      <label>别名（可选）</label>
      <input type="text" id="newAlias" placeholder="例如: 个人账号">
    </div>
    
    <div id="loginError" class="error"></div>
    <div id="loginSuccess" class="success"></div>
    
    <button id="addBtn">添加并登录</button>
  </div>
</div>

<script>
let accounts = [];

async function loadAccounts() {
  try {
    const res = await fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'get-accounts' })
    });
    const data = await res.json();
    if (data.success) {
      accounts = data.accounts;
      renderAccounts();
    }
  } catch (e) { console.error(e); }
}

function renderAccounts() {
  const container = document.getElementById('accountsList');
  if (accounts.length === 0) {
    container.innerHTML = '<div style="text-align: center; padding: 20px; color: #94a3b8;">暂无已保存账号</div>';
    return;
  }
  
  container.innerHTML = '<div style="font-weight: 600; margin-bottom: 12px;">已保存的账号</div>';
  accounts.forEach(acc => {
    const div = document.createElement('div');
    div.className = 'account-item';
    div.innerHTML = \`
      <div>
        <div class="account-email">\${acc.alias || acc.email}</div>
        <div style="font-size: 12px; color: #64748b;">\${acc.email}</div>
      </div>
      <div class="account-actions">
        <button class="btn-icon" onclick="loginWithAccount('\${acc.email}')" title="登录">🔑</button>
        <button class="btn-icon" onclick="deleteAccount('\${acc.email}')" title="删除">🗑️</button>
      </div>
    \`;
    container.appendChild(div);
  });
}

async function loginWithAccount(email) {
  const account = accounts.find(a => a.email === email);
  if (!account) return;
  
  localStorage.setItem('cf_active_email', account.email);
  localStorage.setItem('cf_active_key', account.key);
  window.location.href = '/workers';
}

async function deleteAccount(email) {
  if (!confirm('确定要删除此账号吗？')) return;
  const res = await fetch('/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'delete-account', email })
  });
  const data = await res.json();
  if (data.success) {
    await loadAccounts();
  }
}

document.getElementById('addBtn').addEventListener('click', async () => {
  const email = document.getElementById('newEmail').value.trim();
  const key = document.getElementById('newKey').value.trim();
  const alias = document.getElementById('newAlias').value.trim();
  const errorDiv = document.getElementById('loginError');
  const successDiv = document.getElementById('loginSuccess');
  
  errorDiv.style.display = 'none';
  successDiv.style.display = 'none';
  
  if (!email || !key) {
    errorDiv.textContent = '请填写邮箱和 API Key';
    errorDiv.style.display = 'block';
    return;
  }
  
  const btn = document.getElementById('addBtn');
  btn.disabled = true;
  btn.textContent = '验证中...';
  
  try {
    // 验证凭据
    const validateRes = await fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'validate-credentials', email, key })
    });
    const validateData = await validateRes.json();
    
    if (!validateData.success) {
      errorDiv.textContent = '验证失败：' + (validateData.error || '凭据无效');
      errorDiv.style.display = 'block';
      btn.disabled = false;
      btn.textContent = '添加并登录';
      return;
    }
    
    // 保存账号
    const saveRes = await fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'save-account', email, key, alias })
    });
    const saveData = await saveRes.json();
    
    if (saveData.success) {
      localStorage.setItem('cf_active_email', email);
      localStorage.setItem('cf_active_key', key);
      successDiv.textContent = '验证成功，正在跳转...';
      successDiv.style.display = 'block';
      setTimeout(() => { window.location.href = '/workers'; }, 1000);
    } else {
      errorDiv.textContent = saveData.error || '保存失败';
      errorDiv.style.display = 'block';
      btn.disabled = false;
      btn.textContent = '添加并登录';
    }
  } catch (e) {
    errorDiv.textContent = '网络错误：' + e.message;
    errorDiv.style.display = 'block';
    btn.disabled = false;
    btn.textContent = '添加并登录';
  }
});

loadAccounts();
</script>
</body>
</html>`;
}

function renderAppHTML() {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloudflare 管理平台</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#f6f8fa;--card:#fff;--muted:#6b7280;--accent:#2563eb;--danger:#ef4444}
*{box-sizing:border-box}
body{font-family:Inter,system-ui;margin:0;background:var(--bg);color:#0f1724}
.app{display:flex;min-height:100vh}
.sidebar{width:260px;background:#fff;border-right:1px solid #eef2f6;padding:22px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px}
.nav{margin-top:22px}
.nav .item{display:flex;align-items:center;gap:10px;padding:10px;border-radius:8px;color:#334155;margin-bottom:6px;cursor:pointer}
.nav .item.active{background:#f8fafc;font-weight:600}
.main{flex:1;padding:26px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.metric{background:#fff;padding:20px;border-radius:12px;box-shadow:0 6px 18px rgba(2,6,23,0.04)}
.metric .bar{height:8px;background:#eef2ff;border-radius:999px;overflow:hidden;margin-top:8px}
.metric .bar>div{height:100%;background:linear-gradient(90deg,#2563eb,#60a5fa);width:0%}
.card{background:var(--card);border-radius:12px;box-shadow:0 6px 18px rgba(2,6,23,0.04);margin-bottom:16px}
.card-header{padding:16px 20px;border-bottom:1px solid #eef2f6;display:flex;justify-content:space-between;align-items:center}
.card-body{padding:20px}
.worker-row{border:1px solid #eef2ff;border-radius:10px;padding:16px;margin-bottom:12px;background:#fbfdff}
.worker-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px}
.worker-name{font-weight:700;font-size:16px}
.worker-meta{color:var(--muted);font-size:12px;margin-top:4px}
.domains-section{margin-top:12px;padding-top:12px;border-top:1px solid #eef2f6}
.domain-list{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.domain-tag{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;background:#f1f5f9;border-radius:6px;font-size:12px}
.domain-tag.workers-dev{background:#eff6ff;border:1px solid #dbeafe}
.domain-status{font-size:10px;padding:2px 6px;border-radius:4px}
.domain-status.active{background:#f0fdf4;color:#166534}
.domain-status.inactive{background:#fef2f2;color:#dc2626}
.del-domain{background:none;border:none;cursor:pointer;color:#ef4444;font-size:14px;padding:0 4px}
.del-domain:hover{color:#dc2626}
.btn{padding:6px 12px;border-radius:6px;border:1px solid #e6eef9;background:#fff;cursor:pointer;font-size:12px}
.btn.primary{background:var(--accent);color:#fff;border:0}
.btn.danger{background:#ef4444;color:#fff;border:0}
.btn.small{font-size:11px;padding:4px 8px}
.btns{display:flex;gap:8px;flex-wrap:wrap}
.small{font-size:13px;color:var(--muted)}
.modal{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);align-items:center;justify-content:center;z-index:1000}
.modal-box{background:#fff;border-radius:12px;padding:24px;width:500px;max-width:90%;max-height:90%;overflow:auto}
.input{width:100%;padding:10px;border-radius:8px;border:1px solid #e6edf3;font-size:14px}
textarea.input{min-height:200px;font-family:monospace}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-weight:500;font-size:13px}
.switch{position:relative;display:inline-block;width:40px;height:20px}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background-color:#ccc;transition:.3s;border-radius:20px}
.slider:before{position:absolute;content:"";height:16px;width:16px;left:2px;bottom:2px;background-color:white;transition:.3s;border-radius:50%}
input:checked+.slider{background-color:#2563eb}
input:checked+.slider:before{transform:translateX(20px)}
.page-content{display:none}
.page-content.active{display:block}
.batch-layout{display:flex;gap:20px}
.batch-sidebar{width:280px;border-right:1px solid #eef2f6}
.batch-main{flex:1}
.account-check-item{padding:10px;border-bottom:1px solid #eef2f6;display:flex;align-items:center;gap:8px}
.log-area{background:#1e293b;color:#10b981;padding:12px;border-radius:8px;font-family:monospace;font-size:12px;min-height:200px;max-height:300px;overflow:auto}
.env-row{display:flex;gap:8px;margin-bottom:8px}
.env-row input{flex:1}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="logo">☁️ Cloudflare 管理</div>
    <nav class="nav">
      <div class="item" data-page="workers">Workers</div>
      <div class="item" data-page="batch">批量创建</div>
      <div class="item" data-page="kv">KV 存储</div>
      <div class="item" data-page="d1">D1 数据库</div>
      <div class="item" data-page="dns">域名管理</div>
      <div class="item" data-page="settings">设置</div>
    </nav>
    <div style="margin-top:auto;padding-top:20px;border-top:1px solid #eef2f6">
      <div class="small" id="currentAccount"></div>
      <div style="margin-top:8px;display:flex;gap:12px">
        <span onclick="switchAccount()" style="cursor:pointer;color:#2563eb;font-size:12px">切换账号</span>
        <span onclick="logout()" style="cursor:pointer;color:#ef4444;font-size:12px">退出</span>
      </div>
    </div>
  </aside>
  
  <main class="main">
    <!-- Workers 页面 -->
    <div id="workers-page" class="page-content active">
      <div class="header">
        <div style="font-size:20px;font-weight:700">Workers 管理</div>
        <button class="btn primary" onclick="openCreateWorker()">新建 Worker</button>
      </div>
      
      <div class="metric">
        <div class="small">今日请求数</div>
        <div style="font-size:28px;font-weight:700" id="metricCount">0 / 100,000</div>
        <div class="bar"><div id="metricBar"></div></div>
        <div style="display:flex;justify-content:space-between;margin-top:12px">
          <div><span class="small">Workers:</span> <strong id="workersRequests">0</strong></div>
          <div><span class="small">日配额:</span> <strong>100,000</strong></div>
        </div>
      </div>
      
      <div class="card">
        <div class="card-header">
          <div><strong>Workers 列表</strong></div>
        </div>
        <div class="card-body" id="workersList"></div>
      </div>
    </div>
    
    <!-- 批量创建页面 -->
    <div id="batch-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">批量创建 Workers</div>
      </div>
      <div class="batch-layout">
        <div class="batch-sidebar">
          <div class="card">
            <div class="card-header"><strong>选择账号</strong></div>
            <div class="card-body" id="batchAccountList"></div>
          </div>
        </div>
        <div class="batch-main">
          <div class="card">
            <div class="card-header"><strong>基本配置</strong></div>
            <div class="card-body">
              <div class="form-group">
                <label>Worker 名称</label>
                <input id="batchWorkerName" class="input" placeholder="例如: my-worker">
              </div>
              <div class="form-group">
                <label>代码来源</label>
                <select id="batchScriptSourceType" class="input">
                  <option value="builtin">内置模板</option>
                  <option value="url">自定义 URL</option>
                </select>
              </div>
              <div id="batchBuiltinDiv">
                <div class="form-group">
                  <label>选择模板</label>
                  <select id="batchBuiltinSelect" class="input">
                    <option value="https://raw.githubusercontent.com/cloudflare/workers-sdk/main/templates/worker/typescript/worker.js">基础 Worker 模板</option>
                  </select>
                </div>
              </div>
              <div id="batchUrlDiv" style="display:none">
                <div class="form-group">
                  <label>脚本 URL</label>
                  <input id="batchScriptUrl" class="input" placeholder="https://example.com/worker.js">
                </div>
              </div>
              <div class="form-group">
                <label style="display:flex;align-items:center;gap:8px">
                  <input type="checkbox" id="batchEnableSubdomain" checked> 开启默认域名 (workers.dev)
                </label>
              </div>
            </div>
          </div>
          
          <div class="card">
            <div class="card-header"><strong>环境变量 (可选)</strong></div>
            <div class="card-body">
              <div id="batchEnvList"></div>
              <button class="btn small" onclick="addBatchEnvRow()">+ 添加变量</button>
            </div>
          </div>
          
          <button class="btn primary" style="width:100%;margin-bottom:16px" onclick="startBatchCreate()">开始批量创建</button>
          
          <div class="card">
            <div class="card-header"><strong>执行日志</strong></div>
            <div class="card-body">
              <div id="batchLog" class="log-area">等待开始...</div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- KV 页面 -->
    <div id="kv-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">KV 命名空间</div>
        <button class="btn primary" onclick="openCreateKV()">创建 KV</button>
      </div>
      <div class="card">
        <div class="card-body" id="kvList"></div>
      </div>
    </div>
    
    <!-- D1 页面 -->
    <div id="d1-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">D1 数据库</div>
        <button class="btn primary" onclick="openCreateD1()">创建 D1</button>
      </div>
      <div class="card">
        <div class="card-body" id="d1List"></div>
      </div>
    </div>
    
    <!-- DNS 页面 -->
    <div id="dns-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">域名管理</div>
        <button class="btn primary" onclick="openAddZone()">添加域名</button>
      </div>
      <div class="card" id="zonesCard">
        <div class="card-header"><strong>域名列表</strong></div>
        <div class="card-body" id="zonesList"></div>
      </div>
      <div class="card" id="dnsCard" style="display:none">
        <div class="card-header">
          <strong id="selectedZoneName"></strong>
          <button class="btn" onclick="backToZones()">返回列表</button>
        </div>
        <div class="card-body" id="dnsRecordsList"></div>
      </div>
    </div>
    
    <!-- 设置页面 -->
    <div id="settings-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">设置</div>
      </div>
      <div class="card">
        <div class="card-header"><strong>Workers 子域名</strong></div>
        <div class="card-body">
          <div class="form-group">
            <label>子域名前缀</label>
            <input id="subdomainInput" class="input" placeholder="your-subdomain">
          </div>
          <button class="btn primary" onclick="saveSubdomain()">保存设置</button>
          <div class="small" style="margin-top:8px">设置后 Workers 将通过 *.your-subdomain.workers.dev 访问</div>
        </div>
      </div>
    </div>
  </main>
</div>

<!-- 模态框 -->
<div id="createWorkerModal" class="modal">
  <div class="modal-box">
    <h3>新建 Worker</h3>
    <div class="form-group">
      <label>Worker 名称</label>
      <input id="createWorkerName" class="input" placeholder="worker-name">
    </div>
    <div class="form-group">
      <label>代码</label>
      <textarea id="createWorkerScript" class="input" rows="10">export default {
  async fetch(request, env, ctx) {
    return new Response('Hello World');
  }
};</textarea>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" onclick="closeCreateWorkerModal()">取消</button>
      <button class="btn primary" onclick="confirmCreateWorker()">部署</button>
    </div>
  </div>
</div>

<div id="addDomainModal" class="modal">
  <div class="modal-box">
    <h3>绑定自定义域名</h3>
    <div class="form-group">
      <label>域名</label>
      <input id="customDomain" class="input" placeholder="app.example.com">
      <div class="small" style="margin-top:4px">请确保域名已添加到 Cloudflare</div>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" onclick="closeAddDomainModal()">取消</button>
      <button class="btn primary" onclick="confirmAddDomain()">绑定</button>
    </div>
  </div>
</div>

<div id="envModal" class="modal">
  <div class="modal-box">
    <h3>环境变量</h3>
    <div id="envRows"></div>
    <button class="btn small" onclick="addEnvRow()">+ 添加</button>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
      <button class="btn" onclick="closeEnvModal()">取消</button>
      <button class="btn primary" onclick="saveEnvVars()">保存</button>
    </div>
  </div>
</div>

<div id="createKVModal" class="modal">
  <div class="modal-box">
    <h3>创建 KV 命名空间</h3>
    <div class="form-group">
      <label>名称</label>
      <input id="kvName" class="input" placeholder="my-kv-namespace">
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" onclick="closeCreateKVModal()">取消</button>
      <button class="btn primary" onclick="confirmCreateKV()">创建</button>
    </div>
  </div>
</div>

<div id="createD1Modal" class="modal">
  <div class="modal-box">
    <h3>创建 D1 数据库</h3>
    <div class="form-group">
      <label>名称</label>
      <input id="d1Name" class="input" placeholder="my-d1-database">
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" onclick="closeCreateD1Modal()">取消</button>
      <button class="btn primary" onclick="confirmCreateD1()">创建</button>
    </div>
  </div>
</div>

<div id="addZoneModal" class="modal">
  <div class="modal-box">
    <h3>添加域名</h3>
    <div class="form-group">
      <label>域名</label>
      <input id="zoneName" class="input" placeholder="example.com">
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" onclick="closeAddZoneModal()">取消</button>
      <button class="btn primary" onclick="confirmAddZone()">添加</button>
    </div>
  </div>
</div>

<div id="addDNSModal" class="modal">
  <div class="modal-box">
    <h3>添加 DNS 记录</h3>
    <div class="form-group">
      <label>类型</label>
      <select id="dnsType" class="input">
        <option value="A">A</option>
        <option value="AAAA">AAAA</option>
        <option value="CNAME">CNAME</option>
        <option value="MX">MX</option>
        <option value="TXT">TXT</option>
      </select>
    </div>
    <div class="form-group">
      <label>名称</label>
      <input id="dnsName" class="input" placeholder="@ 或 www">
    </div>
    <div class="form-group">
      <label>内容</label>
      <input id="dnsContent" class="input" placeholder="IP 地址或目标域名">
    </div>
    <div class="form-group">
      <label>TTL</label>
      <select id="dnsTtl" class="input">
        <option value="1">自动</option>
        <option value="120">2分钟</option>
        <option value="300">5分钟</option>
        <option value="3600">1小时</option>
      </select>
    </div>
    <div class="form-group">
      <label style="display:flex;align-items:center;gap:8px">
        <input type="checkbox" id="dnsProxied"> 启用代理 (橙色云)
      </label>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" onclick="closeAddDNSModal()">取消</button>
      <button class="btn primary" onclick="confirmAddDNS()">添加</button>
    </div>
  </div>
</div>

<script src="/static.js"></script>
</body>
</html>`;
}

function renderStaticJS(env) {
  return `(function(){
  // 获取当前账号
  function getActiveCreds() {
    return {
      email: localStorage.getItem('cf_active_email') || '',
      key: localStorage.getItem('cf_active_key') || ''
    };
  }
  
  let currentWorkerForEnv = null;
  let currentWorkerForDomain = null;
  let currentZoneId = null;
  
  // API 调用
  async function api(action, body) {
    const creds = getActiveCreds();
    const payload = { action, ...creds, ...body };
    const resp = await fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    try { return await resp.json(); }
    catch(e) { return { success: false, error: e.message }; }
  }
  
  function showNotification(msg, type) {
    const div = document.createElement('div');
    div.textContent = msg;
    div.style.cssText = \`
      position: fixed; top: 20px; right: 20px; padding: 12px 20px;
      background: \${type === 'error' ? '#ef4444' : '#10b981'};
      color: white; border-radius: 8px; z-index: 10000;
      animation: fadeInOut 3s ease;
    \`;
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 3000);
  }
  
  // 导航
  function navTo(page) {
    document.querySelectorAll('.nav .item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.page-content').forEach(p => p.classList.remove('active'));
    document.getElementById(page + '-page').classList.add('active');
    document.querySelector(\`.nav .item[data-page="\${page}"]\`).classList.add('active');
    
    if (page === 'workers') refreshWorkers();
    if (page === 'batch') loadBatchAccounts();
    if (page === 'kv') refreshKV();
    if (page === 'd1') refreshD1();
    if (page === 'dns') refreshZones();
    if (page === 'settings') loadSubdomain();
  }
  
  // 刷新 Workers 列表
  async function refreshWorkers() {
    const listDiv = document.getElementById('workersList');
    if (!listDiv) return;
    listDiv.innerHTML = '<div class="small">加载中...</div>';
    
    try {
      const accountsRes = await api('list-accounts');
      if (!accountsRes.success || !accountsRes.result || accountsRes.result.length === 0) {
        listDiv.innerHTML = '<div class="small">无法获取账户信息，请检查 API Key</div>';
        return;
      }
      
      const accountId = accountsRes.result[0].id;
      localStorage.setItem('cf_accountId', accountId);
      
      const workersRes = await api('list-workers', { accountId });
      if (!workersRes.success || !workersRes.result) {
        listDiv.innerHTML = '<div class="small">获取 Workers 列表失败</div>';
        return;
      }
      
      // 更新请求数
      updateUsage();
      
      if (workersRes.result.length === 0) {
        listDiv.innerHTML = '<div class="small">暂无 Workers</div>';
        return;
      }
      
      listDiv.innerHTML = '';
      for (const w of workersRes.result) {
        const name = w.id || w.name;
        const created = w.created_on ? new Date(w.created_on).toLocaleDateString() : '未知';
        const domains = w.domains || [];
        const defaultDomain = w.defaultDomain;
        const subdomainEnabled = w.subdomainEnabled !== false;
        
        const div = document.createElement('div');
        div.className = 'worker-row';
        div.innerHTML = \`
          <div class="worker-header">
            <div>
              <div class="worker-name">\${escapeHtml(name)}</div>
              <div class="worker-meta">创建于 \${created}</div>
            </div>
            <div class="btns">
              <button class="btn" onclick="openEnvFor('\${name}')">环境</button>
              <button class="btn" onclick="openAddDomain('\${name}')">绑定域名</button>
              <button class="btn" onclick="editWorker('\${name}')">编辑</button>
              <button class="btn danger" onclick="deleteWorker('\${name}')">删除</button>
            </div>
          </div>
          <div class="domains-section">
            <div class="small">绑定域名：</div>
            <div class="domain-list">
              \${defaultDomain ? \`
                <div class="domain-tag workers-dev">
                  \${escapeHtml(defaultDomain.hostname)}
                  <label class="switch" style="margin-left:8px">
                    <input type="checkbox" \${subdomainEnabled ? 'checked' : ''} onchange="toggleSubdomain('\${name}', this.checked)">
                    <span class="slider"></span>
                  </label>
                  <span style="font-size:10px;margin-left:4px">\${subdomainEnabled ? '已启用' : '已禁用'}</span>
                </div>
              \` : ''}
              \${domains.map(d => \`
                <div class="domain-tag">
                  \${escapeHtml(d.hostname)}
                  <span class="domain-status \${d.status === 'active' ? 'active' : 'pending'}">\${d.status === 'active' ? '已生效' : '待生效'}</span>
                  <button class="del-domain" onclick="deleteDomain('\${name}', '\${d.id}', '\${escapeHtml(d.hostname)}')">✕</button>
                </div>
              \`).join('')}
            </div>
          </div>
        \`;
        listDiv.appendChild(div);
      }
    } catch (e) {
      listDiv.innerHTML = '<div class="small">加载失败: ' + e.message + '</div>';
    }
  }
  
  // 切换子域名开关
  async function toggleSubdomain(scriptName, enabled) {
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('toggle-worker-subdomain', { accountId, scriptName, enabled });
    if (res.success) {
      showNotification(enabled ? '默认域名已启用' : '默认域名已禁用');
      refreshWorkers();
    } else {
      showNotification(res.error || '操作失败', 'error');
    }
  }
  
  // 打开添加域名弹窗
  function openAddDomain(scriptName) {
    currentWorkerForDomain = scriptName;
    document.getElementById('addDomainModal').style.display = 'flex';
  }
  
  function closeAddDomainModal() {
    document.getElementById('addDomainModal').style.display = 'none';
    currentWorkerForDomain = null;
  }
  
  async function confirmAddDomain() {
    const hostname = document.getElementById('customDomain').value.trim();
    if (!hostname) {
      showNotification('请输入域名', 'error');
      return;
    }
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('add-worker-domain', { accountId, scriptName: currentWorkerForDomain, hostname });
    if (res.success) {
      showNotification('域名绑定成功');
      closeAddDomainModal();
      refreshWorkers();
    } else {
      showNotification(res.error || '绑定失败', 'error');
    }
  }
  
  // 删除自定义域名
  async function deleteDomain(scriptName, domainId, hostname) {
    if (!confirm('确定要解绑域名 ' + hostname + ' 吗？')) return;
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('delete-worker-domain', { accountId, scriptName, domainId });
    if (res.success) {
      showNotification('域名已解绑');
      refreshWorkers();
    } else {
      showNotification(res.error || '解绑失败', 'error');
    }
  }
  
  // 更新用量统计
  async function updateUsage() {
    try {
      const accountId = localStorage.getItem('cf_accountId');
      const res = await api('get-usage-today', { accountId });
      if (res.success && res.data) {
        const total = res.data.total || 0;
        const percentage = res.data.percentage || 0;
        document.getElementById('metricCount').textContent = total.toLocaleString() + ' / 100,000';
        document.getElementById('metricBar').style.width = percentage + '%';
        document.getElementById('workersRequests').textContent = (res.data.workers || 0).toLocaleString();
      }
    } catch (e) {}
  }
  
  // 环境变量管理
  async function openEnvFor(scriptName) {
    currentWorkerForEnv = scriptName;
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('get-worker-variables', { accountId, scriptName });
    const container = document.getElementById('envRows');
    container.innerHTML = '';
    
    if (res.success && res.result && res.result.vars) {
      res.result.vars.forEach(v => addEnvRow(v.name, v.value, v.type));
    } else {
      addEnvRow();
    }
    document.getElementById('envModal').style.display = 'flex';
  }
  
  function addEnvRow(name = '', value = '', type = 'plain_text') {
    const container = document.getElementById('envRows');
    const div = document.createElement('div');
    div.className = 'env-row';
    div.innerHTML = \`
      <input class="input" placeholder="变量名" value="\${escapeHtml(name)}" style="flex:2">
      <select class="input" style="width:100px">
        <option value="plain_text" \${type === 'plain_text' ? 'selected' : ''}>文本</option>
        <option value="secret_text" \${type === 'secret_text' ? 'selected' : ''}>密钥</option>
      </select>
      <textarea class="input" placeholder="变量值" rows="1" style="flex:3;resize:vertical">\${escapeHtml(value)}</textarea>
      <button class="btn danger" onclick="this.parentElement.remove()">删除</button>
    \`;
    container.appendChild(div);
  }
  
  async function saveEnvVars() {
    const vars = [];
    document.querySelectorAll('#envRows .env-row').forEach(row => {
      const name = row.querySelector('input').value.trim();
      const type = row.querySelector('select').value;
      const value = row.querySelector('textarea').value;
      if (name) vars.push({ name, value, type });
    });
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('put-worker-variables', { accountId, scriptName: currentWorkerForEnv, variables: vars });
    if (res.success) {
      showNotification('环境变量已保存');
      document.getElementById('envModal').style.display = 'none';
      refreshWorkers();
    } else {
      showNotification(res.error || '保存失败', 'error');
    }
  }
  
  function closeEnvModal() {
    document.getElementById('envModal').style.display = 'none';
  }
  
  // 编辑 Worker
  async function editWorker(name) {
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('get-worker-script', { accountId, scriptName: name });
    if (res.success && res.rawScript) {
      document.getElementById('createWorkerName').value = name;
      document.getElementById('createWorkerScript').value = res.rawScript;
      document.getElementById('createWorkerModal').style.display = 'flex';
    } else {
      showNotification('获取脚本失败', 'error');
    }
  }
  
  async function deleteWorker(name) {
    if (!confirm('确定要删除 Worker: ' + name + ' 吗？')) return;
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('delete-worker', { accountId, scriptName: name });
    if (res.success) {
      showNotification('Worker 已删除');
      refreshWorkers();
    } else {
      showNotification(res.error || '删除失败', 'error');
    }
  }
  
  function openCreateWorker() {
    document.getElementById('createWorkerName').value = '';
    document.getElementById('createWorkerScript').value = 'export default { async fetch(request, env, ctx) { return new Response("Hello World"); } };';
    document.getElementById('createWorkerModal').style.display = 'flex';
  }
  
  function closeCreateWorkerModal() {
    document.getElementById('createWorkerModal').style.display = 'none';
  }
  
  async function confirmCreateWorker() {
    const name = document.getElementById('createWorkerName').value.trim();
    const script = document.getElementById('createWorkerScript').value;
    if (!name) {
      showNotification('请输入 Worker 名称', 'error');
      return;
    }
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('deploy-worker', { accountId, scriptName: name, scriptSource: script, metadataBindings: [] });
    if (res.success) {
      showNotification('部署成功');
      closeCreateWorkerModal();
      refreshWorkers();
    } else {
      showNotification(res.error || '部署失败', 'error');
    }
  }
  
  // 批量创建
  async function loadBatchAccounts() {
    const res = await fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'get-accounts' })
    });
    const data = await res.json();
    const container = document.getElementById('batchAccountList');
    if (data.success && data.accounts.length > 0) {
      container.innerHTML = data.accounts.map(acc => \`
        <div class="account-check-item">
          <input type="checkbox" class="batch-acc-chk" value="\${acc.email}">
          <span>\${escapeHtml(acc.alias || acc.email)}</span>
        </div>
      \`).join('');
    } else {
      container.innerHTML = '<div class="small" style="padding:10px">暂无账号，请在登录页添加</div>';
    }
  }
  
  function toggleBatchSourceInput() {
    const type = document.getElementById('batchScriptSourceType').value;
    document.getElementById('batchBuiltinDiv').style.display = type === 'builtin' ? 'block' : 'none';
    document.getElementById('batchUrlDiv').style.display = type === 'url' ? 'block' : 'none';
  }
  
  function addBatchEnvRow() {
    const container = document.getElementById('batchEnvList');
    const div = document.createElement('div');
    div.className = 'env-row';
    div.innerHTML = \`
      <input class="input" placeholder="变量名" style="flex:2">
      <textarea class="input" placeholder="变量值" rows="1" style="flex:3;resize:vertical"></textarea>
      <button class="btn danger" onclick="this.parentElement.remove()">删除</button>
    \`;
    container.appendChild(div);
  }
  
  function appendBatchLog(msg, color) {
    const log = document.getElementById('batchLog');
    const span = document.createElement('div');
    span.style.color = color || '#fff';
    span.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
    log.appendChild(span);
    log.scrollTop = log.scrollHeight;
  }
  
  async function startBatchCreate() {
    const name = document.getElementById('batchWorkerName').value.trim();
    if (!name) {
      showNotification('请输入 Worker 名称', 'error');
      return;
    }
    
    const selectedEmails = Array.from(document.querySelectorAll('.batch-acc-chk:checked')).map(cb => cb.value);
    if (selectedEmails.length === 0) {
      showNotification('请至少选择一个账号', 'error');
      return;
    }
    
    const sourceType = document.getElementById('batchScriptSourceType').value;
    let scriptUrl = '';
    if (sourceType === 'builtin') {
      scriptUrl = document.getElementById('batchBuiltinSelect').value;
    } else {
      scriptUrl = document.getElementById('batchScriptUrl').value.trim();
      if (!scriptUrl) {
        showNotification('请输入脚本 URL', 'error');
        return;
      }
    }
    
    // 获取环境变量
    const envVars = [];
    document.querySelectorAll('#batchEnvList .env-row').forEach(row => {
      const key = row.querySelector('input').value.trim();
      const value = row.querySelector('textarea').value;
      if (key) envVars.push({ type: 'plain_text', name: key, text: value });
    });
    
    const enableSubdomain = document.getElementById('batchEnableSubdomain').checked;
    
    // 获取账号列表
    const accountsRes = await fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'get-accounts' })
    });
    const accountsData = await accountsRes.json();
    const allAccounts = accountsData.accounts || [];
    
    // 获取脚本
    appendBatchLog('正在获取脚本...', '#60a5fa');
    let scriptContent = '';
    try {
      const scriptRes = await api('fetch-external-script', { url: scriptUrl });
      if (scriptRes.success) {
        scriptContent = scriptRes.content;
        appendBatchLog('脚本获取成功', '#4ade80');
      } else {
        appendBatchLog('脚本获取失败: ' + scriptRes.error, '#ef4444');
        return;
      }
    } catch (e) {
      appendBatchLog('脚本获取异常: ' + e.message, '#ef4444');
      return;
    }
    
    document.getElementById('batchLog').innerHTML = '';
    appendBatchLog('开始批量创建，共 ' + selectedEmails.length + ' 个账号', '#fcd34d');
    
    for (const email of selectedEmails) {
      const account = allAccounts.find(a => a.email === email);
      if (!account) continue;
      
      appendBatchLog('处理账号: ' + email);
      
      try {
        // 获取账户 ID
        const accountIdRes = await api('get-account-id', { email: account.email, key: account.key });
        if (!accountIdRes.success) {
          appendBatchLog('  ❌ 获取账户ID失败', '#ef4444');
          continue;
        }
        const accountId = accountIdRes.accountId;
        
        // 部署
        const deployRes = await api('deploy-worker', {
          email: account.email,
          key: account.key,
          accountId,
          scriptName: name,
          scriptSource: scriptContent,
          metadataBindings: envVars
        });
        
        if (deployRes.success) {
          appendBatchLog('  ✅ 部署成功', '#4ade80');
          
          if (enableSubdomain) {
            const toggleRes = await api('toggle-worker-subdomain', {
              email: account.email,
              key: account.key,
              accountId,
              scriptName: name,
              enabled: true
            });
            if (toggleRes.success) {
              // 获取子域名
              const subRes = await api('get-workers-subdomain', { email: account.email, key: account.key, accountId });
              if (subRes.success && subRes.result && subRes.result.subdomain) {
                appendBatchLog('  🔗 https://' + name + '.' + subRes.result.subdomain + '.workers.dev', '#60a5fa');
              }
            }
          }
        } else {
          appendBatchLog('  ❌ 部署失败: ' + (deployRes.error || '未知错误'), '#ef4444');
        }
      } catch (e) {
        appendBatchLog('  ❌ 异常: ' + e.message, '#ef4444');
      }
    }
    
    appendBatchLog('批量创建完成', '#fcd34d');
  }
  
  // KV 管理
  async function refreshKV() {
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('list-kv-namespaces', { accountId });
    const container = document.getElementById('kvList');
    if (!res.success || !res.result || res.result.length === 0) {
      container.innerHTML = '<div class="small">暂无 KV 命名空间</div>';
      return;
    }
    container.innerHTML = res.result.map(ns => \`
      <div class="worker-row" style="display:flex;justify-content:space-between;align-items:center">
        <div><strong>\${escapeHtml(ns.title || ns.id)}</strong><div class="small">\${ns.id}</div></div>
        <button class="btn danger small" onclick="deleteKV('\${ns.id}')">删除</button>
      </div>
    \`).join('');
  }
  
  function openCreateKV() {
    document.getElementById('createKVModal').style.display = 'flex';
  }
  
  function closeCreateKVModal() {
    document.getElementById('createKVModal').style.display = 'none';
  }
  
  async function confirmCreateKV() {
    const name = document.getElementById('kvName').value.trim();
    if (!name) {
      showNotification('请输入名称', 'error');
      return;
    }
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('create-kv-namespace', { accountId, title: name });
    if (res.success) {
      showNotification('创建成功');
      closeCreateKVModal();
      refreshKV();
    } else {
      showNotification(res.error || '创建失败', 'error');
    }
  }
  
  async function deleteKV(namespaceId) {
    if (!confirm('确定删除此 KV 命名空间吗？')) return;
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('delete-kv-namespace', { accountId, namespaceId });
    if (res.success) {
      showNotification('删除成功');
      refreshKV();
    } else {
      showNotification(res.error || '删除失败', 'error');
    }
  }
  
  // D1 管理
  async function refreshD1() {
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('list-d1', { accountId });
    const container = document.getElementById('d1List');
    if (!res.success || !res.result || res.result.length === 0) {
      container.innerHTML = '<div class="small">暂无 D1 数据库</div>';
      return;
    }
    container.innerHTML = res.result.map(db => \`
      <div class="worker-row" style="display:flex;justify-content:space-between;align-items:center">
        <div><strong>\${escapeHtml(db.name)}</strong><div class="small">\${db.uuid || db.id}</div></div>
        <button class="btn danger small" onclick="deleteD1('\${db.uuid || db.id}')">删除</button>
      </div>
    \`).join('');
  }
  
  function openCreateD1() {
    document.getElementById('createD1Modal').style.display = 'flex';
  }
  
  function closeCreateD1Modal() {
    document.getElementById('createD1Modal').style.display = 'none';
  }
  
  async function confirmCreateD1() {
    const name = document.getElementById('d1Name').value.trim();
    if (!name) {
      showNotification('请输入名称', 'error');
      return;
    }
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('create-d1-database', { accountId, name });
    if (res.success) {
      showNotification('创建成功');
      closeCreateD1Modal();
      refreshD1();
    } else {
      showNotification(res.error || '创建失败', 'error');
    }
  }
  
  async function deleteD1(databaseId) {
    if (!confirm('确定删除此 D1 数据库吗？')) return;
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('delete-d1-database', { accountId, databaseId });
    if (res.success) {
      showNotification('删除成功');
      refreshD1();
    } else {
      showNotification(res.error || '删除失败', 'error');
    }
  }
  
  // DNS 管理
  async function refreshZones() {
    const res = await api('list-zones');
    const container = document.getElementById('zonesList');
    if (!res.success || !res.result || res.result.length === 0) {
      container.innerHTML = '<div class="small">暂无域名</div>';
      return;
    }
    container.innerHTML = res.result.map(zone => \`
      <div class="worker-row" style="display:flex;justify-content:space-between;align-items:center">
        <div><strong>\${escapeHtml(zone.name)}</strong><div class="small">\${zone.status === 'active' ? '已激活' : '待处理'}</div></div>
        <div class="btns">
          <button class="btn small" onclick="viewDNS('\${zone.id}', '\${escapeHtml(zone.name)}')">DNS 记录</button>
          <button class="btn danger small" onclick="deleteZone('\${zone.id}')">删除</button>
        </div>
      </div>
    \`).join('');
  }
  
  function viewDNS(zoneId, zoneName) {
    currentZoneId = zoneId;
    document.getElementById('zonesCard').style.display = 'none';
    document.getElementById('dnsCard').style.display = 'block';
    document.getElementById('selectedZoneName').textContent = zoneName + ' - DNS 记录';
    refreshDNSRecords();
  }
  
  function backToZones() {
    document.getElementById('zonesCard').style.display = 'block';
    document.getElementById('dnsCard').style.display = 'none';
    currentZoneId = null;
    refreshZones();
  }
  
  async function refreshDNSRecords() {
    if (!currentZoneId) return;
    const res = await api('list-dns-records', { zoneId: currentZoneId });
    const container = document.getElementById('dnsRecordsList');
    if (!res.success || !res.result || res.result.length === 0) {
      container.innerHTML = '<div class="small">暂无 DNS 记录</div><button class="btn small" onclick="openAddDNS()">添加记录</button>';
      return;
    }
    container.innerHTML = \`
      <button class="btn small" style="margin-bottom:12px" onclick="openAddDNS()">+ 添加记录</button>
      <table style="width:100%;border-collapse:collapse">
        <thead><tr><th>类型</th><th>名称</th><th>内容</th><th>TTL</th><th>代理</th><th>操作</th></tr></thead>
        <tbody>
          \${res.result.map(r => \`
            <tr style="border-bottom:1px solid #eef2f6">
              <td>\${r.type}</td><td>\${escapeHtml(r.name)}</td><td>\${escapeHtml(r.content)}</td>
              <td>\${r.ttl}</td><td>\${r.proxied ? '开启' : '关闭'}</td>
              <td><button class="btn small" onclick="deleteDNS('\${r.id}')">删除</button></td>
            </tr>
          \`).join('')}
        </tbody>
      </table>
    \`;
  }
  
  function openAddDNS() {
    document.getElementById('addDNSModal').style.display = 'flex';
  }
  
  function closeAddDNSModal() {
    document.getElementById('addDNSModal').style.display = 'none';
  }
  
  async function confirmAddDNS() {
    const type = document.getElementById('dnsType').value;
    const name = document.getElementById('dnsName').value.trim();
    const content = document.getElementById('dnsContent').value.trim();
    const ttl = parseInt(document.getElementById('dnsTtl').value);
    const proxied = document.getElementById('dnsProxied').checked;
    
    const res = await api('create-dns-record', { zoneId: currentZoneId, type, name, content, ttl, proxied });
    if (res.success) {
      showNotification('DNS 记录添加成功');
      closeAddDNSModal();
      refreshDNSRecords();
    } else {
      showNotification(res.error || '添加失败', 'error');
    }
  }
  
  async function deleteDNS(recordId) {
    if (!confirm('确定删除此 DNS 记录吗？')) return;
    const res = await api('delete-dns-record', { zoneId: currentZoneId, recordId });
    if (res.success) {
      showNotification('删除成功');
      refreshDNSRecords();
    } else {
      showNotification(res.success || '删除失败', 'error');
    }
  }
  
  function openAddZone() {
    document.getElementById('addZoneModal').style.display = 'flex';
  }
  
  function closeAddZoneModal() {
    document.getElementById('addZoneModal').style.display = 'none';
  }
  
  async function confirmAddZone() {
    const name = document.getElementById('zoneName').value.trim();
    if (!name) {
      showNotification('请输入域名', 'error');
      return;
    }
    const res = await api('create-zone', { name });
    if (res.success) {
      showNotification('域名添加成功，请在域名注册商处修改 NS 记录');
      closeAddZoneModal();
      refreshZones();
    } else {
      showNotification(res.error || '添加失败', 'error');
    }
  }
  
  async function deleteZone(zoneId) {
    if (!confirm('确定删除此域名吗？')) return;
    const res = await api('delete-zone', { zoneId });
    if (res.success) {
      showNotification('删除成功');
      refreshZones();
    } else {
      showNotification(res.error || '删除失败', 'error');
    }
  }
  
  // 子域名设置
  async function loadSubdomain() {
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('get-workers-subdomain', { accountId });
    if (res.success && res.result && res.result.subdomain) {
      document.getElementById('subdomainInput').value = res.result.subdomain;
    }
  }
  
  async function saveSubdomain() {
    const subdomain = document.getElementById('subdomainInput').value.trim();
    if (!subdomain) {
      showNotification('请输入子域名', 'error');
      return;
    }
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('put-workers-subdomain', { accountId, subdomain });
    if (res.success) {
      showNotification('子域名设置成功');
      refreshWorkers();
    } else {
      showNotification(res.error || '设置失败', 'error');
    }
  }
  
  // 账号切换和退出
  function switchAccount() {
    window.location.href = '/login';
  }
  
  function logout() {
    localStorage.removeItem('cf_active_email');
    localStorage.removeItem('cf_active_key');
    window.location.href = '/login';
  }
  
  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>]/g, function(m) {
      if (m === '&') return '&amp;';
      if (m === '<') return '&lt;';
      if (m === '>') return '&gt;';
      return m;
    });
  }
  
  // 初始化
  (function init() {
    const creds = getActiveCreds();
    if (!creds.email || !creds.key) {
      window.location.href = '/login';
      return;
    }
    document.getElementById('currentAccount').textContent = creds.email;
    
    // 设置导航
    document.querySelectorAll('.nav .item').forEach(item => {
      item.addEventListener('click', () => navTo(item.dataset.page));
    });
    
    // 设置批量创建的切换
    document.getElementById('batchScriptSourceType').addEventListener('change', toggleBatchSourceInput);
    
    // 加载 Workers
    setTimeout(() => refreshWorkers(), 100);
  })();
  
  // 导出全局函数
  window.navTo = navTo;
  window.refreshWorkers = refreshWorkers;
  window.openCreateWorker = openCreateWorker;
  window.closeCreateWorkerModal = closeCreateWorkerModal;
  window.confirmCreateWorker = confirmCreateWorker;
  window.editWorker = editWorker;
  window.deleteWorker = deleteWorker;
  window.openEnvFor = openEnvFor;
  window.closeEnvModal = closeEnvModal;
  window.saveEnvVars = saveEnvVars;
  window.addEnvRow = addEnvRow;
  window.openAddDomain = openAddDomain;
  window.closeAddDomainModal = closeAddDomainModal;
  window.confirmAddDomain = confirmAddDomain;
  window.toggleSubdomain = toggleSubdomain;
  window.deleteDomain = deleteDomain;
  window.refreshKV = refreshKV;
  window.openCreateKV = openCreateKV;
  window.closeCreateKVModal = closeCreateKVModal;
  window.confirmCreateKV = confirmCreateKV;
  window.deleteKV = deleteKV;
  window.refreshD1 = refreshD1;
  window.openCreateD1 = openCreateD1;
  window.closeCreateD1Modal = closeCreateD1Modal;
  window.confirmCreateD1 = confirmCreateD1;
  window.deleteD1 = deleteD1;
  window.refreshZones = refreshZones;
  window.openAddZone = openAddZone;
  window.closeAddZoneModal = closeAddZoneModal;
  window.confirmAddZone = confirmAddZone;
  window.viewDNS = viewDNS;
  window.backToZones = backToZones;
  window.openAddDNS = openAddDNS;
  window.closeAddDNSModal = closeAddDNSModal;
  window.confirmAddDNS = confirmAddDNS;
  window.deleteDNS = deleteDNS;
  window.deleteZone = deleteZone;
  window.loadSubdomain = loadSubdomain;
  window.saveSubdomain = saveSubdomain;
  window.switchAccount = switchAccount;
  window.logout = logout;
  window.toggleBatchSourceInput = toggleBatchSourceInput;
  window.addBatchEnvRow = addBatchEnvRow;
  window.startBatchCreate = startBatchCreate;
  window.loadBatchAccounts = loadBatchAccounts;
})();`;
}

// 注意：此代码需要在 Cloudflare Workers 中部署，并绑定 KV 命名空间（变量名 MY_KV）
