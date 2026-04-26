// =============== Worker 主文件 - Cloudflare Manager ===============
// 支持加密存储凭据到 KV，跨浏览器使用

export default {
  async fetch(request, env, ctx) {
    return await handleRequest(request, env);
  }
};

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';

// 加密相关常量
const IV_LENGTH = 12;
const SALT_LENGTH = 16;

// 生成加密密钥
async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// 加密函数
async function encrypt(text, password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  
  const key = await deriveKey(password, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(text)
  );
  
  const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  result.set(salt, 0);
  result.set(iv, salt.length);
  result.set(new Uint8Array(encrypted), salt.length + iv.length);
  
  return btoa(String.fromCharCode(...result));
}

// 解密函数
async function decrypt(encryptedBase64, password) {
  const decoder = new TextDecoder();
  const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
  
  const salt = encrypted.slice(0, SALT_LENGTH);
  const iv = encrypted.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const data = encrypted.slice(SALT_LENGTH + IV_LENGTH);
  
  const key = await deriveKey(password, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    data
  );
  
  return decoder.decode(decrypted);
}

// 生成 session token
function generateSessionToken() {
  return crypto.randomUUID();
}

// ---------------- Router ----------------
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const p = url.pathname;

  // 检查是否需要配置
  const isConfigured = await env.MY_KV.get('config:is_configured');
  
  // 首次配置页面
  if (p === '/setup' && request.method === 'GET' && !isConfigured) {
    return new Response(renderSetupHTML(), { 
      headers: { 'content-type': 'text/html; charset=utf-8' } 
    });
  }
  
  // API 路由
  if (p === '/api' && request.method === 'POST') {
    return handleAPI(request, env);
  }
  
  // 静态资源
  if (p === '/static.js' && request.method === 'GET') {
    return new Response(renderStaticJS(), { 
      headers: { 
        'content-type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate'
      } 
    });
  }
  
  // 主页重定向
  if (request.method === 'GET' && (p === '/' || p === '/index.html')) {
    if (!isConfigured) {
      return Response.redirect(`${url.origin}/setup`, 302);
    }
    return Response.redirect(`${url.origin}/login`, 302);
  }
  
  // 登录页面
  if (request.method === 'GET' && (p === '/login' || p === '/login/')) {
    if (!isConfigured) {
      return Response.redirect(`${url.origin}/setup`, 302);
    }
    return new Response(renderLoginHTML(), { 
      headers: { 'content-type': 'text/html; charset=utf-8' } 
    });
  }
  
  // Worker 管理页面
  if (request.method === 'GET' && p.startsWith('/workers')) {
    const sessionToken = request.headers.get('X-Session-Token') || url.searchParams.get('session');
    
    if (sessionToken) {
      const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
      if (session && session.expires > Date.now()) {
        return new Response(renderAppHTML(), { 
          headers: { 'content-type': 'text/html; charset=utf-8' } 
        });
      }
    }
    
    return Response.redirect(`${url.origin}/login?redirect=${encodeURIComponent(p)}`, 302);
  }

  return new Response('Not Found', { status: 404 });
}

// ---------------- API handler ----------------
async function handleAPI(req, env) {
  const payload = await safeJSON(req);
  const action = payload.action;
  
  if (!action) return json({ success: false, error: 'action required' }, 400);
  
  // 首次配置
  if (action === 'setup-credentials') {
    const { email, key, masterPassword } = payload;
    
    if (!email || !key || !masterPassword) {
      return json({ success: false, error: '缺少必要参数' }, 400);
    }
    
    const testResult = await cfAny('GET', '/accounts', email, key);
    if (!testResult.success && !testResult.result) {
      return json({ 
        success: false, 
        error: 'Cloudflare 凭据无效：' + (testResult.errors?.[0]?.message || '验证失败')
      });
    }
    
    const credentials = JSON.stringify({ email, key });
    const encryptedCredentials = await encrypt(credentials, masterPassword);
    
    await env.MY_KV.put('config:credentials', encryptedCredentials);
    await env.MY_KV.put('config:is_configured', 'true');
    await env.MY_KV.put('config:setup_time', Date.now().toString());
    
    return json({ success: true, message: '配置已保存' });
  }
  
  // 登录
  if (action === 'login') {
    const { masterPassword } = payload;
    
    if (!masterPassword) {
      return json({ success: false, error: '请输入访问密码' }, 400);
    }
    
    const encryptedCredentials = await env.MY_KV.get('config:credentials');
    if (!encryptedCredentials) {
      return json({ success: false, error: '系统未配置，请先访问 /setup 进行配置' }, 400);
    }
    
    try {
      const credentialsJson = await decrypt(encryptedCredentials, masterPassword);
      const { email, key } = JSON.parse(credentialsJson);
      
      const testResult = await cfAny('GET', '/accounts', email, key);
      if (!testResult.success && !testResult.result) {
        return json({ success: false, error: 'Cloudflare 凭据已失效，请重新配置' });
      }
      
      const sessionToken = generateSessionToken();
      await env.MY_KV.put(`session:${sessionToken}`, JSON.stringify({
        email,
        key,
        expires: Date.now() + 8 * 3600000
      }), { expirationTtl: 28800 });
      
      return json({ success: true, sessionToken, expiresIn: 28800 });
      
    } catch (error) {
      return json({ success: false, error: '访问密码错误' }, 401);
    }
  }
  
  // 登出
  if (action === 'logout') {
    const { sessionToken } = payload;
    if (sessionToken) {
      await env.MY_KV.delete(`session:${sessionToken}`);
    }
    return json({ success: true });
  }
  
  // 需要 Cloudflare 凭据的操作
  const needsCreds = new Set([
    'list-accounts', 'list-workers', 'get-worker-script', 'deploy-worker',
    'list-kv-namespaces', 'list-d1', 'put-worker-variables', 'get-worker-variables',
    'get-workers-subdomain', 'put-workers-subdomain', 'list-dns', 'delete-worker',
    'create-kv-namespace', 'delete-kv-namespace', 'put-kv-value', 'get-kv-value', 'delete-kv-value',
    'list-kv-keys', 'create-d1-database', 'delete-d1-database', 'execute-d1-query',
    'list-zones', 'create-zone', 'delete-zone', 'list-dns-records', 'create-dns-record',
    'delete-dns-record', 'update-dns-record', 'toggle-worker-domain', 'get-worker-analytics',
    'get-usage-today', 'get-worker-domains', 'toggle-worker-subdomain', 'add-worker-domain',
    'delete-worker-domain', 'get-worker-bindings', 'fetch-external-script'
  ]);
  
  if (needsCreds.has(action)) {
    const sessionToken = payload.sessionToken;
    if (!sessionToken) {
      return json({ success: false, error: '请先登录' }, 401);
    }
    
    const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
    if (!session || session.expires < Date.now()) {
      return json({ success: false, error: '会话已过期，请重新登录' }, 401);
    }
    
    payload.email = session.email;
    payload.key = session.key;
  }
  
  try {
    switch(action) {
      case 'fetch-external-script': {
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
      
      case 'get-worker-bindings': {
        const { scriptName } = payload;
        if (!scriptName) return json({ success: false, error: 'scriptName required' }, 400);
        if (!payload.accountId) return json({ success: false, error: 'accountId required' }, 400);
        try {
          const result = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, payload.email, payload.key);
          return json({ success: true, bindings: result.success ? result.result : [] });
        } catch (e) {
          return json({ success: false, error: '获取绑定信息失败: ' + e.message });
        }
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
            form.append('worker.js', new Blob([finalScript], { type:'application/javascript+module' }), 'worker.js');
        } else {
            metadata.body_part = 'script';
            form.append('metadata', JSON.stringify(metadata));
            form.append('script', new Blob([finalScript], { type:'application/javascript' }), 'worker.js');
        }

        const uploadUrl = `${CF_API_BASE}/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}`;
        const resp = await fetch(uploadUrl, { method:'PUT', headers:{ 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key }, body: form });
        
        let text = "";
        try { text = await resp.text(); } catch(e) { text = "{}"; }
        
        let uploadRes;
        try { uploadRes = JSON.parse(text); } catch { uploadRes = { errors: [{ message: text }] }; }

        if (!resp.ok) return json({ success: false, error: '部署失败: ' + (uploadRes.errors?.[0]?.message || 'Unknown'), upload: uploadRes, uploadStatus: resp.status }, 200); 
        return json({ success: true, message: 'Worker 部署成功', upload: uploadRes });
      }

      case 'put-worker-variables': {
        const { scriptName, variables } = payload;
        if (!scriptName || !Array.isArray(variables) || !payload.accountId) return json({ success: false }, 400);
        
        let currentScript = null;
        let currentBindings = [];
        
        try {
          const bRes = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, payload.email, payload.key);
          if (bRes.success) currentBindings = bRes.result;
        } catch (e) {}
        
        try {
             const scriptRes = await getWorkerScriptInternal(payload.email, payload.key, payload.accountId, scriptName);
             const scriptData = await scriptRes.json();
             if (scriptData.ok && scriptData.rawScript) {
                 currentScript = scriptData.rawScript;
             }
        } catch (e) {}

        if (!currentScript || currentScript.trim() === '') {
             currentScript = "export default { async fetch() { return new Response('Worker updated successfully.'); } };";
        }
        
        const envBindings = variables.map(v => ({ type: v.type==='secret_text'?'secret_text':'plain_text', name: v.name, text: String(v.value) }));
        const otherBindings = currentBindings.filter(b => b.type !== 'plain_text' && b.type !== 'secret_text');
        const existingNames = new Set(otherBindings.map(b => b.name));
        const safeEnvBindings = envBindings.filter(b => !existingNames.has(b.name));

        const allBindings = [...otherBindings, ...safeEnvBindings].map(b => {
             if(b.type === 'd1' || b.type === 'd1_database') return { type: 'd1', id: b.id || b.database_id, name: b.name };
             if(b.type === 'kv_namespace') return { type: 'kv_namespace', namespace_id: b.namespace_id || b.id, name: b.name };
             delete b.last_deployed_from;
             return b;
        });
        
        const isModule = currentScript.includes('export default') || currentScript.includes('export {');
        const form = new FormData();
        const metadata = { bindings: allBindings };

        if (isModule) {
            metadata.main_module = 'worker.js';
            form.append('metadata', JSON.stringify(metadata));
            form.append('worker.js', new Blob([currentScript], { type:'application/javascript+module' }), 'worker.js');
        } else {
            metadata.body_part = 'script';
            form.append('metadata', JSON.stringify(metadata));
            form.append('script', new Blob([currentScript], { type:'application/javascript' }), 'worker.js');
        }
        
        const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}`, { method: 'PUT', headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key }, body: form });
        return json({ success: r.ok, message: r.ok ? 'Saved' : 'Failed', details: await r.text() });
      }

      case 'get-worker-variables': {
        const { scriptName } = payload;
        if (!scriptName || !payload.accountId) return json({ success: false }, 400);
        const r = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, payload.email, payload.key);
        const vars = [];
        if (r.success && r.result) r.result.forEach(b => { if(b.type === 'plain_text' || b.type === 'secret_text') vars.push({ name:b.name, type:b.type, value:b.text||'' }); });
        return json({ success: true, result: { vars } });
      }
      
      case 'get-worker-analytics': { 
        const { scriptName } = payload; 
        if (!scriptName || !payload.accountId) return json({ success: false }, 400); 
        const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}/analytics/summary`, { headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key } }); 
        if (r.ok) return json({ success: true, data: (await r.json()).result || {} }); 
        return json({ success: false, error: 'Error' }); 
      }
      
      case 'get-usage-today': { 
        if (!payload.accountId) return json({ success: false }, 400); 
        const { accountId, email, key: apikey } = payload; 
        const now = new Date(); 
        const end = now.toISOString(); 
        now.setUTCHours(0, 0, 0, 0); 
        const start = now.toISOString(); 
        try { 
          const r = await fetch("https://api.cloudflare.com/client/v4/graphql", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Auth-Email": email,
              "X-Auth-Key": apikey
            },
            body: JSON.stringify({
              query: `query getBillingMetrics($accountId: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
                viewer {
                  accounts(filter: { accountTag: $accountId }) {
                    pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) {
                      sum { requests }
                    }
                    workersInvocationsAdaptive(limit: 10000, filter: $filter) {
                      sum { requests }
                    }
                  }
                }
              }`,
              variables: { accountId, filter: { datetime_geq: start, datetime_leq: end } }
            })
          }); 
          if (!r.ok) return json({ success: true, data: { total: 0, workers: 0, pages: 0, percentage: 0 } }); 
          const res = await r.json(); 
          const ac = res?.data?.viewer?.accounts?.[0]; 
          const p = (ac?.pagesFunctionsInvocationsAdaptiveGroups || []).reduce((t, i) => t + (i?.sum?.requests || 0), 0); 
          const w = (ac?.workersInvocationsAdaptive || []).reduce((t, i) => t + (i?.sum?.requests || 0), 0); 
          return json({ success: true, data: { total: p + w, workers: w, pages: p, percentage: Math.min(100, ((p + w) / 100000) * 100) } }); 
        } catch(e) { 
          return json({ success: true, data: { total: 0, workers: 0, pages: 0, percentage: 0 } }); 
        } 
      }
      
      case 'list-kv-namespaces': 
        return json(await cfGet(`/accounts/${payload.accountId || await getAccountId(payload.email, payload.key)}/storage/kv/namespaces`, payload.email, payload.key));
      
      case 'create-kv-namespace': 
        return json(await cfPost(`/accounts/${payload.accountId}/storage/kv/namespaces`, payload.email, payload.key, { title: payload.title }));
      
      case 'delete-kv-namespace': 
        return json(await cfDelete(`/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}`, payload.email, payload.key));
      
      case 'list-kv-keys': 
        return json(await cfGet(`/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}/keys`, payload.email, payload.key));
      
      case 'get-kv-value': { 
        const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}/values/${encodeURIComponent(payload.key)}`, { 
          headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key }
        }); 
        return json({ success: r.ok, value: await r.text() }); 
      }
      
      case 'put-kv-value': { 
        const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}/values/${encodeURIComponent(payload.key)}`, { 
          method: 'PUT', 
          headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key }, 
          body: payload.value 
        }); 
        return json({ success: r.ok }); 
      }
      
      case 'delete-kv-value': 
        return json(await cfDelete(`/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}/values/${encodeURIComponent(payload.key)}`, payload.email, payload.key));

      case 'list-d1': 
        return json(await cfGet(`/accounts/${payload.accountId || await getAccountId(payload.email, payload.key)}/d1/database`, payload.email, payload.key));
      
      case 'create-d1-database': 
        return json(await cfPost(`/accounts/${payload.accountId}/d1/database`, payload.email, payload.key, { name: payload.name }));
      
      case 'delete-d1-database': 
        return json(await cfDelete(`/accounts/${payload.accountId}/d1/database/${payload.databaseId}`, payload.email, payload.key));
      
      case 'execute-d1-query': 
        return json(await cfPost(`/accounts/${payload.accountId}/d1/database/${payload.databaseId}/query`, payload.email, payload.key, { sql: payload.query }));

      case 'get-workers-subdomain': 
        return json(await cfGet(`/accounts/${payload.accountId}/workers/subdomain`, payload.email, payload.key));
      
      case 'put-workers-subdomain': 
        return json({ success: true, data: await cfPutRaw(`/accounts/${payload.accountId}/workers/subdomain`, payload.email, payload.key, { subdomain: payload.subdomain }) });
      
      case 'toggle-worker-subdomain': 
        return json(await cfPost(`/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(payload.scriptName)}/subdomain`, payload.email, payload.key, { enabled: payload.enabled }));

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
      
      case 'add-worker-domain': {
        const { scriptName, hostname } = payload;
        const cleanHost = hostname.replace(/^https?:\/\//, '').replace(/\/$/, '').trim();
        const zonesRes = await cfGet('/zones', payload.email, payload.key);
        const zone = zonesRes.success ? zonesRes.result.find(z => cleanHost === z.name || cleanHost.endsWith('.' + z.name)) : null;
        if (!zone) return json({ success: false, error: '未找到匹配的 Zone' });
        const res = await cfPutRaw(`/zones/${zone.id}/workers/domains`, payload.email, payload.key, { 
          environment: "production", hostname: cleanHost, service: scriptName, zone_id: zone.id 
        });
        return json({ success: res.success || !!res.result, error: res.errors?.[0]?.message });
      }
      
      case 'delete-worker-domain': {
        const url = `${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(payload.scriptName)}/domains/${payload.domainId}`;
        const r = await fetch(url, { method: 'DELETE', headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key } });
        return json({ success: r.ok });
      }
      
      case 'delete-worker': {
        const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(payload.scriptName)}`, { 
          method: 'DELETE', 
          headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key } 
        });
        return json({ success: r.ok });
      }

      default:
        return json({ success: false, error: 'unknown action' }, 400);
    }
  } catch(e) {
    return json({ success: false, error: String(e) }, 500);
  }
}

async function getWorkerScriptInternal(email, key, accountId, scriptName) {
  if (!scriptName) return json({ success: false, error: 'scriptName required' }, 400);
  const accId = accountId || await getAccountId(email, key);
  const url = `${CF_API_BASE}/accounts/${accId}/workers/scripts/${encodeURIComponent(scriptName)}`;
  const resp = await fetch(url, { method: 'GET', headers: { 'X-Auth-Email': email, 'X-Auth-Key': key } });
  
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
            part.includes('Content-Type: application/x-javascript') ||
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
    if (!scriptContent) {
      const jsMatch = text.match(/Content-Type:\s*application\/javascript(?:[\+a-z]*)?[\s\S]*?\r?\n\r?\n([\s\S]*?)(?=\r?\n--)/i);
      if (jsMatch) scriptContent = jsMatch[1].trim();
    }
  } 
  else if (!text.trim().startsWith('{')) {
    scriptContent = text;
  } 
  else {
    try {
      const j = JSON.parse(text);
      if (j.result && j.result.script) scriptContent = j.result.script;
    } catch(e) {}
  }

  if (!scriptContent) {
    if (text.includes('export default') || text.includes('addEventListener')) {
      const rawMatch = text.match(/(export\s+default[\s\S]+|addEventListener[\s\S]+)/);
      if (rawMatch) {
        scriptContent = rawMatch[0].split(/\r?\n--/)[0].trim();
      } else {
        scriptContent = text;
      }
    }
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

function renderSetupHTML() {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>首次配置 - Cloudflare Manager</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  .setup-container {
    background: white;
    border-radius: 20px;
    padding: 40px;
    max-width: 500px;
    width: 100%;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
  }
  h2 {
    color: #1a202c;
    margin-bottom: 8px;
    font-size: 28px;
  }
  .subtitle {
    color: #718096;
    margin-bottom: 30px;
    font-size: 14px;
  }
  .form-group {
    margin-bottom: 20px;
  }
  label {
    display: block;
    margin-bottom: 8px;
    color: #2d3748;
    font-weight: 500;
    font-size: 14px;
  }
  input {
    width: 100%;
    padding: 12px;
    border: 2px solid #e2e8f0;
    border-radius: 10px;
    font-size: 14px;
    transition: all 0.3s;
  }
  input:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
  }
  button {
    width: 100%;
    padding: 12px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border: none;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.2s;
  }
  button:hover {
    transform: translateY(-2px);
  }
  .note {
    margin-top: 20px;
    padding: 12px;
    background: #fef5e7;
    border-left: 4px solid #f39c12;
    font-size: 13px;
    color: #856404;
  }
  .error {
    color: #e53e3e;
    font-size: 13px;
    margin-top: 8px;
    display: none;
  }
</style>
</head>
<body>
<div class="setup-container">
  <h2>🚀 欢迎使用 Cloudflare Manager</h2>
  <div class="subtitle">首次使用，请完成以下配置</div>
  
  <div class="form-group">
    <label>Cloudflare 账号邮箱</label>
    <input type="email" id="email" placeholder="your@email.com">
  </div>
  
  <div class="form-group">
    <label>Cloudflare Global API Key</label>
    <input type="password" id="apiKey" placeholder="您的 Global API Key">
    <div class="note">可在 Cloudflare 控制台右上角 → 我的资料 → API 令牌中获取</div>
  </div>
  
  <div class="form-group">
    <label>设置访问密码</label>
    <input type="password" id="masterPassword" placeholder="用于在其他浏览器登录">
    <div class="note">⚠️ 请务必记住此密码！凭据将加密存储，忘记密码无法找回</div>
  </div>
  
  <div class="form-group">
    <label>确认访问密码</label>
    <input type="password" id="confirmPassword" placeholder="再次输入密码">
  </div>
  
  <div id="errorMsg" class="error"></div>
  
  <button onclick="setup()">保存配置并开始使用</button>
</div>

<script>
async function setup() {
  const email = document.getElementById('email').value.trim();
  const apiKey = document.getElementById('apiKey').value.trim();
  const masterPassword = document.getElementById('masterPassword').value;
  const confirmPassword = document.getElementById('confirmPassword').value;
  
  document.getElementById('errorMsg').style.display = 'none';
  
  if (!email || !apiKey || !masterPassword) {
    showError('请填写所有字段');
    return;
  }
  
  if (masterPassword !== confirmPassword) {
    showError('两次输入的密码不一致');
    return;
  }
  
  if (masterPassword.length < 6) {
    showError('访问密码至少需要 6 个字符');
    return;
  }
  
  const btn = document.querySelector('button');
  btn.disabled = true;
  btn.textContent = '验证中...';
  
  try {
    const response = await fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'setup-credentials',
        email: email,
        key: apiKey,
        masterPassword: masterPassword
      })
    });
    
    const result = await response.json();
    
    if (result.success) {
      alert('配置成功！即将跳转到登录页面');
      window.location.href = '/login';
    } else {
      showError(result.error || '配置失败，请检查 Cloudflare 凭据是否正确');
      btn.disabled = false;
      btn.textContent = '保存配置并开始使用';
    }
  } catch (error) {
    showError('网络错误：' + error.message);
    btn.disabled = false;
    btn.textContent = '保存配置并开始使用';
  }
}

function showError(msg) {
  const errorDiv = document.getElementById('errorMsg');
  errorDiv.textContent = msg;
  errorDiv.style.display = 'block';
}
</script>
</body>
</html>`;
}

function renderLoginHTML() {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 - Cloudflare Manager</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  .login-container {
    background: white;
    border-radius: 20px;
    padding: 40px;
    max-width: 450px;
    width: 100%;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
  }
  h2 {
    color: #1a202c;
    margin-bottom: 8px;
    font-size: 28px;
  }
  .subtitle {
    color: #718096;
    margin-bottom: 30px;
    font-size: 14px;
  }
  .form-group {
    margin-bottom: 20px;
  }
  label {
    display: block;
    margin-bottom: 8px;
    color: #2d3748;
    font-weight: 500;
    font-size: 14px;
  }
  input {
    width: 100%;
    padding: 12px;
    border: 2px solid #e2e8f0;
    border-radius: 10px;
    font-size: 14px;
    transition: all 0.3s;
  }
  input:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
  }
  button {
    width: 100%;
    padding: 12px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border: none;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.2s;
  }
  button:hover {
    transform: translateY(-2px);
  }
  .error {
    color: #e53e3e;
    font-size: 13px;
    margin-top: 8px;
    display: none;
    text-align: center;
  }
  .note {
    margin-top: 20px;
    padding: 12px;
    background: #e6f7ff;
    border-left: 4px solid #1890ff;
    font-size: 13px;
    color: #0050b3;
    text-align: center;
  }
</style>
</head>
<body>
<div class="login-container">
  <h2>🔐 访问控制</h2>
  <div class="subtitle">请输入访问密码继续</div>
  
  <div class="form-group">
    <label>访问密码</label>
    <input type="password" id="password" placeholder="请输入管理员设置的密码" onkeypress="if(event.key==='Enter') login()">
  </div>
  
  <div id="errorMsg" class="error"></div>
  
  <button onclick="login()">登录管理后台</button>
  
  <div class="note">
    💡 提示：密码由管理员在首次配置时设置
  </div>
</div>

<script>
let loginInProgress = false;

async function login() {
  if (loginInProgress) return;
  
  const password = document.getElementById('password').value;
  const errorDiv = document.getElementById('errorMsg');
  
  errorDiv.style.display = 'none';
  
  if (!password) {
    errorDiv.textContent = '请输入访问密码';
    errorDiv.style.display = 'block';
    return;
  }
  
  const btn = document.querySelector('button');
  loginInProgress = true;
  const originalText = btn.textContent;
  btn.textContent = '登录中...';
  btn.disabled = true;
  
  try {
    const response = await fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'login',
        masterPassword: password
      })
    });
    
    const result = await response.json();
    
    if (result.success && result.sessionToken) {
      localStorage.setItem('cf_session_token', result.sessionToken);
      const urlParams = new URLSearchParams(window.location.search);
      const redirect = urlParams.get('redirect') || '/workers';
      window.location.href = redirect;
    } else {
      errorDiv.textContent = result.error || '登录失败';
      errorDiv.style.display = 'block';
      btn.disabled = false;
      btn.textContent = originalText;
      loginInProgress = false;
    }
  } catch (error) {
    errorDiv.textContent = '网络错误：' + error.message;
    errorDiv.style.display = 'block';
    btn.disabled = false;
    btn.textContent = originalText;
    loginInProgress = false;
  }
}
</script>
</body>
</html>`;
}

// 由于 renderAppHTML 和 renderStaticJS 非常长，这里提供修改后的关键部分
// 完整代码请参考原文件，主要修改 api 函数使用 sessionToken

function renderAppHTML() {
  // 这个函数与原版基本相同，只是移除 localStorage 中的 email/key 相关代码
  // 由于长度限制，请参考原文件，主要修改 login 和 api 调用方式
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloudflare 第三方管理平台</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#f6f8fa;--card:#fff;--muted:#6b7280;--accent:#2563eb;--danger:#ef4444}
*{box-sizing:border-box}
body{font-family:Inter,Arial;margin:0;background:var(--bg);color:#0f1724}
.app{display:flex;min-height:100vh}
.sidebar{width:260px;background:#fff;border-right:1px solid #eef2f6;padding:22px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}
.logo{display:flex;align-items:center;gap:10px;font-weight:700}
.nav{margin-top:22px}
.nav .item{display:flex;align-items:center;gap:10px;padding:10px;border-radius:8px;color:#334155;margin-bottom:6px;cursor:pointer}
.nav .item.active{background:#f8fafc;font-weight:600}
.main{flex:1;padding:26px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.metric{background:#fff;padding:20px;border-radius:12px;box-shadow:0 6px 18px rgba(2,6,23,0.04);display:flex;flex-direction:column;gap:8px}
.metric .bar{height:8px;background:#eef2ff;border-radius:999px;overflow:hidden}
.metric .bar > i{display:block;height:100%;background:linear-gradient(90deg,#2563eb,#60a5fa);width:35%}
.grid{display:grid;grid-template-columns:1fr;gap:18px}
.card{background:var(--card);padding:18px;border-radius:12px;box-shadow:0 6px 18px rgba(2,6,23,0.04)}
.workers-list{padding:6px}
.worker-row{display:flex;justify-content:space-between;align-items:flex-start;padding:16px;border-radius:10px;border:1px solid #eef2ff;background:#fbfdff;margin-bottom:12px}
.worker-info{flex:1;padding-right:16px}
.worker-right{display:flex;flex-direction:column;align-items:flex-end;gap:10px;min-width:300px}
.worker-tags{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:6px;margin-bottom:4px}
.worker-meta{color:var(--muted);font-size:13px}
.btns{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.btn{padding:8px 10px;border-radius:8px;border:1px solid #e6eef9;background:#fff;cursor:pointer;font-size:12px}
.btn.primary{background:var(--accent);color:#fff;border:0}
.btn.danger{background:#ef4444;color:#fff;border:0}
.btn.success{background:#10b981;color:#fff;border:0}
.btn.small{font-size:11px;padding:4px 8px}
.small{font-size:13px;color:var(--muted)}
.modal{display:none;position:fixed;left:0;top:0;right:0;bottom:0;background:rgba(0,0,0,0.45);align-items:center;justify-content:center;z-index:1000}
.modal-box{width:720px;background:#fff;border-radius:12px;padding:20px;max-height:90vh;overflow:auto}
.modal-box.small{width:480px}
.input{width:100%;padding:10px;border-radius:8px;border:1px solid #e6edf3}
.kv-item{padding:8px;border-radius:8px;border:1px solid #f1f5f9;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}
pre{background:#0b1220;color:#e6f2ff;padding:12px;border-radius:8px;overflow:auto}
.label{font-size:12px;color:#64748b;margin-bottom:6px}
.domain-toggle{display:flex;align-items:center;gap:8px;margin-top:8px}
.switch{position:relative;display:inline-block;width:34px;height:18px}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background-color:#ccc;transition:.4s;border-radius:24px}
.slider:before{position:absolute;content:"";height:14px;width:14px;left:2px;bottom:2px;background-color:white;transition:.4s;border-radius:50%}
input:checked + .slider{background-color:#2563eb}
input:checked + .slider:before{transform:translateX(16px)}
.resource-section{margin-bottom:16px}
.resource-section h4{margin:0 0 8px 0}
.page-content{display:none}
.page-content.active{display:block}
.table{width:100%;border-collapse:collapse;margin-top:12px}
.table th,.table td{padding:12px;text-align:left;border-bottom:1px solid #eef2f6}
.table th{background:#f8fafc;font-weight:600}
.sql-console{background:#0f172a;color:#e2e8f0;padding:16px;border-radius:8px;margin-top:12px}
.sql-console textarea{width:100%;background:#1e293b;color:#e2e8f0;border:1px solid #334155;border-radius:6px;padding:12px;font-family:monospace;min-height:120px}
.sql-results{margin-top:12px;background:#1e293b;padding:12px;border-radius:6px;max-height:300px;overflow:auto}
.zone-row{padding:12px;border:1px solid #eef2ff;border-radius:8px;margin-bottom:8px;background:#fbfdff;cursor:pointer}
.zone-row:hover{background:#f0f9ff}
.dns-record-row{display:flex;justify-content:space-between;align-items:center;padding:8px;border-bottom:1px solid #f1f5f9}
.ns-records{background:#f0f9ff;padding:8px;border-radius:6px;margin-top:8px;font-size:12px}
.zone-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.zone-actions{display:flex;gap:8px}
.dns-table{width:100%;border-collapse:collapse;margin-top:12px}
.dns-table th,.dns-table td{padding:12px;text-align:left;border-bottom:1px solid #eef2f6}
.dns-table th{background:#f8fafc;font-weight:600}
.copy-btn{background:#f1f5f9;border:1px solid #e2e8f0;padding:4px 8px;border-radius:4px;font-size:11px;cursor:pointer;margin-left:4px}
.copy-btn:hover{background:#e2e8f0}
.domain-control{display:flex;align-items:center;gap:6px}
.domain-status{font-size:11px;padding:2px 6px;border-radius:4px}
.domain-status.active{background:#f0fdf4;color:#166534}
.domain-status.inactive{background:#fef2f2;color:#dc2626}
.domain-status.pending{background:#fffbeb;color:#d97706}
.usage-section{margin-bottom:20px}
.usage-breakdown{display:flex;justify-content:space-between;margin-top:12px}
.usage-item{flex:1;text-align:center;padding:12px}
.usage-item .label{font-size:12px;color:#64748b;margin-bottom:4px}
.usage-item .value{font-size:18px;font-weight:600}
.usage-item.workers .value{color:#2563eb}
.usage-item.pages .value{color:#10b981}
.usage-item.total .value{color:#8b5cf6}
.worker-domains{margin-top:8px}
.domain-tag{display:inline-block;padding:4px 8px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;font-size:12px;margin-right:6px;margin-bottom:4px;text-decoration:none;color:#334155}
.domain-tag:hover{background:#f1f5f9}
.domain-tag .domain-status{margin-left:6px}
.domain-tag.workers-dev{background:#eff6ff;border-color:#dbeafe}
.del-domain-btn{display:inline-block;margin-left:4px;width:16px;height:16px;line-height:16px;text-align:center;border-radius:50%;background:#fee2e2;color:#ef4444;font-size:10px;cursor:pointer}
.del-domain-btn:hover{background:#fecaca}
.domain-list-table { width: 100%; border-collapse: collapse; margin-top: 8px; background: #fff; border-radius: 8px; overflow: hidden; border: 1px solid #e2e8f0; }
.domain-list-table th, .domain-list-table td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
.domain-list-table th { background: #f8fafc; color: #64748b; font-weight: 600; }
.domain-list-table tr:last-child td { border-bottom: none; }
.domain-row-actions { display: flex; gap: 8px; justify-content: flex-end; }
.trash-btn { background: none; border: 1px solid #e2e8f0; border-radius: 6px; cursor: pointer; color: #ef4444; padding: 6px 12px; font-size: 11px; display: flex; align-items: center; gap: 4px; }
.trash-btn:hover { background: #fef2f2; }
.ns-pill { display: inline-flex; align-items: center; background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 4px; padding: 2px 6px; font-family: monospace; font-size: 11px; color: #334155; margin-right: 6px; margin-bottom: 4px; }
.ns-copy-icon { margin-left: 4px; cursor: pointer; color: #64748b; display: flex; align-items: center; }
.ns-copy-icon:hover { color: #2563eb; }
.res-tag { font-size: 11px; padding: 2px 8px; border-radius: 6px; border: 1px solid transparent; display: inline-flex; align-items: center; font-weight: 500; }
.res-tag.kv { background: #eff6ff; color: #1e40af; border-color: #bfdbfe; }
.res-tag.d1 { background: #fff7ed; color: #9a3412; border-color: #fed7aa; }
.res-tag.env { background: #f0fdf4; color: #166534; border-color: #bbf7d0; }
.batch-layout { display: flex; gap: 20px; height: calc(100vh - 100px); }
.batch-sidebar { width: 300px; border-right: 1px solid #eef2f6; overflow-y: auto; padding-right: 16px; }
.batch-main { flex: 1; display: flex; flex-direction: column; overflow-y: auto; }
.account-check-item { display: flex; align-items: center; padding: 8px; border-bottom: 1px solid #eef2f6; }
.account-check-item:hover { background: #f8fafc; }
.log-area { background: #1e293b; color: #10b981; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 12px; margin-top: 16px; min-height: 150px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; }
.env-row-batch { display: flex; gap: 8px; margin-top: 6px; }
.acct-row { padding: 10px; border-bottom: 1px solid #eef2f6; display: flex; justify-content: space-between; align-items: center; }
.acct-row:last-child { border-bottom: 0; }
.acct-active { background: #eff6ff; }
.badge { background: #dbeafe; color: #1e40af; font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: 6px; }
</style>
</head>
<body data-page="app">
<div class="app">
  <aside class="sidebar">
    <div class="logo"><span style="font-size:18px">☁️ Cloudflare</span>管理平台</div>
    <nav class="nav">
      <div class="item active" data-page="workers" onclick="navTo('workers')">Workers</div>
      <div class="item" data-page="batch" onclick="navTo('batch')">批量创建 Worker</div>
      <div class="item" data-page="kv" onclick="navTo('kv')">Workers KV</div>
      <div class="item" data-page="d1" onclick="navTo('d1')">D1 数据库</div>
      <div class="item" data-page="dns" onclick="navTo('dns')">域名管理</div>
      <div class="item" data-page="settings" onclick="navTo('settings')">设置</div>
    </nav>
    <div style="margin-top:auto;padding-top:20px;border-top:1px solid #eef2f6">
       <div class="small" style="margin-bottom:4px">当前会话</div>
       <div style="font-weight:600;font-size:13px" id="sessionInfo">已登录</div>
       <div style="margin-top:8px;font-size:11px;color:var(--muted)">
         <span onclick="logout()" style="cursor:pointer;color:#ef4444">退出登录</span>
       </div>
    </div>
  </aside>
  <main class="main">
    <div id="workers-page" class="page-content active">
      <div class="header"><div style="font-size:20px;font-weight:700">Workers 管理</div><div><button class="btn primary" onclick="openCreateWorker()">新建 Worker</button></div></div>
      <div class="metric"><div class="small">今天的请求</div><div style="display:flex;justify-content:space-between;align-items:center"><div style="font-size:28px;font-weight:700" id="metricCount">0 / 100,000</div></div><div class="bar"><i id="metricBar" style="width:0%"></i></div>
        <div class="usage-section"><div class="usage-breakdown"><div class="usage-item workers"><div class="label">WORKERS 请求</div><div class="value" id="workersRequests">0</div></div><div class="usage-item pages"><div class="label">PAGES 请求</div><div class="value" id="pagesRequests">0</div></div><div class="usage-item total"><div class="label">日配额</div><div class="value">100,000</div></div></div></div>
      </div>
      <div class="grid" style="margin-top:16px"><div class="card"><div style="display:flex;justify-content:space-between;align-items:center"><div><h2 style="margin:0">Workers 列表</h2><div class="small">查看和管理您的 Cloudflare Workers</div></div></div><div class="workers-list" id="workersList"></div></div></div>
    </div>
    <div id="batch-page" class="page-content"><div class="header"><div style="font-size:20px;font-weight:700">批量创建 Workers</div></div><div class="batch-layout"><div class="batch-sidebar"><div style="padding-bottom:10px;border-bottom:1px solid #eef2f6;margin-bottom:10px"><span style="font-weight:600">选择账号</span></div><div id="batchAccountList"></div></div><div class="batch-main"><div class="card"><div style="font-weight:600;margin-bottom:12px">基本配置</div><label class="small">Worker 名称</label><input id="batchWorkerName" class="input" placeholder="例如: my-proxy-worker"><div style="margin-top:12px"><label class="small" style="display:flex;align-items:center;cursor:pointer"><input type="checkbox" id="batchEnableSubdomain" checked style="margin-right:8px"> 开启默认域名 (*.workers.dev)</label></div><label class="small" style="display:block;margin-top:12px">代码来源</label><select id="batchScriptSourceType" class="input" onchange="toggleBatchSourceInput()"><option value="builtin">内置模板</option><option value="url">自定义链接 (URL)</option></select><div id="batchSourceBuiltinDiv" style="margin-top:8px"><select id="batchBuiltinSelect" class="input"><option value="">选择模板</option></select></div><div id="batchSourceUrlDiv" style="margin-top:8px;display:none"><input id="batchScriptUrl" class="input" placeholder="https://raw.githubusercontent.com/user/repo/main/worker.js"></div></div><div class="card" style="margin-top:16px"><div style="font-weight:600;margin-bottom:12px">高级绑定配置</div><div><div style="font-size:13px;font-weight:600;margin-bottom:4px">环境变量</div><div id="batchEnvList"></div><button class="btn small" onclick="addBatchEnvRow()">+ 添加变量</button></div><div style="margin-top:12px"><div style="font-size:13px;font-weight:600;margin-bottom:4px">KV 命名空间</div><div style="display:flex;gap:8px"><input id="batchKvBind" class="input" placeholder="绑定名"><input id="batchKvName" class="input" placeholder="KV 空间名称"></div></div><div style="margin-top:12px"><div style="font-size:13px;font-weight:600;margin-bottom:4px">D1 数据库</div><div style="display:flex;gap:8px"><input id="batchD1Bind" class="input" placeholder="绑定名"><input id="batchD1Name" class="input" placeholder="数据库名称"></div></div><button class="btn primary" style="margin-top:16px;width:100%" onclick="startBatchCreate()">开始批量创建</button></div><div><div style="font-weight:600;margin-top:16px">执行日志</div><div id="batchLog" class="log-area">等待开始...</div></div></div></div></div>
    <div id="kv-page" class="page-content"><div class="header"><div style="font-size:20px;font-weight:700">Workers KV 管理</div><div><button class="btn primary" onclick="openCreateKVNamespace()">创建 KV 命名空间</button></div></div><div class="card"><h3 style="margin:0">KV 命名空间列表</h3><div id="kvNamespacesList" style="margin-top:16px"></div></div></div>
    <div id="d1-page" class="page-content"><div class="header"><div style="font-size:20px;font-weight:700">D1 数据库管理</div><div><button class="btn primary" onclick="openCreateD1Database()">创建 D1 数据库</button></div></div><div class="card"><h3 style="margin:0">D1 SQL 数据库</h3><div id="d1DatabasesList" style="margin-top:16px"></div></div><div class="card" style="margin-top:16px"><h4 style="margin:0">SQL 控制台</h4><div style="margin-top:12px"><select id="d1DatabaseSelect" class="input"><option value="">- 选择数据库 -</option></select></div><div class="sql-console"><textarea id="d1Query" placeholder="SELECT * FROM table_name LIMIT 10;"></textarea><button class="btn primary" style="margin-top:8px" onclick="executeD1Query()">执行查询</button></div><div id="d1QueryResults" class="sql-results"></div></div></div>
    <div id="dns-page" class="page-content"><div class="header"><div style="font-size:20px;font-weight:700">域名管理</div><div><button class="btn primary" onclick="openAddZone()">添加新域名</button></div></div><div class="card"><h3 style="margin:0">域名列表</h3><div id="zonesList" style="margin-top:16px"></div></div><div id="dnsRecordsSection" class="card" style="margin-top:16px;display:none"><div class="zone-header"><div><h3 style="margin:0" id="selectedZoneName">域名 DNS 记录</h3><div class="small" id="selectedZoneInfo"></div></div><div class="zone-actions"><button class="btn primary" onclick="openAddDNSRecord()">添加 DNS 记录</button><button class="btn" onclick="backToZones()">返回域名列表</button></div></div><div id="dnsRecordsList"></div></div></div>
    <div id="settings-page" class="page-content"><div class="header"><div style="font-size:20px;font-weight:700">设置</div></div><div class="card"><h3 style="margin:0">Workers 域名设置</h3><div class="small" style="margin-top:8px">设置您的 workers.dev 子域名</div><div style="margin-top:12px"><input id="subdomainInput" class="input" placeholder="输入子域名"><button class="btn primary" style="margin-top:8px" onclick="saveSubdomain()">保存设置</button></div></div><div class="card" style="margin-top:16px; display:flex; justify-content:center; padding:24px;"><a href="https://t.me/yifang_chat" target="_blank" style="text-decoration:none; text-align:center; color:#334155;"><div style="width:60px;height:60px;background:#229ED9;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto;box-shadow:0 4px 10px rgba(34,158,217,0.4)"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg></div><div style="margin-top:10px;font-weight:600;font-size:14px;">反馈加群</div></a></div></div>
  </main>
</div>
<div id="accountModal" class="modal"><div class="modal-box small"><div style="display:flex;justify-content:space-between;margin-bottom:16px"><h3 style="margin:0">切换账号</h3><button onclick="closeAccountSwitcher()">✕</button></div><div id="accountListContainer"></div></div></div>
<div id="envModal" class="modal"><div class="modal-box"><h3>管理环境变量</h3><div id="envRows"></div><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="addEnvRow()">添加变量</button><button class="btn" onclick="saveEnv()">保存</button><button class="btn" onclick="closeEnvModal()">取消</button></div></div></div>
<div id="bindModal" class="modal"><div class="modal-box"><h3>绑定 KV / D1</h3><div style="display:flex;gap:8px;margin-top:8px"><select id="bindType" class="input" onchange="refreshBindList()"><option value="kv">KV 命名空间</option><option value="d1">D1 数据库</option></select></div><div style="margin-top:8px"><select id="bindSelect" class="input"></select></div><div style="margin-top:8px"><input id="bindName" class="input" placeholder="绑定名"></div><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmBind()">确认绑定</button><button class="btn" onclick="closeBindModal()">取消</button></div></div></div>
<div id="createModal" class="modal"><div class="modal-box"><h3>新建 / 编辑 Worker</h3><input id="createName" class="input" placeholder="worker-name"><textarea id="createScript" class="input" rows="10">export default { async fetch(request, env, ctx) { return new Response('Hello World'); } };</textarea><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmCreate()">保存并部署</button><button class="btn" onclick="closeCreate()">取消</button></div></div></div>
<div id="createKVModal" class="modal"><div class="modal-box small"><h3>创建 KV 命名空间</h3><input id="kvNamespaceName" class="input" placeholder="my-kv-namespace"><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmCreateKVNamespace()">创建</button><button class="btn" onclick="closeCreateKVModal()">取消</button></div></div></div>
<div id="kvValueModal" class="modal"><div class="modal-box"><h3>添加/更新键值</h3><input id="kvKey" class="input" placeholder="Key"><textarea id="kvValue" class="input" rows="6" placeholder="Value"></textarea><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmKVPut()">保存</button><button class="btn" onclick="closeKVValueModal()">取消</button></div></div></div>
<div id="createD1Modal" class="modal"><div class="modal-box small"><h3>创建 D1 数据库</h3><input id="d1DatabaseName" class="input" placeholder="my-d1-database"><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmCreateD1Database()">创建</button><button class="btn" onclick="closeCreateD1Modal()">取消</button></div></div></div>
<div id="addDomainModal" class="modal"><div class="modal-box small"><h3>绑定自定义域名</h3><input id="newDomainInput" class="input" placeholder="app.example.com"><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmAddDomain()">绑定</button><button class="btn" onclick="closeAddDomainModal()">取消</button></div></div></div>
<div id="addZoneModal" class="modal"><div class="modal-box small"><h3>添加新域名</h3><input id="zoneName" class="input" placeholder="example.com"><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmAddZone()">添加</button><button class="btn" onclick="closeAddZoneModal()">取消</button></div></div></div>
<div id="addDNSRecordModal" class="modal"><div class="modal-box"><h3>添加 DNS 记录</h3><select id="dnsRecordType" class="input"><option value="A">A</option><option value="AAAA">AAAA</option><option value="CNAME">CNAME</option><option value="MX">MX</option><option value="TXT">TXT</option></select><input id="dnsRecordName" class="input" placeholder="记录名称"><input id="dnsRecordContent" class="input" placeholder="记录内容"><select id="dnsRecordTTL" class="input"><option value="1">自动</option><option value="120">2分钟</option><option value="300">5分钟</option><option value="3600">1小时</option><option value="86400">1天</option></select><label><input type="checkbox" id="dnsRecordProxied"> 启用代理</label><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmAddDNSRecord()">添加记录</button><button class="btn" onclick="closeAddDNSRecordModal()">取消</button></div></div></div>
<div id="editDNSRecordModal" class="modal"><div class="modal-box"><h3>编辑 DNS 记录</h3><select id="editDnsRecordType" class="input"><option value="A">A</option><option value="AAAA">AAAA</option><option value="CNAME">CNAME</option><option value="MX">MX</option><option value="TXT">TXT</option></select><input id="editDnsRecordName" class="input"><input id="editDnsRecordContent" class="input"><select id="editDnsRecordTTL" class="input"><option value="1">自动</option><option value="120">2分钟</option><option value="300">5分钟</option><option value="3600">1小时</option><option value="86400">1天</option></select><label><input type="checkbox" id="editDnsRecordProxied"> 启用代理</label><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmEditDNSRecord()">保存</button><button class="btn" onclick="closeEditDNSRecordModal()">取消</button></div></div></div>
<div id="outModal" class="modal"><div class="modal-box"><h3>调试输出</h3><pre id="debugOut" style="height:300px;overflow:auto"></pre><button class="btn" onclick="closeOut()">关闭</button></div></div>
<script src="/static.js"></script>
</body>
</html>`;
}

function renderStaticJS() {
  return `(function(){
  const DEFAULT_WORKER_SCRIPT = "export default {\\n  async fetch(request, env, ctx) {\\n    return new Response('Hello World');\\n  }\\n};";
  
  function el(id){ return document.getElementById(id); }
  
  function getSessionToken() { return localStorage.getItem('cf_session_token'); }
  
  async function api(action, body) {
    const sessionToken = getSessionToken();
    const payload = Object.assign({ action, sessionToken }, body);
    const r = await fetch('/api', { 
      method: 'POST', 
      headers: { 'Content-Type': 'application/json' }, 
      body: JSON.stringify(payload) 
    });
    try { return await r.json(); } 
    catch (e) { return await r.text(); }
  }
  
  async function logout() {
    await api('logout', { sessionToken: getSessionToken() });
    localStorage.removeItem('cf_session_token');
    window.location.href = '/login';
  }
  
  function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.innerHTML = message;
    notification.style.cssText = \`
      position: fixed; top: 20px; right: 20px; padding: 12px 20px; border-radius: 8px;
      color: white; background: \${type === 'success' ? '#10b981' : '#ef4444'};
      box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 10000; max-width: 400px;
      animation: slideIn 0.3s ease-out;
    \`;
    document.body.appendChild(notification);
    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease-in';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
    if (!document.querySelector('#notification-styles')) {
      const style = document.createElement('style');
      style.id = 'notification-styles';
      style.textContent = \`
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes slideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }
      \`;
      document.head.appendChild(style);
    }
  }
  
  function copyToClipboard(text, event) {
    if (event) event.stopPropagation();
    navigator.clipboard.writeText(text).then(() => showNotification('已复制到剪贴板'));
  }
  
  let currentWorkerForEnv = '';
  let currentWorkerForBind = '';
  let currentZoneId = null;
  let currentEditingRecord = null;
  let currentBindType = 'kv';
  
  // 页面导航
  function navTo(page) {
    document.querySelectorAll('.nav .item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.page-content').forEach(p => p.classList.remove('active'));
    const activeNav = Array.from(document.querySelectorAll('.nav .item')).find(i => i.dataset.page === page);
    const activePage = el(page + '-page');
    if (activeNav) activeNav.classList.add('active');
    if (activePage) activePage.classList.add('active');
    switch(page) {
      case 'workers': refreshWorkers(); break;
      case 'batch': renderBatchPage(); break;
      case 'kv': refreshKVNamespaces(); break;
      case 'd1': refreshD1Databases(); break;
      case 'dns': showZonesList(); break;
      case 'settings': loadSubdomainSettings(); break;
    }
  }
  
  // Workers 管理
  async function refreshWorkers() {
    el('workersList').innerHTML = '加载中...';
    const accounts = await api('list-accounts');
    if (!accounts || !accounts.result) { 
      el('workersList').innerHTML = '无法获取账户'; 
      return; 
    }
    const accountId = accounts.result[0].id || accounts.result[0].account_id;
    localStorage.setItem('cf_accountId', accountId);
    const res = await api('list-workers', { accountId });
    if (!res || !res.result) { 
      el('workersList').innerHTML = '获取 Workers 失败'; 
      return; 
    }
    
    el('workersList').innerHTML = '';
    res.result.forEach(w => {
      const name = w.id || w.name || w.script_name;
      const created = w.created_on || w.created_at || w.modified_on || '';
      const defaultDomain = w.defaultDomain;
      const domains = w.domains || [];
      const bindings = w.bindings || [];
      const subdomainEnabled = w.subdomainEnabled !== false;
      
      const envBindings = bindings.filter(b => b.type === 'plain_text' || b.type === 'secret_text');
      const kvBindings = bindings.filter(b => b.type === 'kv_namespace');
      const d1Bindings = bindings.filter(b => b.type === 'd1' || b.type === 'd1_database');
      
      const div = document.createElement('div'); 
      div.className = 'worker-row';
      div.innerHTML = \`
        <div class="worker-info">
          <div style="font-weight:700">\${name}</div>
          <div class="worker-meta">创建时间：\${created}</div>
          \${defaultDomain ? \`
            <div class="worker-domains">
              <div class="small" style="margin-bottom:2px;">默认域名:</div>
              <div style="display:flex;align-items:center;gap:12px">
                <a href="https://\${defaultDomain.hostname}" target="_blank" class="domain-tag workers-dev">\${defaultDomain.hostname}</a>
                <div class="domain-control">
                   <label class="switch">
                     <input type="checkbox" \${subdomainEnabled ? 'checked' : ''} onchange="toggleWorkerSubdomain('\${name}', this.checked)">
                     <span class="slider"></span>
                   </label>
                   <span class="small" style="margin-left:8px">\${subdomainEnabled ? '已开启' : '已关闭'}</span>
                </div>
              </div>
            </div>
          \` : '<div class="worker-meta" style="color:#ef4444">Workers 域名未设置</div>'}
          <div class="worker-domains" style="margin-top:8px">
            <div class="small" style="margin-bottom:2px;">自定义域名:</div>
            \${domains.length > 0 ? domains.map(domain => {
              const status = domain.status || 'active';
              const statusText = status === 'active' ? '已启用' : '待处理';
              const statusClass = status === 'active' ? 'active' : 'pending';
              return \`<div style="display:inline-block;position:relative"><a href="https://\${domain.hostname}" target="_blank" class="domain-tag">\${domain.hostname}<span class="domain-status \${statusClass}">\${statusText}</span></a><span class="del-domain-btn" onclick="deleteWorkerDomain('\${name}', '\${domain.id}')">✕</span></div>\`;
            }).join('') : '<span class="small" style="color:#94a3b8">暂无自定义域名</span>'}
          </div>
        </div>
        <div class="worker-right">
          <div class="worker-tags">
            \${envBindings.map(b => \`<span class="res-tag env">ENV: \${b.name}</span>\`).join('')}
            \${kvBindings.map(b => \`<span class="res-tag kv">KV: \${b.name}</span>\`).join('')}
            \${d1Bindings.map(b => \`<span class="res-tag d1">D1: \${b.name}</span>\`).join('')}
          </div>
          <div class="btns">
            <button class="btn" data-name="\${name}" data-act="env">环境</button>
            <button class="btn" data-name="\${name}" data-act="bind">绑定资源</button>
            <button class="btn" data-name="\${name}" data-act="addDomain">绑定域名</button>
            <button class="btn" data-name="\${name}" data-act="edit">编辑</button>
            <button class="btn danger" data-name="\${name}" data-act="delete">删除</button>
          </div>
        </div>
      \`;
      el('workersList').appendChild(div);
    });
    
    Array.from(document.querySelectorAll('.btns .btn')).forEach(b => {
      b.addEventListener('click', async function(e) {
        e.stopPropagation();
        const act = this.dataset.act; 
        const name = this.dataset.name;
        if (act === 'env') openEnvFor(name);
        if (act === 'bind') openBindFor(name);
        if (act === 'edit') editWorker(name);
        if (act === 'delete') deleteWorker(name);
        if (act === 'addDomain') openAddDomainModal(name);
      });
    });
    updateWorkerMetrics();
  }
  
  async function toggleWorkerSubdomain(scriptName, enabled) {
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('toggle-worker-subdomain', { accountId, scriptName, enabled });
    if (res && res.success) {
      showNotification(enabled ? '子域名已启用' : '子域名已禁用');
      setTimeout(refreshWorkers, 1000);
    } else {
      showNotification(res.error || '操作失败', 'error');
      refreshWorkers();
    }
  }
  
  async function updateWorkerMetrics() {
    try {
      const usageRes = await api('get-usage-today', { accountId: localStorage.getItem('cf_accountId') });
      if (usageRes && usageRes.success && usageRes.data) {
        const data = usageRes.data;
        const total = data.total || 0;
        const workers = data.workers || 0;
        const pages = data.pages || 0;
        const percentage = data.percentage || 0;
        el('metricCount').textContent = \`\${total.toLocaleString()} / 100,000\`;
        el('metricBar').style.width = \`\${percentage}%\`;
        el('workersRequests').textContent = workers.toLocaleString();
        el('pagesRequests').textContent = pages.toLocaleString();
      }
    } catch (e) { console.error(e); }
  }
  
  async function editWorker(name) {
    const accounts = await api('list-accounts');
    const accountId = accounts.result?.[0]?.id;
    const res = await api('get-worker-script', { accountId, scriptName: name });
    if (res && res.rawScript !== undefined) {
      el('createName').value = name;
      el('createScript').value = res.rawScript;
      el('createModal').style.display = 'flex';
    } else {
      showNotification('获取 Worker 脚本失败', 'error');
    }
  }
  
  async function confirmCreate() {
    const name = el('createName').value.trim();
    const script = el('createScript').value;
    if (!name) return showNotification('请输入 Worker 名称', 'error');
    const accountId = (await api('list-accounts')).result?.[0]?.id;
    const res = await api('deploy-worker', { accountId, scriptName: name, scriptSource: script, metadataBindings: [] });
    if (res && res.success) {
      showNotification('Worker 部署成功');
      el('createModal').style.display = 'none';
      setTimeout(refreshWorkers, 800);
    } else {
      showNotification(res.error || '部署失败', 'error');
    }
  }
  
  function closeCreate() { el('createModal').style.display = 'none'; }
  
  async function deleteWorker(name) {
    if (!confirm('确定要删除 Worker: ' + name + ' 吗？')) return;
    const accountId = (await api('list-accounts')).result?.[0]?.id;
    const res = await api('delete-worker', { accountId, scriptName: name });
    if (res && res.success) {
      showNotification('Worker 删除成功');
      setTimeout(refreshWorkers, 600);
    } else {
      showNotification(res.error || '删除失败', 'error');
    }
  }
  
  // 环境变量管理
  async function openEnvFor(name) {
    currentWorkerForEnv = name;
    await loadEnvVars(name);
    el('envModal').style.display = 'flex';
  }
  
  async function loadEnvVars(scriptName) {
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('get-worker-variables', { accountId, scriptName });
    el('envRows').innerHTML = '';
    if (res && res.result && res.result.vars) {
      res.result.vars.forEach(v => addEnvRow(v.name, v.type || 'plain_text', v.value || ''));
    } else {
      addEnvRow();
    }
  }
  
  function addEnvRow(name = '', type = 'plain_text', value = '') {
    const rows = el('envRows');
    const div = document.createElement('div');
    div.style.display = 'flex';
    div.style.gap = '8px';
    div.style.marginTop = '8px';
    div.innerHTML = \`
      <input class="input env-name" placeholder="变量名" value="\${name}" style="flex:2">
      <select class="input env-type" style="width:140px"><option value="plain_text">文本</option><option value="secret_text">密钥</option></select>
      <textarea class="input env-value" placeholder="变量值" style="flex:3;min-height:60px">\${value}</textarea>
      <button class="btn danger">删除</button>
    \`;
    rows.appendChild(div);
    div.querySelector('button').addEventListener('click', () => div.remove());
    div.querySelector('select').value = type;
  }
  
  async function saveEnv() {
    const script = currentWorkerForEnv;
    if (!script) return showNotification('请选择 Worker', 'error');
    const rows = Array.from(el('envRows').children);
    const vars = [];
    for (const row of rows) {
      const name = row.querySelector('.env-name').value.trim();
      const type = row.querySelector('.env-type').value;
      const value = row.querySelector('.env-value').value;
      if (name) vars.push({ name, value, type });
    }
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('put-worker-variables', { accountId, scriptName: script, variables: vars });
    if (res && res.success) {
      showNotification('环境变量保存成功');
      el('envModal').style.display = 'none';
      refreshWorkers();
    } else {
      showNotification(res.error || '保存失败', 'error');
    }
  }
  
  function closeEnvModal() { el('envModal').style.display = 'none'; }
  
  // 绑定资源管理
  async function openBindFor(name) {
    currentWorkerForBind = name;
    el('createName').value = name;
    await refreshBindList();
    el('bindModal').style.display = 'flex';
  }
  
  async function refreshBindList() {
    const type = el('bindType').value;
    currentBindType = type;
    const accountId = localStorage.getItem('cf_accountId');
    if (!accountId) {
      el('bindSelect').innerHTML = '<option>无 account</option>';
      return;
    }
    el('bindSelect').innerHTML = '<option value="">加载中...</option>';
    try {
      if (type === 'kv') {
        const kv = await api('list-kv-namespaces', { accountId });
        const arr = kv.result || [];
        el('bindSelect').innerHTML = '';
        if (arr.length) {
          arr.forEach(ns => {
            const opt = document.createElement('option');
            opt.value = ns.id;
            opt.textContent = (ns.title || ns.name || ns.id) + ' (' + ns.id + ')';
            el('bindSelect').appendChild(opt);
          });
        } else {
          el('bindSelect').innerHTML = '<option value="">未找到 KV 命名空间</option>';
        }
      } else {
        const d1 = await api('list-d1', { accountId });
        const arr = d1.result || [];
        el('bindSelect').innerHTML = '';
        if (arr.length) {
          arr.forEach(db => {
            const id = db.uuid || db.id;
            const opt = document.createElement('option');
            opt.value = id;
            opt.textContent = (db.name || db.uuid || db.id) + ' (' + id + ')';
            el('bindSelect').appendChild(opt);
          });
        } else {
          el('bindSelect').innerHTML = '<option value="">未找到 D1 数据库</option>';
        }
      }
    } catch (error) {
      console.error('刷新绑定列表失败:', error);
      el('bindSelect').innerHTML = '<option value="">加载失败</option>';
    }
  }
  
  async function confirmBind() {
    const type = currentBindType;
    const ref = el('bindSelect').value;
    const bindName = el('bindName').value.trim() || (type === 'kv' ? 'MY_KV' : 'MY_DB');
    const script = currentWorkerForBind;
    if (!script) return showNotification('请选择 Worker', 'error');
    if (!ref) return showNotification('请选择要绑定的资源', 'error');
    const accountId = localStorage.getItem('cf_accountId');
    const currentScriptRes = await api('get-worker-script', { accountId, scriptName: script });
    let currentScript = currentScriptRes?.rawScript || DEFAULT_WORKER_SCRIPT;
    const newBinding = (type === 'kv') 
      ? { type: 'kv_namespace', name: bindName, namespace_id: ref }
      : { type: 'd1', name: bindName, id: ref };
    const res = await api('deploy-worker', { accountId, scriptName: script, scriptSource: currentScript, metadataBindings: [newBinding] });
    if (res && res.success) {
      showNotification('资源绑定成功');
      el('bindModal').style.display = 'none';
      setTimeout(refreshWorkers, 800);
    } else {
      showNotification(res.error || '绑定失败', 'error');
    }
  }
  
  function closeBindModal() { el('bindModal').style.display = 'none'; }
  
  // 域名管理
  let currentWorkerForDomain = '';
  function openAddDomainModal(scriptName) {
    currentWorkerForDomain = scriptName;
    el('addDomainModal').style.display = 'flex';
  }
  function closeAddDomainModal() { el('addDomainModal').style.display = 'none'; }
  async function confirmAddDomain() {
    const hostname = el('newDomainInput').value.trim();
    const scriptName = currentWorkerForDomain;
    if (!hostname) return showNotification('请输入域名', 'error');
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('add-worker-domain', { accountId, scriptName, hostname });
    if (res && res.success) {
      showNotification('域名绑定成功');
      closeAddDomainModal();
      refreshWorkers();
    } else {
      showNotification(res.error || '绑定失败', 'error');
    }
  }
  async function deleteWorkerDomain(scriptName, domainId) {
    if (!confirm('确定要解绑此域名吗？')) return;
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('delete-worker-domain', { accountId, scriptName, domainId });
    if (res && res.success) {
      showNotification('域名解绑成功');
      refreshWorkers();
    } else {
      showNotification(res.error || '解绑失败', 'error');
    }
  }
  
  // KV 管理
  async function refreshKVNamespaces() {
    const accountId = localStorage.getItem('cf_accountId');
    if (!accountId) return;
    const res = await api('list-kv-namespaces', { accountId });
    const namespaces = res.result || [];
    el('kvNamespacesList').innerHTML = '';
    if (namespaces.length === 0) {
      el('kvNamespacesList').innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无 KV 命名空间</div>';
      return;
    }
    namespaces.forEach(ns => {
      const div = document.createElement('div');
      div.className = 'kv-item';
      div.innerHTML = \`<div><div style="font-weight:600">\${ns.title || ns.id}</div><div class="small">ID: \${ns.id}</div></div><div class="btns"><button class="btn" data-id="\${ns.id}" data-act="view">查看键值</button><button class="btn danger" data-id="\${ns.id}" data-act="delete">删除</button></div>\`;
      el('kvNamespacesList').appendChild(div);
    });
    Array.from(el('kvNamespacesList').querySelectorAll('.btn')).forEach(btn => {
      btn.addEventListener('click', function() {
        const namespaceId = this.dataset.id;
        const act = this.dataset.act;
        if (act === 'view') viewKVNamespace(namespaceId);
        if (act === 'delete') deleteKVNamespace(namespaceId);
      });
    });
  }
  
  async function viewKVNamespace(namespaceId) {
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('list-kv-keys', { accountId, namespaceId });
    if (res && res.result) {
      const keys = res.result;
      let content = '<h4>KV 键值列表</h4>';
      if (keys.length === 0) content += '<p>暂无键值对</p>';
      else {
        content += '<ul>';
        keys.forEach(key => { content += \`<li>\${key.name}</li>\`; });
        content += '</ul>';
      }
      el('debugOut').innerHTML = content;
      el('outModal').style.display = 'flex';
    }
  }
  
  async function deleteKVNamespace(namespaceId) {
    if (!confirm('确定要删除此 KV 命名空间吗？')) return;
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('delete-kv-namespace', { accountId, namespaceId });
    if (res && res.success) {
      showNotification('KV 命名空间删除成功');
      refreshKVNamespaces();
    } else {
      showNotification(res.error || '删除失败', 'error');
    }
  }
  
  function openCreateKVNamespace() { el('createKVModal').style.display = 'flex'; }
  function closeCreateKVModal() { el('createKVModal').style.display = 'none'; }
  async function confirmCreateKVNamespace() {
    const name = el('kvNamespaceName').value.trim();
    if (!name) return showNotification('请输入命名空间名称', 'error');
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('create-kv-namespace', { accountId, title: name });
    if (res && res.result) {
      showNotification('KV 命名空间创建成功');
      closeCreateKVModal();
      refreshKVNamespaces();
    } else {
      showNotification(res.error || '创建失败', 'error');
    }
  }
  
  // D1 管理
  async function refreshD1Databases() {
    const accountId = localStorage.getItem('cf_accountId');
    if (!accountId) return;
    const res = await api('list-d1', { accountId });
    const databases = res.result || [];
    el('d1DatabasesList').innerHTML = '';
    el('d1DatabaseSelect').innerHTML = '<option value="">- 选择数据库 -</option>';
    if (databases.length === 0) {
      el('d1DatabasesList').innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无 D1 数据库</div>';
      return;
    }
    databases.forEach(db => {
      const div = document.createElement('div');
      div.className = 'kv-item';
      div.innerHTML = \`<div><div style="font-weight:600">\${db.name || db.id}</div><div class="small">ID: \${db.uuid || db.id}</div></div><div class="btns"><button class="btn danger" data-id="\${db.uuid || db.id}" data-act="delete">删除</button></div>\`;
      el('d1DatabasesList').appendChild(div);
      const option = document.createElement('option');
      option.value = db.uuid || db.id;
      option.textContent = \`\${db.name} (\${db.uuid || db.id})\`;
      el('d1DatabaseSelect').appendChild(option);
    });
    Array.from(el('d1DatabasesList').querySelectorAll('.btn')).forEach(btn => {
      btn.addEventListener('click', function() {
        const databaseId = this.dataset.id;
        deleteD1Database(databaseId);
      });
    });
  }
  
  async function deleteD1Database(databaseId) {
    if (!confirm('确定要删除此 D1 数据库吗？')) return;
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('delete-d1-database', { accountId, databaseId });
    if (res && res.success) {
      showNotification('D1 数据库删除成功');
      refreshD1Databases();
    } else {
      showNotification(res.error || '删除失败', 'error');
    }
  }
  
  function openCreateD1Database() { el('createD1Modal').style.display = 'flex'; }
  function closeCreateD1Modal() { el('createD1Modal').style.display = 'none'; }
  async function confirmCreateD1Database() {
    const name = el('d1DatabaseName').value.trim();
    if (!name) return showNotification('请输入数据库名称', 'error');
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('create-d1-database', { accountId, name });
    if (res && res.result) {
      showNotification('D1 数据库创建成功');
      closeCreateD1Modal();
      refreshD1Databases();
    } else {
      showNotification(res.error || '创建失败', 'error');
    }
  }
  
  async function executeD1Query() {
    const databaseId = el('d1DatabaseSelect').value;
    const query = el('d1Query').value.trim();
    if (!databaseId || !query) return showNotification('请选择数据库并输入查询语句', 'error');
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('execute-d1-query', { accountId, databaseId, query });
    if (res && res.result) {
      el('d1QueryResults').innerHTML = '<pre>' + JSON.stringify(res.result, null, 2) + '</pre>';
    } else {
      showNotification(res.error || '查询失败', 'error');
    }
  }
  
  // DNS 管理
  async function refreshZones() {
    const res = await api('list-zones');
    const zones = res.result || [];
    el('zonesList').innerHTML = '';
    if (zones.length === 0) {
      el('zonesList').innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无域名</div>';
      return;
    }
    const table = document.createElement('table');
    table.className = 'domain-list-table';
    table.innerHTML = \`<thead><tr><th>域名</th><th>状态</th><th>区域 ID</th><th>操作</th></tr></thead><tbody></tbody>\`;
    const tbody = table.querySelector('tbody');
    zones.forEach(zone => {
      const row = document.createElement('tr');
      let statusHtml = zone.status === 'active' 
        ? '<span style="background:#f0fdf4;color:#166534;padding:2px 8px;border-radius:999px;font-size:11px">已激活</span>'
        : '<span style="background:#fffbeb;color:#d97706;padding:2px 8px;border-radius:999px;font-size:11px">待处理</span>';
      row.innerHTML = \`<td><div style="font-weight:600">\${zone.name}</div></td><td>\${statusHtml}</td><td style="font-family:monospace;font-size:11px">\${zone.id}</td><td><button class="trash-btn" style="color:#2563eb" onclick="viewZoneDNS('\${zone.id}', '\${zone.name}')">管理 DNS</button><button class="trash-btn" onclick="deleteZone('\${zone.id}')">删除</button></td>\`;
      tbody.appendChild(row);
    });
    el('zonesList').appendChild(table);
  }
  
  function showZonesList() {
    el('zonesList').style.display = 'block';
    el('dnsRecordsSection').style.display = 'none';
    currentZoneId = null;
    refreshZones();
  }
  
  function viewZoneDNS(zoneId, zoneName) {
    currentZoneId = zoneId;
    el('zonesList').style.display = 'none';
    el('dnsRecordsSection').style.display = 'block';
    el('selectedZoneName').textContent = zoneName + ' - DNS 记录管理';
    refreshDNSRecords(zoneId);
  }
  
  function backToZones() { showZonesList(); }
  
  async function refreshDNSRecords(zoneId) {
    const res = await api('list-dns-records', { zoneId });
    const records = res.result || [];
    el('dnsRecordsList').innerHTML = '';
    if (records.length === 0) {
      el('dnsRecordsList').innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无 DNS 记录</div>';
      return;
    }
    const table = document.createElement('table');
    table.className = 'dns-table';
    table.innerHTML = \`<thead><tr><th>类型</th><th>名称</th><th>内容</th><th>TTL</th><th>代理</th><th>操作</th></tr></thead><tbody></tbody>\`;
    const tbody = table.querySelector('tbody');
    records.forEach(record => {
      const row = document.createElement('tr');
      row.innerHTML = \`<td>\${record.type}</td><td>\${record.name}</td><td>\${record.content}</td><td>\${record.ttl}</td><td>\${record.proxied ? '开启' : '关闭'}</td><td><button class="btn small" data-id="\${record.id}" data-act="edit">编辑</button><button class="btn small danger" data-id="\${record.id}" data-act="delete">删除</button></td>\`;
      tbody.appendChild(row);
    });
    el('dnsRecordsList').appendChild(table);
    Array.from(el('dnsRecordsList').querySelectorAll('.btn')).forEach(btn => {
      btn.addEventListener('click', function() {
        const recordId = this.dataset.id;
        const act = this.dataset.act;
        if (act === 'edit') editDNSRecord(zoneId, recordId);
        if (act === 'delete') deleteDNSRecord(zoneId, recordId);
      });
    });
  }
  
  async function editDNSRecord(zoneId, recordId) {
    const res = await api('list-dns-records', { zoneId });
    const record = res.result.find(r => r.id === recordId);
    if (record) {
      currentEditingRecord = record;
      el('editDnsRecordType').value = record.type;
      el('editDnsRecordName').value = record.name;
      el('editDnsRecordContent').value = record.content;
      el('editDnsRecordTTL').value = record.ttl;
      el('editDnsRecordProxied').checked = record.proxied;
      el('editDNSRecordModal').style.display = 'flex';
    }
  }
  
  async function confirmEditDNSRecord() {
    const zoneId = currentZoneId;
    const recordId = currentEditingRecord.id;
    const type = el('editDnsRecordType').value;
    const name = el('editDnsRecordName').value.trim();
    const content = el('editDnsRecordContent').value.trim();
    const ttl = parseInt(el('editDnsRecordTTL').value);
    const proxied = el('editDnsRecordProxied').checked;
    const res = await api('update-dns-record', { zoneId, recordId, type, name, content, ttl, proxied });
    if (res && res.result) {
      showNotification('DNS 记录更新成功');
      el('editDNSRecordModal').style.display = 'none';
      refreshDNSRecords(zoneId);
    } else {
      showNotification(res.error || '更新失败', 'error');
    }
  }
  
  function closeEditDNSRecordModal() { el('editDNSRecordModal').style.display = 'none'; }
  
  function openAddDNSRecord() {
    if (!currentZoneId) return showNotification('请先选择域名', 'error');
    el('addDNSRecordModal').style.display = 'flex';
  }
  
  function closeAddDNSRecordModal() { el('addDNSRecordModal').style.display = 'none'; }
  
  async function confirmAddDNSRecord() {
    const zoneId = currentZoneId;
    const type = el('dnsRecordType').value;
    const name = el('dnsRecordName').value.trim();
    const content = el('dnsRecordContent').value.trim();
    const ttl = parseInt(el('dnsRecordTTL').value);
    const proxied = el('dnsRecordProxied').checked;
    const res = await api('create-dns-record', { zoneId, type, name, content, ttl, proxied });
    if (res && res.result) {
      showNotification('DNS 记录添加成功');
      closeAddDNSRecordModal();
      refreshDNSRecords(zoneId);
    } else {
      showNotification(res.error || '添加失败', 'error');
    }
  }
  
  async function deleteDNSRecord(zoneId, recordId) {
    if (!confirm('确定要删除此 DNS 记录吗？')) return;
    const res = await api('delete-dns-record', { zoneId, recordId });
    if (res && res.success) {
      showNotification('DNS 记录删除成功');
      refreshDNSRecords(zoneId);
    } else {
      showNotification(res.error || '删除失败', 'error');
    }
  }
  
  async function deleteZone(zoneId) {
    if (!confirm('确定要删除此域名吗？')) return;
    const res = await api('delete-zone', { zoneId });
    if (res && res.success) {
      showNotification('域名删除成功');
      refreshZones();
    } else {
      showNotification(res.error || '删除失败', 'error');
    }
  }
  
  function openAddZone() { el('addZoneModal').style.display = 'flex'; }
  function closeAddZoneModal() { el('addZoneModal').style.display = 'none'; }
  async function confirmAddZone() {
    const name = el('zoneName').value.trim();
    if (!name) return showNotification('请输入域名', 'error');
    const res = await api('create-zone', { name });
    if (res && res.result) {
      showNotification('域名添加成功');
      closeAddZoneModal();
      refreshZones();
    } else {
      showNotification(res.error || '添加失败', 'error');
    }
  }
  
  // 设置
  async function loadSubdomainSettings() {
    const accountId = localStorage.getItem('cf_accountId');
    if (!accountId) return;
    const res = await api('get-workers-subdomain', { accountId });
    if (res && res.result) {
      el('subdomainInput').value = res.result.subdomain || '';
    }
  }
  
  async function saveSubdomain() {
    const subdomain = el('subdomainInput').value.trim();
    if (!subdomain) return showNotification('请输入子域名', 'error');
    const accountId = localStorage.getItem('cf_accountId');
    const res = await api('put-workers-subdomain', { accountId, subdomain });
    if (res && res.success) {
      showNotification('Workers 域名设置成功');
      setTimeout(refreshWorkers, 1000);
    } else {
      showNotification(res.error || '设置失败', 'error');
    }
  }
  
  // 批量创建
  function renderBatchPage() {
    el('batchAccountList').innerHTML = '<div style="padding:10px;color:#999">批量创建需要配置多个账号，当前使用单账号模式</div><div class="account-check-item"><label><input type="checkbox" class="batch-acc-chk" checked> 当前账号</label></div>';
    el('batchEnvList').innerHTML = '';
  }
  
  function toggleBatchSourceInput() {
    const type = el('batchScriptSourceType').value;
    if (type === 'url') {
      el('batchSourceBuiltinDiv').style.display = 'none';
      el('batchSourceUrlDiv').style.display = 'block';
    } else {
      el('batchSourceBuiltinDiv').style.display = 'block';
      el('batchSourceUrlDiv').style.display = 'none';
    }
  }
  
  function addBatchEnvRow() {
    const div = document.createElement('div');
    div.className = 'env-row-batch';
    div.innerHTML = \`<input class="input b-env-key" placeholder="Key" style="flex:1"><input class="input b-env-val" placeholder="Value" style="flex:1"><button class="trash-btn" onclick="this.parentElement.remove()">✕</button>\`;
    el('batchEnvList').appendChild(div);
  }
  
  function appendBatchLog(msg, color = '#fff') {
    const log = el('batchLog');
    const span = document.createElement('div');
    span.style.color = color;
    span.textContent = \`[\${new Date().toLocaleTimeString()}] \${msg}\`;
    log.appendChild(span);
    log.scrollTop = log.scrollHeight;
  }
  
  async function startBatchCreate() {
    const name = el('batchWorkerName').value.trim();
    if (!name) return alert('请输入 Worker 名称');
    
    const sourceType = el('batchScriptSourceType').value;
    let scriptUrl = '';
    if (sourceType === 'builtin') {
      scriptUrl = 'https://raw.githubusercontent.com/cloudflare/workers-sdk/main/templates/worker/typescript/worker.js';
    } else {
      scriptUrl = el('batchScriptUrl').value.trim();
      if (!scriptUrl) return alert('请输入脚本链接');
    }
    
    const bindings = [];
    el('batchEnvList').querySelectorAll('.env-row-batch').forEach(row => {
      const k = row.querySelector('.b-env-key').value.trim();
      const v = row.querySelector('.b-env-val').value;
      if (k) bindings.push({ type: 'plain_text', name: k, text: v });
    });
    
    appendBatchLog('正在获取脚本...', '#60a5fa');
    let scriptContent = '';
    try {
      const res = await api('fetch-external-script', { url: scriptUrl });
      if (res.success) {
        scriptContent = res.content;
        appendBatchLog('脚本获取成功', '#4ade80');
      } else {
        appendBatchLog('脚本获取失败: ' + res.error, '#ef4444');
        return;
      }
    } catch (e) {
      appendBatchLog('脚本获取异常: ' + e.message, '#ef4444');
      return;
    }
    
    el('batchLog').innerHTML = '';
    appendBatchLog(\`开始部署 Worker: \${name}\`, '#fcd34d');
    
    try {
      const accounts = await api('list-accounts');
      const accountId = accounts.result?.[0]?.id;
      if (!accountId) throw new Error('无法获取账户ID');
      
      appendBatchLog('正在部署...', '#9ca3af');
      const deployRes = await api('deploy-worker', {
        accountId,
        scriptName: name,
        scriptSource: scriptContent,
        metadataBindings: bindings
      });
      
      if (deployRes.success) {
        appendBatchLog('✅ 部署成功', '#4ade80');
        
        const enableSubdomain = el('batchEnableSubdomain').checked;
        if (enableSubdomain) {
          await api('toggle-worker-subdomain', { accountId, scriptName: name, enabled: true });
          appendBatchLog('已开启子域名访问', '#60a5fa');
        }
      } else {
        appendBatchLog('❌ 部署失败: ' + deployRes.error, '#ef4444');
      }
    } catch (e) {
      appendBatchLog('❌ 异常: ' + e.message, '#ef4444');
    }
    appendBatchLog('操作完成', '#fcd34d');
  }
  
  function closeOut() { el('outModal').style.display = 'none'; }
  
  // 初始化
  (async function init() {
    const sessionToken = getSessionToken();
    if (!sessionToken) {
      window.location.href = '/login';
      return;
    }
    setTimeout(() => refreshWorkers(), 300);
  })();
  
  // 导出全局函数
  window.navTo = navTo;
  window.logout = logout;
  window.openCreateWorker = function() {
    el('createName').value = '';
    el('createScript').value = DEFAULT_WORKER_SCRIPT;
    el('createModal').style.display = 'flex';
  };
  window.closeCreate = closeCreate;
  window.confirmCreate = confirmCreate;
  window.openEnvFor = openEnvFor;
  window.addEnvRow = addEnvRow;
  window.saveEnv = saveEnv;
  window.closeEnvModal = closeEnvModal;
  window.openBindFor = openBindFor;
  window.refreshBindList = refreshBindList;
  window.confirmBind = confirmBind;
  window.closeBindModal = closeBindModal;
  window.editWorker = editWorker;
  window.deleteWorker = deleteWorker;
  window.toggleWorkerSubdomain = toggleWorkerSubdomain;
  window.openAddDomainModal = openAddDomainModal;
  window.closeAddDomainModal = closeAddDomainModal;
  window.confirmAddDomain = confirmAddDomain;
  window.deleteWorkerDomain = deleteWorkerDomain;
  window.refreshKVNamespaces = refreshKVNamespaces;
  window.openCreateKVNamespace = openCreateKVNamespace;
  window.closeCreateKVModal = closeCreateKVModal;
  window.confirmCreateKVNamespace = confirmCreateKVNamespace;
  window.refreshD1Databases = refreshD1Databases;
  window.openCreateD1Database = openCreateD1Database;
  window.closeCreateD1Modal = closeCreateD1Modal;
  window.confirmCreateD1Database = confirmCreateD1Database;
  window.executeD1Query = executeD1Query;
  window.refreshZones = refreshZones;
  window.openAddZone = openAddZone;
  window.closeAddZoneModal = closeAddZoneModal;
  window.confirmAddZone = confirmAddZone;
  window.viewZoneDNS = viewZoneDNS;
  window.backToZones = backToZones;
  window.openAddDNSRecord = openAddDNSRecord;
  window.closeAddDNSRecordModal = closeAddDNSRecordModal;
  window.confirmAddDNSRecord = confirmAddDNSRecord;
  window.editDNSRecord = editDNSRecord;
  window.confirmEditDNSRecord = confirmEditDNSRecord;
  window.closeEditDNSRecordModal = closeEditDNSRecordModal;
  window.deleteZone = deleteZone;
  window.saveSubdomain = saveSubdomain;
  window.loadSubdomainSettings = loadSubdomainSettings;
  window.copyToClipboard = copyToClipboard;
  window.closeOut = closeOut;
  window.toggleBatchSourceInput = toggleBatchSourceInput;
  window.addBatchEnvRow = addBatchEnvRow;
  window.startBatchCreate = startBatchCreate;
  window.renderBatchPage = renderBatchPage;
})();`;
}

// 注意：由于代码长度限制，renderStaticJS 中的 BATCH_CONFIG 相关代码已简化
// 如需完整功能，请根据实际需求配置环境变量 BATCH_URLS 和 BATCH_NAMES
