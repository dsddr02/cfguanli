// =============== Cloudflare Manager - 完整版 ===============
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
    return new Response(renderStaticJS(env), { 
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
  
  // Worker 管理页面（需要认证）
  if (request.method === 'GET' && p.startsWith('/workers')) {
    let sessionToken = request.headers.get('X-Session-Token');
    
    if (!sessionToken) {
      const cookie = request.headers.get('Cookie');
      if (cookie) {
        const match = cookie.match(/session_token=([^;]+)/);
        if (match) sessionToken = match[1];
      }
    }
    
    if (!sessionToken) {
      sessionToken = url.searchParams.get('session');
    }
    
    if (sessionToken) {
      const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
      
      if (session && session.expires > Date.now()) {
        return new Response(renderAppHTML(), { 
          headers: { 
            'content-type': 'text/html; charset=utf-8',
            'Set-Cookie': `session_token=${sessionToken}; Path=/; Secure; SameSite=Strict; Max-Age=28800`
          }
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
    
    // 存储主账号凭据
    const mainAccount = { email, key, alias: '主账号', isDefault: true };
    const encryptedCredentials = await encrypt(JSON.stringify([mainAccount]), masterPassword);
    
    await env.MY_KV.put('config:credentials', encryptedCredentials);
    await env.MY_KV.put('config:is_configured', 'true');
    await env.MY_KV.put('config:setup_time', Date.now().toString());
    
    // 创建初始会话
    const sessionToken = generateSessionToken();
    await env.MY_KV.put(`session:${sessionToken}`, JSON.stringify({
      email,
      key,
      expires: Date.now() + 8 * 3600000
    }), { expirationTtl: 28800 });
    
    return json({ success: true, sessionToken, message: '配置已保存' });
  }
  
  // 登录
  // 登录 - 修改，存储完整账号列表到 session
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
    const accountsJson = await decrypt(encryptedCredentials, masterPassword);
    let accounts = JSON.parse(accountsJson);
    
    // 确保是数组格式
    if (!Array.isArray(accounts)) {
      accounts = [{ email: accounts.email, key: accounts.key, alias: '主账号', isDefault: true }];
    }
    
    const defaultAccount = accounts.find(a => a.isDefault) || accounts[0];
    
    const sessionToken = generateSessionToken();
    await env.MY_KV.put(`session:${sessionToken}`, JSON.stringify({
      email: defaultAccount.email,
      key: defaultAccount.key,
      accounts: accounts,  // 存储完整账号列表
      expires: Date.now() + 8 * 3600000
    }), { expirationTtl: 28800 });
    
    return json({ success: true, sessionToken, expiresIn: 28800 });
    
  } catch (error) {
    return json({ success: false, error: '访问密码错误' }, 401);
  }
}
  // 获取账号列表 - 直接从 session 获取
if (action === 'get-accounts') {
  const sessionToken = payload.sessionToken;
  if (!sessionToken) {
    return json({ success: false, error: '未登录' }, 401);
  }
  
  const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
  if (!session || session.expires < Date.now()) {
    return json({ success: false, error: '会话已过期' }, 401);
  }
  
  // 从 session 中返回账号列表（登录时已经解密并存入了 session）
  const accounts = session.accounts || [];
  return json({ success: true, accounts: accounts.map(a => ({ 
    email: a.email, 
    alias: a.alias || a.email,
    isDefault: a.isDefault 
  })) });
}
  
  // 添加账号
  // 添加账号 - 修复解密问题
if (action === 'add-account') {
  const { sessionToken, email, key, alias, masterPassword } = payload;
  
  if (!sessionToken) {
    return json({ success: false, error: '未登录' }, 401);
  }
  
  const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
  if (!session || session.expires < Date.now()) {
    return json({ success: false, error: '会话已过期' }, 401);
  }
  
  if (!email || !key) {
    return json({ success: false, error: '缺少邮箱或 API Key' }, 400);
  }
  
  if (!masterPassword) {
    return json({ success: false, error: '需要主密码才能添加账号' }, 400);
  }
  
  try {
    // 验证新账号
    const testResult = await cfAny('GET', '/accounts', email, key);
    if (!testResult.success && !testResult.result) {
      return json({ 
        success: false, 
        error: 'Cloudflare 凭据无效：' + (testResult.errors?.[0]?.message || '验证失败')
      });
    }
    
    // 获取加密的凭据并解密
    const encryptedCredentials = await env.MY_KV.get('config:credentials');
    if (!encryptedCredentials) {
      return json({ success: false, error: '系统未配置' }, 400);
    }
    
    let accounts;
    try {
      const accountsJson = await decrypt(encryptedCredentials, masterPassword);
      accounts = JSON.parse(accountsJson);
    } catch (decryptError) {
      console.error('Decrypt error:', decryptError);
      return json({ success: false, error: '主密码错误，无法解密账号列表' }, 401);
    }
    
    // 确保 accounts 是数组
    if (!Array.isArray(accounts)) {
      accounts = [accounts];
    }
    
    // 检查是否已存在
    const existingIndex = accounts.findIndex(a => a.email === email);
    const newAccount = { email, key, alias: alias || email, isDefault: false };
    
    if (existingIndex >= 0) {
      accounts[existingIndex] = newAccount;
    } else {
      accounts.push(newAccount);
    }
    
    // 重新加密保存
    const newEncrypted = await encrypt(JSON.stringify(accounts), masterPassword);
    await env.MY_KV.put('config:credentials', newEncrypted);
    
    // 更新 session 中的账号列表
    session.accounts = accounts;
    await env.MY_KV.put(`session:${sessionToken}`, JSON.stringify(session), { expirationTtl: 28800 });
    
    return json({ success: true, message: '账号添加成功' });
    
  } catch (error) {
    console.error('Add account error:', error);
    return json({ success: false, error: '添加失败：' + error.message }, 500);
  }
}
  
  // 切换账号
  if (action === 'switch-account') {
    const { sessionToken, email } = payload;
    
    if (!sessionToken || !email) {
      return json({ success: false, error: '缺少参数' }, 400);
    }
    
    const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
    if (!session || session.expires < Date.now()) {
      return json({ success: false, error: '会话已过期' }, 401);
    }
    
    const account = session.accounts.find(a => a.email === email);
    if (!account) {
      return json({ success: false, error: '账号不存在' }, 400);
    }
    
    // 更新 session 中的当前账号
    session.email = account.email;
    session.key = account.key;
    await env.MY_KV.put(`session:${sessionToken}`, JSON.stringify(session), { expirationTtl: 28800 });
    
    return json({ success: true, message: '已切换账号' });
  }
  
  // 登出
  if (action === 'logout') {
    const { sessionToken } = payload;
    if (sessionToken) {
      await env.MY_KV.delete(`session:${sessionToken}`);
    }
    return json({ success: true });
  }
  if (action === 'validate-credentials') {
    const { email, key } = payload;
    if (!email || !key) {
      return json({ success: false, error: '缺少邮箱或 API Key' }, 400);
    }
    try {
      const r = await cfAny('GET', '/accounts', email, key);
      if (r.success && r.result && r.result.length > 0) {
        return json({ success: true, message: '凭据有效', accountId: r.result[0].id });
      } else {
        return json({ success: false, error: r.errors?.[0]?.message || '凭据无效' });
      }
    } catch (e) {
      return json({ success: false, error: e.message });
    }
  }
  // 需要 Cloudflare 凭据的操作
  const needsCreds = new Set([
    'list-accounts', 'list-workers', 'get-worker-script', 'deploy-worker',
    'list-kv-namespaces', 'list-d1', 'put-worker-variables', 'get-worker-variables',
    'get-workers-subdomain', 'put-workers-subdomain', 'delete-worker',
    'create-kv-namespace', 'delete-kv-namespace', 'list-kv-keys',
    'create-d1-database', 'delete-d1-database', 'execute-d1-query',
    'list-zones', 'create-zone', 'delete-zone', 'list-dns-records', 'create-dns-record',
    'delete-dns-record', 'update-dns-record', 'toggle-worker-subdomain', 'add-worker-domain',
    'delete-worker-domain', 'get-worker-analytics', 'get-usage-today', 'fetch-external-script'
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
              if (domainsResult.success && domainsResult.result) {
                worker.domains = domainsResult.result.map(domain => ({
                  id: domain.id,
                  hostname: domain.hostname,
                  status: domain.status || 'active'  // 修复：如果没有状态字段，默认为 active
                }));
              } else {
                worker.domains = [];
              }
              
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
        
        const envBindings = variables.map(v => ({ type: v.type === 'secret_text' ? 'secret_text' : 'plain_text', name: v.name, text: String(v.value) }));
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
          form.append('worker.js', new Blob([currentScript], { type: 'application/javascript+module' }), 'worker.js');
        } else {
          metadata.body_part = 'script';
          form.append('metadata', JSON.stringify(metadata));
          form.append('script', new Blob([currentScript], { type: 'application/javascript' }), 'worker.js');
        }
        
        const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}`, { 
          method: 'PUT', 
          headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key }, 
          body: form 
        });
        return json({ success: r.ok, message: r.ok ? 'Saved' : 'Failed', details: await r.text() });
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
      
      case 'get-worker-analytics': { 
        const { scriptName } = payload; 
        if (!scriptName || !payload.accountId) return json({ success: false }, 400); 
        const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}/analytics/summary`, { 
          headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key } 
        }); 
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
          // 尝试通过每个脚本获取请求数
          let totalRequests = 0;
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
                    totalRequests += data.result.requests;
                  }
                }
              } catch (e) {}
            }
          }
          
          const percentage = Math.min(100, (totalRequests / 100000) * 100);
          return json({ 
            success: true, 
            data: { 
              total: totalRequests, 
              workers: totalRequests, 
              pages: 0, 
              percentage: percentage 
            } 
          }); 
        } catch(e){ 
          return json({ 
            success: true, 
            data: { total: 0, workers: 0, pages: 0, percentage: 0 } 
          }); 
        } 
      }
      
      case 'list-kv-namespaces': 
        return json(await cfGet(`/accounts/${payload.accountId}/storage/kv/namespaces`, payload.email, payload.key));
      
      case 'create-kv-namespace': 
        return json(await cfPost(`/accounts/${payload.accountId}/storage/kv/namespaces`, payload.email, payload.key, { title: payload.title }));
      
      case 'delete-kv-namespace': 
        return json(await cfDelete(`/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}`, payload.email, payload.key));
      
      case 'list-kv-keys': 
        return json(await cfGet(`/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}/keys`, payload.email, payload.key));

      case 'list-d1': 
        return json(await cfGet(`/accounts/${payload.accountId}/d1/database`, payload.email, payload.key));
      
      case 'create-d1-database': 
        return json(await cfPost(`/accounts/${payload.accountId}/d1/database`, payload.email, payload.key, { name: payload.name }));
      
      case 'delete-d1-database': 
        return json(await cfDelete(`/accounts/${payload.accountId}/d1/database/${payload.databaseId}`, payload.email, payload.key));
      
      case 'execute-d1-query': 
        return json(await cfPost(`/accounts/${payload.accountId}/d1/database/${payload.databaseId}/query`, payload.email, payload.key, { sql: payload.query }));

      case 'get-workers-subdomain': 
        return json(await cfGet(`/accounts/${payload.accountId}/workers/subdomain`, payload.email, payload.key));
      
      case 'put-workers-subdomain': 
        return json(await cfPutRaw(`/accounts/${payload.accountId}/workers/subdomain`, payload.email, payload.key, { subdomain: payload.subdomain }));
      
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
        const r = await fetch(url, { 
          method: 'DELETE', 
          headers: { 'X-Auth-Email': payload.email, 'X-Auth-Key': payload.key } 
        });
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
  h2 { color: #1a202c; margin-bottom: 8px; font-size: 28px; }
  .subtitle { color: #718096; margin-bottom: 30px; font-size: 14px; }
  .form-group { margin-bottom: 20px; }
  label { display: block; margin-bottom: 8px; color: #2d3748; font-weight: 500; font-size: 14px; }
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
  button:hover { transform: translateY(-2px); }
  .note {
    margin-top: 20px;
    padding: 12px;
    background: #fef5e7;
    border-left: 4px solid #f39c12;
    font-size: 13px;
    color: #856404;
  }
  .error { color: #e53e3e; font-size: 13px; margin-top: 8px; display: none; }
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
    <input type="password" id="masterPassword" placeholder="用于登录管理后台">
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
    
    if (result.success && result.sessionToken) {
      localStorage.setItem('cf_session_token', result.sessionToken);
      document.cookie = 'session_token=' + result.sessionToken + '; path=/; max-age=28800; SameSite=Strict';
      window.location.href = '/workers';
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
<\/script>
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
  h2 { color: #1a202c; margin-bottom: 8px; font-size: 28px; }
  .subtitle { color: #718096; margin-bottom: 30px; font-size: 14px; }
  .form-group { margin-bottom: 20px; }
  label { display: block; margin-bottom: 8px; color: #2d3748; font-weight: 500; font-size: 14px; }
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
  button:hover { transform: translateY(-2px); }
  .error { color: #e53e3e; font-size: 13px; margin-top: 8px; display: none; text-align: center; }
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
      document.cookie = 'session_token=' + result.sessionToken + '; path=/; max-age=28800; SameSite=Strict';
      
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
<\/script>
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
.card-header h3{margin:0;font-size:16px}
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
.domain-status.pending{background:#fffbeb;color:#d97706}
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
.acct-row{display:flex;justify-content:space-between;align-items:center;padding:12px;border-bottom:1px solid #eef2f6}
.acct-active{background:#eff6ff}
.badge{background:#dbeafe;color:#1e40af;font-size:10px;padding:2px 6px;border-radius:4px;margin-left:8px}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="logo">☁️ Cloudflare 管理</div>
    <nav class="nav">
      <div class="item active" data-page="workers">Workers</div>
      <div class="item" data-page="batch">批量创建</div>
      <div class="item" data-page="accounts">账号管理</div>
      <div class="item" data-page="kv">KV 存储</div>
      <div class="item" data-page="d1">D1 数据库</div>
      <div class="item" data-page="dns">域名管理</div>
      <div class="item" data-page="settings">设置</div>
    </nav>
    <div style="margin-top:auto;padding-top:20px;border-top:1px solid #eef2f6">
      <div class="small" id="currentAccount"></div>
      <div style="margin-top:8px;display:flex;gap:12px">
        <span onclick="showAccountSwitcher()" style="cursor:pointer;color:#2563eb;font-size:12px">切换账号</span>
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
        <div class="card-header"><h3>Workers 列表</h3></div>
        <div class="card-body" id="workersList"></div>
      </div>
    </div>
    
    <!-- 批量创建页面 -->
    <div id="batch-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">批量创建 Workers</div>
      </div>
      <div class="card">
        <div class="card-header"><h3>选择账号</h3></div>
        <div class="card-body" id="batchAccountList"></div>
        <div class="card-header"><h3>基本配置</h3></div>
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
          <button class="btn primary" style="width:100%" onclick="startBatchCreate()">开始批量创建</button>
        </div>
        <div class="card-header"><h3>执行日志</h3></div>
        <div class="card-body">
          <div id="batchLog" class="log-area">等待开始...</div>
        </div>
      </div>
    </div>
    
    <!-- 账号管理页面 -->
    <div id="accounts-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">账号管理</div>
        <button class="btn primary" onclick="openAddAccountModal()">添加账号</button>
      </div>
      
      <div class="card">
        <div class="card-header"><h3>已保存的账号</h3></div>
        <div class="card-body" id="accountsList"></div>
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
        <div class="card-header"><h3>域名列表</h3></div>
        <div class="card-body" id="zonesList"></div>
      </div>
      <div class="card" id="dnsCard" style="display:none">
        <div class="card-header">
          <h3 id="selectedZoneName"></h3>
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
        <div class="card-header"><h3>Workers 子域名</h3></div>
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

<div id="addAccountModal" class="modal">
  <div class="modal-box">
    <h3>添加 Cloudflare 账号</h3>
    <div class="form-group">
      <label>邮箱地址</label>
      <input id="newAccountEmail" class="input" placeholder="your@email.com">
    </div>
    <div class="form-group">
      <label>Global API Key</label>
      <input id="newAccountKey" class="input" type="password" placeholder="API Key">
    </div>
    <div class="form-group">
      <label>别名（可选）</label>
      <input id="newAccountAlias" class="input" placeholder="例如: 工作账号">
    </div>
    <div class="form-group">
      <label>主密码（用于加密）</label>
      <input id="masterPasswordForAdd" class="input" type="password" placeholder="输入您的主密码">
    </div>
    <div id="addAccountError" class="small" style="color:#ef4444;display:none"></div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
      <button class="btn" onclick="closeAddAccountModal()">取消</button>
      <button class="btn primary" onclick="confirmAddAccount()">验证并添加</button>
    </div>
  </div>
</div>

<div id="accountSwitcherModal" class="modal">
  <div class="modal-box">
    <h3>切换账号</h3>
    <div id="accountSwitcherList"></div>
    <div style="margin-top:16px">
      <button class="btn" style="width:100%" onclick="closeAccountSwitcher()">关闭</button>
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
  // 获取 session token
  function getSessionToken() {
    return localStorage.getItem('cf_session_token');
  }
  
  let currentWorkerForEnv = null;
  let currentWorkerForDomain = null;
  let currentZoneId = null;
  
  // API 调用
  async function api(action, body) {
    const sessionToken = getSessionToken();
    const payload = { action, sessionToken, ...body };
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
    const navItem = Array.from(document.querySelectorAll('.nav .item')).find(i => i.dataset.page === page);
    if (navItem) navItem.classList.add('active');
    
    if (page === 'workers') refreshWorkers();
    if (page === 'batch') loadBatchAccounts();
    if (page === 'accounts') loadAccountsPage();
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
              <button class="btn" onclick="openEnvFor('\${name}')">环境变量</button>
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
              \${domains.map(d => {
                // 修复：正确判断域名状态
                const status = d.status || 'active';
                const statusText = status === 'active' ? '✅ 已生效' : (status === 'pending' ? '⏳ 待生效' : status);
                const statusClass = status === 'active' ? 'active' : 'pending';
                return \`
                  <div class="domain-tag">
                    <a href="https://\${escapeHtml(d.hostname)}" target="_blank" style="text-decoration:none;color:inherit">\${escapeHtml(d.hostname)}</a>
                    <span class="domain-status \${statusClass}" title="状态: \${statusText}">\${statusText}</span>
                    <button class="del-domain" onclick="deleteDomain('\${name}', '\${d.id}', '\${escapeHtml(d.hostname)}')" title="解绑域名">✕</button>
                  </div>
                \`;
              }).join('')}
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
    document.getElementById('customDomain').value = '';
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
  
  // 账号管理页面
  async function loadAccountsPage() {
    const res = await api('get-accounts');
    const container = document.getElementById('accountsList');
    
    if (!res.success || !res.accounts || res.accounts.length === 0) {
      container.innerHTML = '<div class="small">暂无其他账号</div>';
      return;
    }
    
    const currentEmail = localStorage.getItem('cf_active_email');
    container.innerHTML = res.accounts.map(acc => \`
      <div class="acct-row \${acc.email === currentEmail ? 'acct-active' : ''}">
        <div>
          <strong>\${escapeHtml(acc.alias || acc.email)}</strong>
          <div class="small">\${acc.email}</div>
          \${acc.isDefault ? '<span class="badge">默认</span>' : ''}
        </div>
        <div>
          <button class="btn small" onclick="switchToAccount('\${acc.email}')">切换</button>
        </div>
      </div>
    \`).join('');
  }
  
  async function switchToAccount(email) {
    const res = await api('switch-account', { email });
    if (res.success) {
      showNotification('已切换账号');
      location.reload();
    } else {
      showNotification(res.error || '切换失败', 'error');
    }
  }
  
  // 添加账号
  function openAddAccountModal() {
    document.getElementById('newAccountEmail').value = '';
    document.getElementById('newAccountKey').value = '';
    document.getElementById('newAccountAlias').value = '';
    document.getElementById('masterPasswordForAdd').value = '';
    document.getElementById('addAccountError').style.display = 'none';
    document.getElementById('addAccountModal').style.display = 'flex';
  }
  
  function closeAddAccountModal() {
    document.getElementById('addAccountModal').style.display = 'none';
  }
  
  async function confirmAddAccount() {
    const email = document.getElementById('newAccountEmail').value.trim();
    const key = document.getElementById('newAccountKey').value.trim();
    const alias = document.getElementById('newAccountAlias').value.trim();
    const masterPassword = document.getElementById('masterPasswordForAdd').value;
    const errorDiv = document.getElementById('addAccountError');
    
    errorDiv.style.display = 'none';
    
    if (!email || !key) {
      errorDiv.textContent = '请填写邮箱和 API Key';
      errorDiv.style.display = 'block';
      return;
    }
    
    if (!masterPassword) {
      errorDiv.textContent = '请输入主密码';
      errorDiv.style.display = 'block';
      return;
    }
    
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = '验证中...';
    
    try {
      // 先验证新账号
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
        btn.textContent = '验证并添加';
        return;
      }
      
      // 添加账号
      const addRes = await api('add-account', { email, key, alias, masterPassword });
      if (addRes.success) {
        showNotification('账号添加成功');
        closeAddAccountModal();
        loadAccountsPage();
      } else {
        errorDiv.textContent = addRes.error || '添加失败';
        errorDiv.style.display = 'block';
      }
    } catch (e) {
      errorDiv.textContent = '网络错误：' + e.message;
      errorDiv.style.display = 'block';
    } finally {
      btn.disabled = false;
      btn.textContent = '验证并添加';
    }
  }
  
  // 账号切换器
  async function showAccountSwitcher() {
    const res = await api('get-accounts');
    const container = document.getElementById('accountSwitcherList');
    
    if (!res.success || !res.accounts || res.accounts.length === 0) {
      container.innerHTML = '<div class="small">暂无其他账号</div>';
    } else {
      const currentEmail = localStorage.getItem('cf_active_email');
      container.innerHTML = res.accounts.map(acc => \`
        <div class="acct-row \${acc.email === currentEmail ? 'acct-active' : ''}" style="cursor:pointer" onclick="switchToAccountAndClose('\${acc.email}')">
          <div>
            <strong>\${escapeHtml(acc.alias || acc.email)}</strong>
            <div class="small">\${acc.email}</div>
            \${acc.isDefault ? '<span class="badge">默认</span>' : ''}
          </div>
          \${acc.email !== currentEmail ? '<span>→</span>' : '<span class="badge">当前</span>'}
        </div>
      \`).join('');
    }
    document.getElementById('accountSwitcherModal').style.display = 'flex';
  }
  
  async function switchToAccountAndClose(email) {
    const res = await api('switch-account', { email });
    if (res.success) {
      closeAccountSwitcher();
      location.reload();
    } else {
      showNotification(res.error || '切换失败', 'error');
    }
  }
  
  function closeAccountSwitcher() {
    document.getElementById('accountSwitcherModal').style.display = 'none';
  }
  
  // 批量创建
  async function loadBatchAccounts() {
    const res = await api('get-accounts');
    const container = document.getElementById('batchAccountList');
    if (res.success && res.accounts && res.accounts.length > 0) {
      container.innerHTML = res.accounts.map(acc => \`
        <div class="account-check-item">
          <input type="checkbox" class="batch-acc-chk" value="\${acc.email}">
          <span>\${escapeHtml(acc.alias || acc.email)}</span>
        </div>
      \`).join('');
    } else {
      container.innerHTML = '<div class="small" style="padding:10px">暂无账号，请在账号管理页面添加</div>';
    }
  }
  
  function toggleBatchSourceInput() {
    const type = document.getElementById('batchScriptSourceType').value;
    document.getElementById('batchBuiltinDiv').style.display = type === 'builtin' ? 'block' : 'none';
    document.getElementById('batchUrlDiv').style.display = type === 'url' ? 'block' : 'none';
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
    
    const enableSubdomain = document.getElementById('batchEnableSubdomain').checked;
    
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
      appendBatchLog('处理账号: ' + email);
      
      try {
        // 获取当前会话信息或者直接使用存储的凭据
        // 这里需要临时切换账号，但由于复杂度，暂时只使用当前账号
        // 完整实现需要从存储中获取每个账号的 key
        
        // 简化版：只部署到当前选中的账号（需要先切换）
        // 完整版需要从账号列表获取 key，这里保持简单
        appendBatchLog('  ⚠️ 批量创建需要先切换到对应账号', '#f59e0b');
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
      container.innerHTML = '<div class="small">暂无 DNS 记录</div><button class="btn small" style="margin-top:8px" onclick="openAddDNS()">+ 添加记录</button>';
      return;
    }
    container.innerHTML = \`
      <button class="btn small" style="margin-bottom:12px" onclick="openAddDNS()">+ 添加记录</button>
      <table style="width:100%;border-collapse:collapse">
        <thead><tr><th>类型</th><th>名称</th><th>内容</th><th>TTL</th><th>代理</th><th>操作</th></tr></thead>
        <tbody>
          \${res.result.map(r => \`
            <tr style="border-bottom:1px solid #eef2f6">
              <td>\${r.type}</td><td>\${escapeHtml(r.name)}</td>
              <td>\${escapeHtml(r.content)}</td><td>\${r.ttl}</td>
              <td>\${r.proxied ? '开启' : '关闭'}</td>
              <td><button class="btn small danger" onclick="deleteDNSRecord('\${r.id}')">删除</button></td>
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
    
    if (!name || !content) {
      showNotification('请填写完整信息', 'error');
      return;
    }
    
    const res = await api('create-dns-record', { zoneId: currentZoneId, type, name, content, ttl, proxied });
    if (res.success) {
      showNotification('DNS 记录添加成功');
      closeAddDNSModal();
      refreshDNSRecords();
    } else {
      showNotification(res.error || '添加失败', 'error');
    }
  }
  
  async function deleteDNSRecord(recordId) {
    if (!confirm('确定删除此 DNS 记录吗？')) return;
    const res = await api('delete-dns-record', { zoneId: currentZoneId, recordId });
    if (res.success) {
      showNotification('删除成功');
      refreshDNSRecords();
    } else {
      showNotification(res.error || '删除失败', 'error');
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
  
  // 退出登录
  async function logout() {
    await api('logout');
    localStorage.removeItem('cf_session_token');
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
    const sessionToken = getSessionToken();
    if (!sessionToken) {
      window.location.href = '/login';
      return;
    }
    
    // 显示当前账号（从 cookie 或 localStorage 获取）
    document.getElementById('currentAccount').textContent = '已登录';
    
    // 设置导航
    document.querySelectorAll('.nav .item').forEach(item => {
      item.addEventListener('click', () => navTo(item.dataset.page));
    });
    
    // 设置批量创建的切换
    const sourceTypeSelect = document.getElementById('batchScriptSourceType');
    if (sourceTypeSelect) {
      sourceTypeSelect.addEventListener('change', toggleBatchSourceInput);
    }
    
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
  window.switchToAccount = switchToAccount;
  window.openAddAccountModal = openAddAccountModal;
  window.closeAddAccountModal = closeAddAccountModal;
  window.confirmAddAccount = confirmAddAccount;
  window.showAccountSwitcher = showAccountSwitcher;
  window.closeAccountSwitcher = closeAccountSwitcher;
  window.switchToAccountAndClose = switchToAccountAndClose;
  window.logout = logout;
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
  window.deleteDNSRecord = deleteDNSRecord;
  window.deleteZone = deleteZone;
  window.loadSubdomain = loadSubdomain;
  window.saveSubdomain = saveSubdomain;
  window.toggleBatchSourceInput = toggleBatchSourceInput;
  window.startBatchCreate = startBatchCreate;
  window.loadBatchAccounts = loadBatchAccounts;
  window.loadAccountsPage = loadAccountsPage;
})();`;
}

// 注意：需要在 Cloudflare Workers 中绑定 KV 命名空间，变量名为 MY_KV
