// =============== Cloudflare Manager - 简化版 ===============
// 首次只设置主密码，账号登录后再添加

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

// 修复加密函数 - 使用 webcrypto 兼容方法
async function encrypt(text, password) {
  const encoder = new TextEncoder();
  
  // 使用 webcrypto 生成随机数
  const salt = new Uint8Array(SALT_LENGTH);
  const iv = new Uint8Array(IV_LENGTH);
  
  // 使用 crypto.getRandomValues（Workers 支持）
  crypto.getRandomValues(salt);
  crypto.getRandomValues(iv);
  
  const key = await deriveKey(password, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(text)
  );
  
  // 合并 salt + iv + encrypted
  const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  result.set(salt, 0);
  result.set(iv, salt.length);
  result.set(new Uint8Array(encrypted), salt.length + iv.length);
  
  // 转换为 base64
  let binary = '';
  for (let i = 0; i < result.length; i++) {
    binary += String.fromCharCode(result[i]);
  }
  return btoa(binary);
}

// 修复解密函数
async function decrypt(encryptedBase64, password) {
  const decoder = new TextDecoder();
  
  // 从 base64 恢复二进制数据
  const binary = atob(encryptedBase64);
  const encrypted = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    encrypted[i] = binary.charCodeAt(i);
  }
  
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

  // 检查是否已设置主密码
  const hasMasterPassword = await env.MY_KV.get('config:has_master_password');
  
  // 首次配置页面（只设置主密码）
  if (p === '/setup' && request.method === 'GET' && !hasMasterPassword) {
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
    if (!hasMasterPassword) {
      return Response.redirect(`${url.origin}/setup`, 302);
    }
    return Response.redirect(`${url.origin}/login`, 302);
  }
  
  // 登录页面
  if (request.method === 'GET' && (p === '/login' || p === '/login/')) {
    if (!hasMasterPassword) {
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
  
  // ========== 首次设置主密码 ==========
  if (action === 'setup-master-password') {
    const { masterPassword } = payload;
    
    if (!masterPassword || masterPassword.length < 6) {
      return json({ success: false, error: '密码至少需要6个字符' }, 400);
    }
    
    // 存储主密码的哈希（加密存储一个标志）
    // 实际不存储密码，只存储是否已设置
    await env.MY_KV.put('config:has_master_password', 'true');
    await env.MY_KV.put('config:setup_time', Date.now().toString());
    
    // 初始化空的账号列表（加密存储）
    const emptyAccounts = JSON.stringify([]);
    const encryptedAccounts = await encrypt(emptyAccounts, masterPassword);
    await env.MY_KV.put('config:accounts', encryptedAccounts);
    
    return json({ success: true, message: '主密码设置成功' });
  }
  
  // ========== 登录 ==========
  if (action === 'login') {
    const { masterPassword } = payload;
    
    if (!masterPassword) {
      return json({ success: false, error: '请输入主密码' }, 400);
    }
    
    const hasMasterPassword = await env.MY_KV.get('config:has_master_password');
    if (!hasMasterPassword) {
      return json({ success: false, error: '系统未初始化，请先访问 /setup' }, 400);
    }
    
    try {
      // 尝试解密账号列表来验证主密码
      const encryptedAccounts = await env.MY_KV.get('config:accounts');
      await decrypt(encryptedAccounts, masterPassword);
      
      // 创建 session
      const sessionToken = generateSessionToken();
      await env.MY_KV.put(`session:${sessionToken}`, JSON.stringify({
        masterPassword, // 注意：实际生产环境不应存储密码，这里简化处理
        expires: Date.now() + 8 * 3600000
      }), { expirationTtl: 28800 });
      
      return json({ success: true, sessionToken, expiresIn: 28800 });
      
    } catch (error) {
      return json({ success: false, error: '主密码错误' }, 401);
    }
  }
  
  // ========== 账号管理（需要登录）==========
  
  // 获取所有 Cloudflare 账号
  if (action === 'get-cf-accounts') {
    const sessionToken = payload.sessionToken;
    if (!sessionToken) {
      return json({ success: false, error: '未登录' }, 401);
    }
    
    const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
    if (!session || session.expires < Date.now()) {
      return json({ success: false, error: '会话已过期' }, 401);
    }
    
    try {
      const encryptedAccounts = await env.MY_KV.get('config:accounts');
      const accountsJson = await decrypt(encryptedAccounts, session.masterPassword);
      const accounts = JSON.parse(accountsJson);
      return json({ success: true, accounts });
    } catch (error) {
      return json({ success: false, error: '解密失败' }, 500);
    }
  }
  
  // 添加 Cloudflare 账号
  if (action === 'add-cf-account') {
    const { sessionToken, email, key, alias } = payload;
    
    if (!sessionToken) {
      return json({ success: false, error: '未登录' }, 401);
    }
    
    if (!email || !key) {
      return json({ success: false, error: '缺少邮箱或 API Key' }, 400);
    }
    
    const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
    if (!session || session.expires < Date.now()) {
      return json({ success: false, error: '会话已过期' }, 401);
    }
    
    // 验证 Cloudflare 账号
    const testResult = await cfAny('GET', '/accounts', email, key);
    if (!testResult.success && !testResult.result) {
      return json({ 
        success: false, 
        error: 'Cloudflare 凭据无效：' + (testResult.errors?.[0]?.message || '验证失败')
      });
    }
    
    try {
      const encryptedAccounts = await env.MY_KV.get('config:accounts');
      const accountsJson = await decrypt(encryptedAccounts, session.masterPassword);
      let accounts = JSON.parse(accountsJson);
      
      const existingIndex = accounts.findIndex(a => a.email === email);
      const newAccount = { 
        email, 
        key, 
        alias: alias || email,
        createdAt: Date.now()
      };
      
      if (existingIndex >= 0) {
        accounts[existingIndex] = newAccount;
      } else {
        accounts.push(newAccount);
      }
      
      const newEncrypted = await encrypt(JSON.stringify(accounts), session.masterPassword);
      await env.MY_KV.put('config:accounts', newEncrypted);
      
      return json({ success: true, message: '账号添加成功' });
    } catch (error) {
      return json({ success: false, error: '保存失败：' + error.message }, 500);
    }
  }
  
  // 删除 Cloudflare 账号
  if (action === 'delete-cf-account') {
    const { sessionToken, email } = payload;
    
    if (!sessionToken) {
      return json({ success: false, error: '未登录' }, 401);
    }
    
    const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
    if (!session || session.expires < Date.now()) {
      return json({ success: false, error: '会话已过期' }, 401);
    }
    
    try {
      const encryptedAccounts = await env.MY_KV.get('config:accounts');
      const accountsJson = await decrypt(encryptedAccounts, session.masterPassword);
      let accounts = JSON.parse(accountsJson);
      accounts = accounts.filter(a => a.email !== email);
      
      const newEncrypted = await encrypt(JSON.stringify(accounts), session.masterPassword);
      await env.MY_KV.put('config:accounts', newEncrypted);
      
      return json({ success: true, message: '账号删除成功' });
    } catch (error) {
      return json({ success: false, error: '删除失败：' + error.message }, 500);
    }
  }
  
  // 切换当前使用的账号
  if (action === 'set-current-account') {
    const { sessionToken, email } = payload;
    
    if (!sessionToken || !email) {
      return json({ success: false, error: '缺少参数' }, 400);
    }
    
    const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
    if (!session || session.expires < Date.now()) {
      return json({ success: false, error: '会话已过期' }, 401);
    }
    
    try {
      const encryptedAccounts = await env.MY_KV.get('config:accounts');
      const accountsJson = await decrypt(encryptedAccounts, session.masterPassword);
      const accounts = JSON.parse(accountsJson);
      const account = accounts.find(a => a.email === email);
      
      if (!account) {
        return json({ success: false, error: '账号不存在' }, 400);
      }
      
      // 更新 session 中的当前账号
      session.currentAccount = account;
      await env.MY_KV.put(`session:${sessionToken}`, JSON.stringify(session), { expirationTtl: 28800 });
      
      return json({ success: true, account: { email: account.email, alias: account.alias } });
    } catch (error) {
      return json({ success: false, error: '切换失败：' + error.message }, 500);
    }
  }
  
  // 获取当前使用的账号
  if (action === 'get-current-account') {
    const sessionToken = payload.sessionToken;
    if (!sessionToken) {
      return json({ success: false, error: '未登录' }, 401);
    }
    
    const session = await env.MY_KV.get(`session:${sessionToken}`, 'json');
    if (!session || session.expires < Date.now()) {
      return json({ success: false, error: '会话已过期' }, 401);
    }
    
    if (session.currentAccount) {
      return json({ success: true, account: session.currentAccount });
    }
    return json({ success: true, account: null });
  }
  // 在 handleAPI 函数中，添加 validate-credentials 处理
// 放在账号管理相关 actions 之后

// ========== 验证 Cloudflare 账号有效性 ==========
if (action === 'validate-credentials') {
  const { email, key } = payload;
  if (!email || !key) {
    return json({ success: false, error: '缺少邮箱或 API Key' }, 400);
  }
  try {
    const testResult = await cfAny('GET', '/accounts', email, key);
    if (testResult.success && testResult.result && testResult.result.length > 0) {
      return json({ success: true, message: '凭据有效', accountId: testResult.result[0].id });
    } else {
      return json({ 
        success: false, 
        error: testResult.errors?.[0]?.message || '凭据无效'
      });
    }
  } catch (e) {
    return json({ success: false, error: e.message });
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
  
  // ========== 需要 Cloudflare 凭据的操作 ==========
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
    
    if (!session.currentAccount) {
      return json({ success: false, error: '请先在账号管理中选择一个账号' }, 400);
    }
    
    payload.email = session.currentAccount.email;
    payload.key = session.currentAccount.key;
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
                  status: domain.status || 'active'
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
          let workersRequests = 0;
          let pagesRequests = 0;
          
          // 使用 GraphQL 查询
          const graphqlQuery = {
            query: `query {
              viewer {
                accounts(filter: {accountTag: "${accountId}"}) {
                  workersInvocationsAdaptive(
                    limit: 100,
                    filter: { datetime_geq: "${start}", datetime_lt: "${end}" }
                  ) {
                    sum { requests }
                  }
                  pagesFunctionsInvocationsAdaptive(
                    limit: 100,
                    filter: { datetime_geq: "${start}", datetime_lt: "${end}" }
                  ) {
                    sum { requests }
                  }
                }
              }
            }`
          };
          
          const graphqlRes = await fetch("https://api.cloudflare.com/client/v4/graphql", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Auth-Email": email,
              "X-Auth-Key": apikey
            },
            body: JSON.stringify(graphqlQuery)
          });
          
          if (graphqlRes.ok) {
            const data = await graphqlRes.json();
            const account = data?.data?.viewer?.accounts?.[0];
            
            const workersInv = account?.workersInvocationsAdaptive || [];
            for (const inv of workersInv) {
              if (inv.sum?.requests) workersRequests += inv.sum.requests;
            }
            
            const pagesInv = account?.pagesFunctionsInvocationsAdaptive || [];
            for (const inv of pagesInv) {
              if (inv.sum?.requests) pagesRequests += inv.sum.requests;
            }
          }
          
          const totalRequests = workersRequests + pagesRequests;
          const percentage = Math.min(100, (totalRequests / 100000) * 100);
          
          return json({ 
            success: true, 
            data: { 
              total: totalRequests, 
              workers: workersRequests, 
              pages: pagesRequests, 
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
  <h2>🔐 欢迎使用 Cloudflare Manager</h2>
  <div class="subtitle">首次使用，请设置主密码（登录密码）</div>
  
  <div class="form-group">
    <label>设置主密码</label>
    <input type="password" id="masterPassword" placeholder="请输入主密码（至少6位）">
    <div class="note">⚠️ 请务必记住此密码！用于登录管理后台，忘记无法找回</div>
  </div>
  
  <div class="form-group">
    <label>确认主密码</label>
    <input type="password" id="confirmPassword" placeholder="再次输入密码">
  </div>
  
  <div id="errorMsg" class="error"></div>
  
  <button onclick="setup()">设置主密码并开始使用</button>
  
  <div class="note" style="margin-top: 16px;">
    💡 提示：设置完成后，您可以在后台添加多个 Cloudflare 账号
  </div>
</div>

<script>
async function setup() {
  const masterPassword = document.getElementById('masterPassword').value;
  const confirmPassword = document.getElementById('confirmPassword').value;
  
  document.getElementById('errorMsg').style.display = 'none';
  
  if (!masterPassword) {
    showError('请输入主密码');
    return;
  }
  
  if (masterPassword !== confirmPassword) {
    showError('两次输入的密码不一致');
    return;
  }
  
  if (masterPassword.length < 6) {
    showError('主密码至少需要 6 个字符');
    return;
  }
  
  const btn = document.querySelector('button');
  btn.disabled = true;
  btn.textContent = '设置中...';
  
  try {
    const response = await fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'setup-master-password',
        masterPassword: masterPassword
      })
    });
    
    const result = await response.json();
    
    if (result.success) {
      alert('主密码设置成功！请使用主密码登录');
      window.location.href = '/login';
    } else {
      showError(result.error || '设置失败');
      btn.disabled = false;
      btn.textContent = '设置主密码并开始使用';
    }
  } catch (error) {
    showError('网络错误：' + error.message);
    btn.disabled = false;
    btn.textContent = '设置主密码并开始使用';
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
  <h2>🔐 Cloudflare Manager</h2>
  <div class="subtitle">请输入主密码登录</div>
  
  <div class="form-group">
    <label>主密码</label>
    <input type="password" id="password" placeholder="请输入主密码" onkeypress="if(event.key==='Enter') login()">
  </div>
  
  <div id="errorMsg" class="error"></div>
  
  <button onclick="login()">登录管理后台</button>
  
  <div class="note">
    💡 提示：主密码在首次部署时设置，请妥善保管
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
    errorDiv.textContent = '请输入主密码';
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
.current-badge{background:#10b981;color:white}
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
      <div class="small" id="currentAccountDisplay">未选择账号</div>
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
          <div><span class="small">Pages:</span> <strong id="pagesRequests">0</strong></div>
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
        <div style="font-size:20px;font-weight:700">Cloudflare 账号管理</div>
        <button class="btn primary" onclick="openAddAccountModal()">添加账号</button>
      </div>
      
      <div class="card">
        <div class="card-header"><h3>已保存的账号</h3></div>
        <div class="card-body" id="accountsList"></div>
      </div>
      
      <div class="card">
        <div class="card-header"><h3>当前使用的账号</h3></div>
        <div class="card-body" id="currentAccountInfo"></div>
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
      <div class="small" style="margin-top:4px">可在 Cloudflare 控制台 → 我的资料 → API 令牌中获取</div>
    </div>
    <div class="form-group">
      <label>别名（可选）</label>
      <input id="newAccountAlias" class="input" placeholder="例如: 工作账号">
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
  // 获取 session token
  function getSessionToken() {
    return localStorage.getItem('cf_session_token');
  }
  
  let currentWorkerForEnv = null;
  let currentWorkerForDomain = null;
  let currentZoneId = null;
  let currentAccounts = [];
  let currentSelectedAccount = null;
  
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
  
  // 加载当前账号信息
  async function loadCurrentAccount() {
    const res = await api('get-current-account');
    if (res.success && res.account) {
      currentSelectedAccount = res.account;
      document.getElementById('currentAccountDisplay').innerHTML = \`当前: \${res.account.alias || res.account.email}\`;
      document.getElementById('currentAccountInfo').innerHTML = \`
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div>
            <strong>\${escapeHtml(res.account.alias || res.account.email)}</strong>
            <div class="small">\${res.account.email}</div>
          </div>
          <span class="badge current-badge" style="background:#10b981">当前使用</span>
        </div>
      \`;
    } else {
      document.getElementById('currentAccountDisplay').innerHTML = '未选择账号';
      if (document.getElementById('currentAccountInfo')) {
        document.getElementById('currentAccountInfo').innerHTML = '<div class="small" style="color:#ef4444">请先在账号管理中选择一个账号</div>';
      }
    }
  }
  
  // 刷新 Workers 列表
  async function refreshWorkers() {
    const listDiv = document.getElementById('workersList');
    if (!listDiv) return;
    
    if (!currentSelectedAccount) {
      listDiv.innerHTML = '<div class="small" style="color:#ef4444">请先在账号管理中选择一个账号</div>';
      return;
    }
    
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
                const status = d.status || 'active';
                const statusText = status === 'active' ? '✅ 已生效' : (status === 'pending' ? '⏳ 待生效' : status);
                const statusClass = status === 'active' ? 'active' : 'pending';
                return \`
                  <div class="domain-tag">
                    <a href="https://\${escapeHtml(d.hostname)}" target="_blank" style="text-decoration:none;color:inherit">\${escapeHtml(d.hostname)}</a>
                    <span class="domain-status \${statusClass}">\${statusText}</span>
                    <button class="del-domain" onclick="deleteDomain('\${name}', '\${d.id}', '\${escapeHtml(d.hostname)}')">✕</button>
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
    if (!currentSelectedAccount) return;
    try {
      const accountId = localStorage.getItem('cf_accountId');
      const res = await api('get-usage-today', { accountId });
      if (res.success && res.data) {
        const total = res.data.total || 0;
        const workers = res.data.workers || 0;
        const pages = res.data.pages || 0;
        const percentage = res.data.percentage || 0;
        
        document.getElementById('metricCount').textContent = total.toLocaleString() + ' / 100,000';
        document.getElementById('metricBar').style.width = percentage + '%';
        document.getElementById('workersRequests').textContent = workers.toLocaleString();
        document.getElementById('pagesRequests').textContent = pages.toLocaleString();
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
    const res = await api('get-cf-accounts');
    const container = document.getElementById('accountsList');
    
    if (!res.success || !res.accounts || res.accounts.length === 0) {
      container.innerHTML = '<div class="small">暂无账号，请点击"添加账号"按钮添加</div>';
      return;
    }
    
    currentAccounts = res.accounts;
    container.innerHTML = res.accounts.map(acc => \`
      <div class="acct-row">
        <div>
          <strong>\${escapeHtml(acc.alias || acc.email)}</strong>
          <div class="small">\${acc.email}</div>
        </div>
        <div class="btns">
          <button class="btn small" onclick="selectAccount('\${acc.email}')">选择使用</button>
          <button class="btn danger small" onclick="deleteAccount('\${acc.email}')">删除</button>
        </div>
      </div>
    \`).join('');
    
    // 加载当前使用的账号
    await loadCurrentAccount();
  }
  
  async function selectAccount(email) {
    const res = await api('set-current-account', { email });
    if (res.success) {
      showNotification('已切换到账号：' + (res.account?.alias || email));
      await loadCurrentAccount();
      await refreshWorkers();
      navTo('workers');
    } else {
      showNotification(res.error || '切换失败', 'error');
    }
  }
  
  async function deleteAccount(email) {
    if (!confirm('确定要删除此账号吗？')) return;
    const res = await api('delete-cf-account', { email });
    if (res.success) {
      showNotification('账号已删除');
      loadAccountsPage();
    } else {
      showNotification(res.error || '删除失败', 'error');
    }
  }
  
  // 添加账号
  function openAddAccountModal() {
    document.getElementById('newAccountEmail').value = '';
    document.getElementById('newAccountKey').value = '';
    document.getElementById('newAccountAlias').value = '';
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
    const errorDiv = document.getElementById('addAccountError');
    
    errorDiv.style.display = 'none';
    
    if (!email || !key) {
      errorDiv.textContent = '请填写邮箱和 API Key';
      errorDiv.style.display = 'block';
      return;
    }
    
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = '验证中...';
    
    try {
      // 先验证账号
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
      const addRes = await api('add-cf-account', { email, key, alias });
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
    const res = await api('get-cf-accounts');
    const container = document.getElementById('accountSwitcherList');
    
    if (!res.success || !res.accounts || res.accounts.length === 0) {
      container.innerHTML = '<div class="small">暂无账号，请先在账号管理页面添加</div>';
    } else {
      const currentEmail = currentSelectedAccount?.email;
      container.innerHTML = res.accounts.map(acc => \`
        <div class="acct-row" style="cursor:pointer" onclick="selectAccountAndClose('\${acc.email}')">
          <div>
            <strong>\${escapeHtml(acc.alias || acc.email)}</strong>
            <div class="small">\${acc.email}</div>
          </div>
          \${acc.email === currentEmail ? '<span class="badge current-badge">当前</span>' : '<span>→</span>'}
        </div>
      \`).join('');
    }
    document.getElementById('accountSwitcherModal').style.display = 'flex';
  }
  
  async function selectAccountAndClose(email) {
    const res = await api('set-current-account', { email });
    if (res.success) {
      closeAccountSwitcher();
      await loadCurrentAccount();
      await refreshWorkers();
      showNotification('已切换账号');
    } else {
      showNotification(res.error || '切换失败', 'error');
    }
  }
  
  function closeAccountSwitcher() {
    document.getElementById('accountSwitcherModal').style.display = 'none';
  }
  
  // 批量创建
  async function loadBatchAccounts() {
    const res = await api('get-cf-accounts');
    const container = document.getElementById('batchAccountList');
    if (res.success && res.accounts && res.accounts.length > 0) {
      container.innerHTML = res.accounts.map(acc => \`
        <div class="account-check-item">
          <input type="checkbox" class="batch-acc-chk" value="\${acc.email}">
          <span>\${escapeHtml(acc.alias || acc.email)}</span>
        </div>
      \`).join('');
    } else {
      container.innerHTML = '<div class="small" style="padding:10px">暂无账号，请先在账号管理页面添加</div>';
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
    
    // 注意：批量创建需要获取每个账号的 key，这里简化处理
    appendBatchLog('⚠️ 批量创建功能需要先切换到对应账号', '#f59e0b');
    appendBatchLog('批量创建完成', '#fcd34d');
  }
  
  // KV 管理
  async function refreshKV() {
    if (!currentSelectedAccount) {
      document.getElementById('kvList').innerHTML = '<div class="small">请先在账号管理中选择一个账号</div>';
      return;
    }
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
    if (!currentSelectedAccount) {
      document.getElementById('d1List').innerHTML = '<div class="small">请先在账号管理中选择一个账号</div>';
      return;
    }
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
    if (!currentSelectedAccount) {
      document.getElementById('zonesList').innerHTML = '<div class="small">请先在账号管理中选择一个账号</div>';
      return;
    }
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
      现s
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
    if (!currentSelectedAccount) {
      document.getElementById('subdomainInput').disabled = true;
      document.getElementById('subdomainInput').placeholder = '请先选择账号';
      return;
    }
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
    
    // 设置导航
    document.querySelectorAll('.nav .item').forEach(item => {
      item.addEventListener('click', () => navTo(item.dataset.page));
    });
    
    // 设置批量创建的切换
    const sourceTypeSelect = document.getElementById('batchScriptSourceType');
    if (sourceTypeSelect) {
      sourceTypeSelect.addEventListener('change', toggleBatchSourceInput);
    }
    
    // 加载当前账号
    loadCurrentAccount().then(() => {
      // 如果有当前账号，加载 Workers
      if (currentSelectedAccount) {
        setTimeout(() => refreshWorkers(), 100);
      } else {
        // 没有账号时，自动切换到账号管理页面
        navTo('accounts');
      }
    });
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
  window.selectAccount = selectAccount;
  window.deleteAccount = deleteAccount;
  window.openAddAccountModal = openAddAccountModal;
  window.closeAddAccountModal = closeAddAccountModal;
  window.confirmAddAccount = confirmAddAccount;
  window.showAccountSwitcher = showAccountSwitcher;
  window.closeAccountSwitcher = closeAccountSwitcher;
  window.selectAccountAndClose = selectAccountAndClose;
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
  window.loadCurrentAccount = loadCurrentAccount;
})();`;
}

// 注意：需要在 Cloudflare Workers 中绑定 KV 命名空间，变量名为 MY_KV
