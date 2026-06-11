// --- HELPER FUNCTIONS ---
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 
      'Content-Type': 'application/json', 
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

// 1. Simple Rate Limiter (In-memory, resets on worker restart)
const rateLimitMap = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 60000; // 1 minute window
  const maxRequests = 5;  // Max 5 requests per minute
  
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const timestamps = rateLimitMap.get(ip).filter(t => now - t < windowMs);
  
  if (timestamps.length >= maxRequests) return false; // Limit exceeded
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  return true;
}

// 2. JWT Middleware (Simplified for demo: checks format & expiry)
async function verifyJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false, error: 'Invalid token format' };
    // Decode payload (Base64 URL to JSON)
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return { valid: false, error: 'Token expired' };
    }
    return { valid: true, payload };
  } catch (e) {
    return { valid: false, error: 'Malformed token' };
  }
}

// --- MAIN API ROUTER ---
export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' } });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    
    // 7. Basic Request Logging
    console.log(`[${new Date().toISOString()}] ${method} ${path} from IP: ${ip}`);

    // 7. Health Check (No Auth Required)
    if (path === '/health') {
      return jsonResponse({ status: 'OK', message: 'API Gateway is running', timestamp: Date.now() });
    }

    // 1. JWT Authentication Middleware
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return jsonResponse({ error: 'Unauthorized: Missing Bearer token' }, 401);
    }
    const token = authHeader.split(' ')[1];
    const auth = await verifyJWT(token);
    if (!auth.valid) {
      return jsonResponse({ error: `Unauthorized: ${auth.error}` }, 401);
    }

    // 4. Rate Limiting
    if (!checkRateLimit(ip)) {
      return jsonResponse({ error: 'Too Many Requests: Rate limit exceeded (5 req/min)' }, 429);
    }

    // 5. Edge Caching for GET requests
    if (method === 'GET' && path.startsWith('/api/employees')) {
      const cache = caches.default;
      let cachedResponse = await cache.match(request);
      
      if (cachedResponse) {
        console.log('[CACHE HIT]', path);
        const newHeaders = new Headers(cachedResponse.headers);
        newHeaders.set('X-Cache', 'HIT'); // Proof of cache hit!
        return new Response(cachedResponse.body, { status: cachedResponse.status, headers: newHeaders });
      }
    }

    // 2 & 3. Handle CRUD (D1) and Files (R2)
    let response = await handleRoutes(request, env, path, method, ctx);
    
    // If it was a successful GET, save it to the Edge Cache
    if (method === 'GET' && path.startsWith('/api/employees') && response.status === 200) {
        const newHeaders = new Headers(response.headers);
        newHeaders.set('X-Cache', 'MISS');
        newHeaders.set('Cache-Control', 'max-age=60'); // Cache for 60 seconds
        const responseToCache = new Response(response.body, { status: response.status, headers: newHeaders });
        
        ctx.waitUntil(caches.default.put(request, responseToCache.clone()));
        return responseToCache;
    }

    return response;
  }
};

// --- ROUTE HANDLER ---
async function handleRoutes(request, env, path, method, ctx) {
  const parts = path.split('/').filter(Boolean);
  
  // 2. CRUD for Employees (D1 Database)
  if (parts[1] === 'employees') {
    if (method === 'GET' && parts.length === 2) {
      const { results } = await env.DB.prepare("SELECT * FROM employees").all();
      return jsonResponse(results, 200);
    }
    if (method === 'POST' && parts.length === 2) {
      const data = await request.json();
      if (!data.name || !data.role) return jsonResponse({ error: 'Missing required fields: name, role' }, 400);
      await env.DB.prepare("INSERT INTO employees (name, role, email) VALUES (?, ?, ?)")
        .bind(data.name, data.role, data.email || null).run();
      return jsonResponse({ success: true, message: 'Employee added successfully' }, 201);
    }
    if (parts.length === 3) {
      const id = parts[2];
      if (method === 'PUT') {
        const data = await request.json();
        await env.DB.prepare("UPDATE employees SET name=?, role=?, email=? WHERE id=?")
          .bind(data.name, data.role, data.email, id).run();
        return jsonResponse({ success: true, message: 'Employee updated' }, 200);
      }
      if (method === 'DELETE') {
        await env.DB.prepare("DELETE FROM employees WHERE id=?").bind(id).run();
        return jsonResponse({ success: true, message: 'Employee deleted' }, 200);
      }
    }
  }

  // 3. File Attachments (R2 Storage)
  if (parts[1] === 'attachments' && parts.length === 3) {
    const fileId = parts[2];
    if (method === 'POST') {
      const body = await request.arrayBuffer();
      await env.R2.put(`files/${fileId}`, body);
      return jsonResponse({ success: true, fileId, message: 'File uploaded to R2 successfully' }, 201);
    }
    if (method === 'GET') {
      const obj = await env.R2.get(`files/${fileId}`);
      if (!obj) return jsonResponse({ error: 'File not found in R2 storage' }, 404);
      return new Response(obj.body, { headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${fileId}"` } });
    }
  }

  // 6. Proper 404 for unknown routes
  return jsonResponse({ error: 'Endpoint Not Found. Check your URL and method.' }, 404);
}
