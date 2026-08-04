const CACHE = 'controle-v2';
const PRECACHE = [
  '/pre-registro.html',
  '/pre-registro-visitante.html',
  '/manifest.json'
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE).map(k => caches.delete(k))
    ))
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  // Nunca cacheiar requisicoes de API (podem conter dados sensiveis)
  if (e.request.url.includes('/api/')) {
    e.respondWith(
      fetch(e.request).catch(() => new Response(JSON.stringify({ erro: 'Sem conexão com o servidor' }), {
        status: 503, headers: { 'Content-Type': 'application/json' }
      }))
    );
    return;
  }
  // Cacheiar apenas assets estaticos (HTML, CSS, JS, imagens)
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request).then(res => {
      if (res.ok && (res.headers.get('content-type') || '').match(/text\/(html|css|javascript)|application\/javascript|image\//)) {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
      }
      return res;
    }).catch(() => caches.match(e.request))
  );
});
