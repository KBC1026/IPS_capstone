const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://api.chanxai.com';

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.reply || payload.message || `API request failed: ${response.status}`);
  }
  return payload;
}

export const api = {
  baseUrl: API_BASE_URL,
  health: () => request('/api/health'),
  events: (limit = 50) => request(`/api/security/events?limit=${limit}`),
  summary: () => request('/api/security/summary'),
  timeline: () => request('/api/security/timeline'),
  runSimulation: (scenario) => request(`/api/simulation/${scenario}`, { method: 'POST' }),
  chat: (message) => request('/api/ai/chat', { method: 'POST', body: JSON.stringify({ message }) })
};
