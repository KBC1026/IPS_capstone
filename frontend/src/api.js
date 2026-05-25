const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://api.chanxai.com';

function queryString(params = {}) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, String(value));
    }
  });
  const value = search.toString();
  return value ? `?${value}` : '';
}

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
  events: (limit = 50, options = {}) => request(`/api/security/events${queryString({ limit, lab_only: options.labOnly })}`),
  summary: (options = {}) => request(`/api/security/summary${queryString({ lab_only: options.labOnly })}`),
  timeline: (options = {}) => request(`/api/security/timeline${queryString({ lab_only: options.labOnly })}`),
  runSimulation: (scenario) => request(`/api/simulation/${scenario}`, { method: 'POST' }),
  chat: (message) => request('/api/ai/chat', { method: 'POST', body: JSON.stringify({ message }) })
};
