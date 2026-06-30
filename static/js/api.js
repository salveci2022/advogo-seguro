/* ============================================================
   ADVOGO SEGURO — Camada de integração com a API Flask
   ============================================================ */

const API_BASE = ''; // mesma origem (Flask serve front e API)

const Auth = {
  TOKEN_KEY: 'advogo_seguro_token',
  TIPO_KEY: 'advogo_seguro_tipo',
  NOME_KEY: 'advogo_seguro_nome',
  PLANO_KEY: 'advogo_seguro_plano',

  setSession(token, tipo, nome, plano) {
    localStorage.setItem(this.TOKEN_KEY, token);
    localStorage.setItem(this.TIPO_KEY, tipo);
    localStorage.setItem(this.NOME_KEY, nome || '');
    if (plano) localStorage.setItem(this.PLANO_KEY, plano);
  },
  getToken() { return localStorage.getItem(this.TOKEN_KEY); },
  getTipo() { return localStorage.getItem(this.TIPO_KEY); },
  getNome() { return localStorage.getItem(this.NOME_KEY) || ''; },
  getPlano() { return localStorage.getItem(this.PLANO_KEY) || ''; },
  isLogged() { return !!this.getToken(); },
  logout() {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.TIPO_KEY);
    localStorage.removeItem(this.NOME_KEY);
    localStorage.removeItem(this.PLANO_KEY);
    window.location.href = '/';
  },
  /** Redireciona se não houver sessão do tipo esperado */
  requireTipo(tipoEsperado, redirectTo) {
    if (!this.isLogged() || this.getTipo() !== tipoEsperado) {
      window.location.href = redirectTo;
    }
  }
};

/**
 * Wrapper de fetch com tratamento de erro amigável e JWT automático.
 * @param {string} path - caminho da rota da API (ex: '/api/escritorio/advogados')
 * @param {object} options - { method, body, auth }
 */
async function apiRequest(path, options = {}) {
  const { method = 'GET', body = null, auth = true } = options;

  const headers = { 'Content-Type': 'application/json' };
  if (auth) {
    const token = Auth.getToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
  }

  let response;
  try {
    response = await fetch(API_BASE + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });
  } catch (networkErr) {
    throw new Error('Não foi possível conectar ao servidor. Verifique sua internet e tente novamente.');
  }

  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }

  if (response.status === 401) {
    // sessão expirada ou inválida
    if (auth) {
      Auth.logout();
    }
    throw new Error((data && data.erro) || 'Sessão expirada. Faça login novamente.');
  }

  if (!response.ok) {
    const msg = (data && data.erro) || 'Ocorreu um erro inesperado. Tente novamente.';
    const err = new Error(msg);
    err.payload = data;
    err.status = response.status;
    throw err;
  }

  return data;
}

/* ---------- Helpers de UI compartilhados ---------- */

function showAlert(elId, message, tipo = 'erro') {
  const el = document.getElementById(elId);
  if (!el) return;
  el.textContent = message;
  el.className = 'alert-box show alert-' + tipo;
}

function hideAlert(elId) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.className = 'alert-box';
}

function setLoading(buttonEl, isLoading, textoNormal, textoCarregando) {
  if (!buttonEl) return;
  buttonEl.disabled = isLoading;
  buttonEl.innerHTML = isLoading
    ? `<span class="spinner"></span> ${textoCarregando || 'Aguarde...'}`
    : textoNormal;
}

function toggleSidebar() {
  const sb = document.querySelector('.sidebar');
  if (sb) sb.classList.toggle('open');
}

function formatarTelefone(input) {
  return input.replace(/\D/g, '');
}

/** Marca o link ativo do menu lateral com base na página atual */
function marcarMenuAtivo() {
  const path = window.location.pathname;
  document.querySelectorAll('.sidebar nav a[data-path]').forEach(a => {
    if (a.getAttribute('data-path') === path) a.classList.add('active');
  });
}

document.addEventListener('DOMContentLoaded', marcarMenuAtivo);

/**
 * Lê um texto em voz alta (pt-BR), pensado para clientes idosos, analfabetos
 * ou com baixa leitura — não depende do usuário conseguir ler a tela.
 */
function falarTexto(texto) {
  try {
    if (!('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel(); // evita sobrepor falas anteriores
    const fala = new SpeechSynthesisUtterance(texto);
    fala.lang = 'pt-BR';
    fala.rate = 0.95;
    window.speechSynthesis.speak(fala);
  } catch (_) {
    // ambiente sem suporte a voz — falha silenciosamente, não quebra a tela
  }
}
