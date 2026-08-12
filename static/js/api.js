/* ============================================================
   ADVOGO SEGURO — Camada de integração com a API Flask
   ============================================================ */

const API_BASE = window.location.origin; // usa automaticamente o domínio local ou do Render

const Auth = {
  TOKEN_KEY: 'advogo_seguro_token', // legado: removido por segurança
  TIPO_KEY: 'advogo_seguro_tipo',
  NOME_KEY: 'advogo_seguro_nome',
  PLANO_KEY: 'advogo_seguro_plano',

  setSession(_tokenIgnorado, tipo, nome, plano) {
    // O JWT fica em cookie HttpOnly e não é acessível ao JavaScript.
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.setItem(this.TIPO_KEY, tipo);
    localStorage.setItem(this.NOME_KEY, nome || '');
    if (plano) localStorage.setItem(this.PLANO_KEY, plano);
  },
  getToken() { return null; },
  getTipo() { return localStorage.getItem(this.TIPO_KEY); },
  getNome() { return localStorage.getItem(this.NOME_KEY) || ''; },
  getPlano() { return localStorage.getItem(this.PLANO_KEY) || ''; },
  isLogged() { return !!this.getTipo(); },
  getCsrfToken() {
    const prefixo = 'advogo_seguro_csrf=';
    const item = document.cookie.split('; ').find(v => v.startsWith(prefixo));
    return item ? decodeURIComponent(item.substring(prefixo.length)) : '';
  },
  clearLocal() {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.TIPO_KEY);
    localStorage.removeItem(this.NOME_KEY);
    localStorage.removeItem(this.PLANO_KEY);
  },
  logout() {
    const csrf = this.getCsrfToken();
    fetch('/api/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: csrf ? { 'X-CSRF-Token': csrf } : {}
    }).catch(() => {}).finally(() => {
      this.clearLocal();
      window.location.href = '/';
    });
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
  if (auth && !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())) {
    const csrf = Auth.getCsrfToken();
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }

  const url = new URL(path, API_BASE).toString();

  async function executarFetch() {
    return fetch(url, {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      body: body ? JSON.stringify(body) : undefined
    });
  }

  let response;
  try {
    response = await executarFetch();
  } catch (primeiroErro) {
    // Uma segunda tentativa curta ajuda quando o serviço do Render está
    // iniciando ou sofreu uma interrupção momentânea.
    await new Promise(resolve => setTimeout(resolve, 1500));

    try {
      response = await executarFetch();
    } catch (segundoErro) {
      console.error('Falha de conexão com a API:', {
        url,
        primeiroErro,
        segundoErro
      });

      throw new Error(
        'O servidor está temporariamente indisponível. ' +
        'Aguarde alguns segundos, atualize a página e tente novamente.'
      );
    }
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
      const tipoAtual = Auth.getTipo();
      Auth.clearLocal();
      window.location.href = tipoAtual === 'cliente' ? '/cliente/login' : '/escritorio/login';
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
  el.setAttribute('role', tipo === 'erro' ? 'alert' : 'status');
  el.setAttribute('aria-live', tipo === 'erro' ? 'assertive' : 'polite');
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

function garantirBackdropSidebar() {
  let backdrop = document.getElementById('sidebarBackdrop');
  if (!backdrop) {
    backdrop = document.createElement('div');
    backdrop.id = 'sidebarBackdrop';
    backdrop.className = 'sidebar-backdrop';
    backdrop.addEventListener('click', fecharSidebar);
    document.body.appendChild(backdrop);
  }
  return backdrop;
}
function atualizarA11ySidebar(aberto) {
  const btn = document.querySelector('.mobile-topbar button');
  if (!btn) return;
  btn.setAttribute('type', 'button');
  btn.setAttribute('aria-controls', 'sidebarEl');
  btn.setAttribute('aria-expanded', aberto ? 'true' : 'false');
  btn.setAttribute('aria-label', aberto ? 'Fechar menu' : 'Abrir menu');
}
function abrirSidebar() {
  const sb = document.querySelector('.sidebar');
  if (!sb) return;
  sb.classList.add('open');
  garantirBackdropSidebar().classList.add('show');
  document.body.classList.add('sidebar-open');
  atualizarA11ySidebar(true);
}
function fecharSidebar() {
  const sb = document.querySelector('.sidebar');
  if (!sb) return;
  sb.classList.remove('open');
  const backdrop = document.getElementById('sidebarBackdrop');
  if (backdrop) backdrop.classList.remove('show');
  document.body.classList.remove('sidebar-open');
  atualizarA11ySidebar(false);
}
function toggleSidebar() {
  const sb = document.querySelector('.sidebar');
  if (!sb) return;
  sb.classList.contains('open') ? fecharSidebar() : abrirSidebar();
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

document.addEventListener('DOMContentLoaded', () => {
  marcarMenuAtivo();
  atualizarA11ySidebar(false);
  document.querySelectorAll('.sidebar nav a').forEach(link => {
    link.addEventListener('click', () => {
      if (window.innerWidth <= 860) fecharSidebar();
    });
  });
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') fecharSidebar();
});
window.addEventListener('resize', () => {
  if (window.innerWidth > 860) fecharSidebar();
});

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
