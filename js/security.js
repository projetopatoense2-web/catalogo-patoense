/**
 * security.js — Utilitários de segurança frontend
 * Distribuidora Patoense 2026
 *
 * CHANGELOG DE SEGURANÇA:
 *  [SEC-01] Rate limiting progressivo com backoff exponencial
 *  [SEC-02] safeError() aprimorado: mascara stacks e códigos Firebase
 *  [SEC-03] sanitizeText() mantido; adicionado sanitizeForLog()
 *  [SEC-04] Validações sem alteração de assinatura (compatibilidade total)
 */

'use strict';

// ══════════════════════════════════════════════════════════════════
//  HASH DE SENHA — SHA-256 via Web Crypto API
// ══════════════════════════════════════════════════════════════════

/**
 * Gera hash SHA-256 da senha com salt composto de tel + versão.
 * @param {string} senha
 * @param {string} tel  — telefone do usuário (apenas dígitos)
 * @returns {Promise<string>} hex string de 64 caracteres
 */
export async function hashSenha(senha, tel) {
  if (!senha || typeof senha !== 'string') return '';
  const telDigits = (tel || '').replace(/\D/g, '');
  const salt      = 'patoense2026:' + telDigits + ':v2';
  const data      = new TextEncoder().encode(salt + senha);
  const hashBuf   = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verifica senha contra hash armazenado.
 * Suporta migração: hash SHA-256 novo e btoa legado.
 * @param {string} senha
 * @param {string} tel
 * @param {string} storedHash
 * @returns {Promise<boolean>}
 */
export async function verificarSenha(senha, tel, storedHash) {
  if (!storedHash) return false;
  const telDigits = (tel || '').replace(/\D/g, '');

  const hashNovo = await hashSenha(senha, telDigits);
  if (hashNovo === storedHash) return true;

  // Compatibilidade retroativa com hash btoa antigo
  try {
    const hashAntigo = btoa('pat2026:' + senha + ':' + telDigits);
    if (hashAntigo === storedHash) return true;
  } catch (_) {}

  return false;
}

// ══════════════════════════════════════════════════════════════════
//  RATE LIMITING PROGRESSIVO — [SEC-01]
//
//  MUDANÇAS em relação à versão anterior:
//   - Backoff exponencial: bloqueio dobra a cada violação (30s→60s→120s→…)
//   - Máximo de bloqueio: 30 minutos por chave
//   - Janela deslizante independente por contexto (login/admin/reset)
//   - reset seguro: zera apenas tentativas bem-sucedidas, não o histórico
//   - Proteção contra brute force distribuído: limite global por hora
//
//  MITIGAÇÃO: impede adivinhação de senha mesmo com IPs rotacionados
//  (ataque na mesma sessão do browser).
// ══════════════════════════════════════════════════════════════════

const _attempts    = new Map();
const _globalCount = { count: 0, windowStart: Date.now() };

/** Limite de tentativas antes do 1º bloqueio */
const RATE_MAX_ATTEMPTS  = 5;
/** Duração inicial de bloqueio em ms (30 s) */
const RATE_BASE_BLOCK_MS = 30_000;
/** Bloqueio máximo em ms (30 min) */
const RATE_MAX_BLOCK_MS  = 30 * 60_000;
/** Janela de observação em ms (10 min) */
const RATE_WINDOW_MS     = 10 * 60_000;
/** Limite global de falhas por hora na sessão */
const RATE_GLOBAL_LIMIT  = 30;

/**
 * Checa se a chave está bloqueada por excesso de tentativas.
 * Implementa backoff exponencial progressivo.
 *
 * @param {string} key  — ex: 'login:84999...' ou 'adm:admin@...'
 * @returns {{ blocked: boolean, secs?: number }}
 */
export function checkRateLimit(key) {
  const now = Date.now();

  // ── Proteção global (brute force distribuído na mesma sessão) ──
  if (now - _globalCount.windowStart > 60 * 60_000) {
    _globalCount.count       = 0;
    _globalCount.windowStart = now;
  }
  if (_globalCount.count >= RATE_GLOBAL_LIMIT) {
    return { blocked: true, secs: Math.ceil((60 * 60_000 - (now - _globalCount.windowStart)) / 1000) };
  }

  // ── Limite por chave ──
  if (!_attempts.has(key)) {
    _attempts.set(key, { count: 0, windowStart: now, blockedUntil: 0, violations: 0 });
  }
  const entry = _attempts.get(key);

  // Ainda dentro do período de bloqueio?
  if (now < entry.blockedUntil) {
    return { blocked: true, secs: Math.ceil((entry.blockedUntil - now) / 1000) };
  }

  // Reset da janela deslizante
  if (now - entry.windowStart > RATE_WINDOW_MS) {
    entry.count       = 0;
    entry.windowStart = now;
    // NÃO reseta violations — histórico de bloqueios persiste
  }

  entry.count++;
  _globalCount.count++;

  if (entry.count >= RATE_MAX_ATTEMPTS) {
    entry.violations++;
    // Backoff exponencial: 30s × 2^(violations-1), máximo 30 min
    const blockMs      = Math.min(RATE_BASE_BLOCK_MS * Math.pow(2, entry.violations - 1), RATE_MAX_BLOCK_MS);
    entry.blockedUntil = now + blockMs;
    entry.count        = 0;
    devLog(`rateLimit: bloqueio #${entry.violations} por ${blockMs / 1000}s → ${key}`);
    return { blocked: true, secs: Math.ceil(blockMs / 1000) };
  }

  return { blocked: false };
}

/**
 * Remove apenas o contador de tentativas após login bem-sucedido.
 * Mantém o histórico de violations para evitar reset malicioso.
 * @param {string} key
 */
export function resetRateLimit(key) {
  const entry = _attempts.get(key);
  if (entry) {
    entry.count        = 0;
    entry.windowStart  = Date.now();
    entry.blockedUntil = 0;
    // violations é mantido intencionalmente
  }
}

// ══════════════════════════════════════════════════════════════════
//  SANITIZAÇÃO & VALIDAÇÃO DE INPUTS
// ══════════════════════════════════════════════════════════════════

/**
 * Remove tags HTML/JS de uma string. Previne XSS ao exibir no DOM.
 * @param {string} str
 * @returns {string}
 */
export function sanitizeText(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * [SEC-03] Sanitiza string para logs: remove dados sensíveis.
 * Impede que tokens/senhas apareçam acidentalmente nos logs.
 * @param {string} str
 * @returns {string}
 */
export function sanitizeForLog(str) {
  if (typeof str !== 'string') return '[non-string]';
  return str
    .replace(/("senha"|"password"|"token"|"secret"|"apiKey")\s*:\s*"[^"]*"/gi, '$1:"[REDACTED]"')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED]')
    .slice(0, 200); // trunca para evitar logs excessivos
}

/**
 * Valida e normaliza telefone (somente dígitos, 10-11 chars).
 * @param {string} tel
 * @returns {{ ok: boolean, digits: string, msg?: string }}
 */
export function validarTel(tel) {
  const digits = (tel || '').replace(/\D/g, '');
  if (digits.length < 10) return { ok: false, digits, msg: 'Telefone muito curto (mínimo 10 dígitos).' };
  if (digits.length > 11) return { ok: false, digits, msg: 'Telefone muito longo (máximo 11 dígitos).' };
  return { ok: true, digits };
}

/**
 * Valida e-mail básico.
 * @param {string} email
 * @returns {boolean}
 */
export function validarEmail(email) {
  if (typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) && email.length <= 200;
}

/**
 * Valida nome (2–120 caracteres, sem HTML).
 * @param {string} nome
 * @returns {{ ok: boolean, msg?: string }}
 */
export function validarNome(nome) {
  const v = (nome || '').trim();
  if (v.length < 2)   return { ok: false, msg: 'Nome muito curto (mínimo 2 caracteres).' };
  if (v.length > 120) return { ok: false, msg: 'Nome muito longo (máximo 120 caracteres).' };
  if (/<|>|script/i.test(v)) return { ok: false, msg: 'Nome contém caracteres inválidos.' };
  return { ok: true };
}

/**
 * Valida senha (mínimo 6 caracteres).
 * @param {string} senha
 * @returns {{ ok: boolean, msg?: string }}
 */
export function validarSenha(senha) {
  if (!senha || senha.length < 6)  return { ok: false, msg: 'Senha muito curta (mínimo 6 caracteres).' };
  if (senha.length > 128)          return { ok: false, msg: 'Senha muito longa.' };
  return { ok: true };
}

/**
 * Valida lista de itens do pedido.
 * @param {Array} itens
 * @returns {{ ok: boolean, msg?: string }}
 */
export function validarItensPedido(itens) {
  if (!Array.isArray(itens) || itens.length === 0) return { ok: false, msg: 'Pedido sem itens.' };
  if (itens.length > 200) return { ok: false, msg: 'Muitos itens no pedido (máximo 200).' };
  for (const item of itens) {
    if (typeof item.code !== 'number') return { ok: false, msg: 'Código de produto inválido.' };
    if (typeof item.qty  !== 'number' || item.qty < 1 || item.qty > 9999)
      return { ok: false, msg: 'Quantidade inválida.' };
    if (typeof item.name !== 'string' || item.name.length > 200)
      return { ok: false, msg: 'Nome de produto inválido.' };
  }
  return { ok: true };
}

// ══════════════════════════════════════════════════════════════════
//  LOG SEGURO — [SEC-02]
//
//  MUDANÇAS:
//   - safeError() mascara TODOS os detalhes Firebase em produção
//   - Usa código interno estruturado (contexto + timestamp hash)
//   - sanitizeForLog() remove tokens/senhas de mensagens acidentais
//   - devLog/devWarn inalterados (apenas desenvolvimento)
//
//  MITIGAÇÃO: impede vazamento de stack traces, project IDs,
//  Firebase error codes e mensagens internas para o console
//  em produção (onde atacantes podem inspecioná-los).
// ══════════════════════════════════════════════════════════════════

const IS_DEV = location.hostname === 'localhost' || location.hostname === '127.0.0.1';

/**
 * Console.log somente em desenvolvimento.
 * @param {...any} args
 */
export function devLog(...args) {
  if (IS_DEV) console.log('[DEV]', ...args);
}

/**
 * Console.warn somente em desenvolvimento.
 * @param {...any} args
 */
export function devWarn(...args) {
  if (IS_DEV) console.warn('[DEV WARN]', ...args);
}

/**
 * Gera código de erro interno ofuscado (não sequencial, não previsível).
 * Formato: ERR-XXXX onde XXXX é hash do contexto + minuto atual.
 * @param {string} context
 * @returns {string}
 */
async function _errorCode(context) {
  try {
    const data = new TextEncoder().encode(context + ':' + Math.floor(Date.now() / 60_000));
    const buf  = await crypto.subtle.digest('SHA-256', data);
    const hex  = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    return 'ERR-' + hex.slice(0, 6).toUpperCase();
  } catch (_) {
    return 'ERR-000000';
  }
}

/**
 * Loga erros com controle rigoroso de exposição.
 *
 * Em DEV  : loga contexto + erro completo (stack, código Firebase)
 * Em PROD : loga apenas código interno, SEM stack, SEM firebase code,
 *           SEM mensagens que possam revelar estrutura do Firestore
 *
 * @param {string}      context — identificador do ponto de erro
 * @param {Error|string} err
 */
export async function safeError(context, err) {
  if (IS_DEV) {
    console.error('[ERR]', context, err);
    return;
  }

  // Produção: código interno + contexto sanitizado, nada mais
  const code = await _errorCode(context);
  // Loga só o código — não loga context diretamente (pode conter IDs)
  console.error('[ERR]', code);

  // Suprime completamente: stack traces, firebase codes, mensagens internas
  // Se precisar de rastreabilidade, integre um serviço como Sentry aqui:
  // Sentry.captureException(err, { tags: { context, code } });
}
