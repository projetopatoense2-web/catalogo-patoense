/**
 * security.js — Utilitários de segurança frontend
 * Distribuidora Patoense 2026
 *
 * Responsabilidades:
 *  - Hash de senhas (Web Crypto API)
 *  - Rate limiting de tentativas de login
 *  - Sanitização e validação de inputs
 *  - Helpers de log seguro (sem dados sensíveis)
 */

'use strict';

// ══════════════════════════════════════════════════════════════════
//  HASH DE SENHA — SHA-256 via Web Crypto API
//  Não usa btoa() que é apenas base64 (reversível, não é hash)
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

  // Hash atual (SHA-256)
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
//  RATE LIMITING — limita tentativas de login
//  Armazenado apenas em memória (não persiste entre reloads)
// ══════════════════════════════════════════════════════════════════

const _attempts = new Map();

/**
 * Checa se a chave está bloqueada por excesso de tentativas.
 * @param {string} key  — ex: 'login:84999...' ou 'adm:admin@...'
 * @returns {{ blocked: boolean, secs?: number }}
 */
export function checkRateLimit(key) {
  const now = Date.now();
  if (!_attempts.has(key)) {
    _attempts.set(key, { count: 0, firstAt: now, blockedUntil: 0 });
  }
  const entry = _attempts.get(key);

  if (now < entry.blockedUntil) {
    return { blocked: true, secs: Math.ceil((entry.blockedUntil - now) / 1000) };
  }

  // Reset janela de 5 minutos
  if (now - entry.firstAt > 5 * 60 * 1000) {
    entry.count   = 0;
    entry.firstAt = now;
  }

  entry.count++;
  if (entry.count >= 6) {
    entry.blockedUntil = now + 5 * 60 * 1000;
    entry.count        = 0;
    return { blocked: true, secs: 300 };
  }

  return { blocked: false };
}

/**
 * Remove registro de tentativas após login bem-sucedido.
 * @param {string} key
 */
export function resetRateLimit(key) {
  _attempts.delete(key);
}

// ══════════════════════════════════════════════════════════════════
//  SANITIZAÇÃO & VALIDAÇÃO DE INPUTS
// ══════════════════════════════════════════════════════════════════

/**
 * Remove tags HTML/JS de uma string.
 * Previne XSS básico ao exibir dados no DOM.
 * @param {string} str
 * @returns {string}
 */
export function sanitizeText(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
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
//  LOG SEGURO — nunca loga dados sensíveis em produção
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
 * Erro sempre logado, mas nunca expõe stack trace em produção.
 * @param {string} context
 * @param {Error|string} err
 */
export function safeError(context, err) {
  if (IS_DEV) {
    console.error('[ERR]', context, err);
  } else {
    // Em produção: loga apenas o contexto, não o stack trace
    console.error('[ERR]', context);
  }
}
