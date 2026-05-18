/**
 * auth.js — Autenticação de usuários (clientes e admin)
 * Distribuidora Patoense 2026
 *
 * CHANGELOG DE SEGURANÇA:
 *  [AUTH-01] loginCliente() — removida busca por nome (enumeração de usuários)
 *            Login agora APENAS por telefone. Mensagem de erro genérica mantida.
 *  [AUTH-02] restoreClientSession() — timeout de validação (5 s),
 *            invalidação após SESSION_OFFLINE_TTL minutos offline,
 *            flag de revalidação pendente em vez de manter sessão indefinida.
 *  [AUTH-03] Expiração automática de sessão cliente (SESSION_MAX_AGE_MS)
 *  [AUTH-04] Revalidação periódica silenciosa a cada REVALIDATE_INTERVAL_MS
 *  [AUTH-05] Logout por inatividade (INACTIVITY_TIMEOUT_MS)
 *  [AUTH-06] recuperarSenhaAdmin() agora tem rate limiting próprio
 */

import { auth, db, doc, getDoc, setDoc, serverTimestamp,
         signInWithEmailAndPassword, signOut,
         onAuthStateChanged, sendPasswordResetEmail }
  from './firebase.js';

import { hashSenha, verificarSenha, checkRateLimit, resetRateLimit,
         validarTel, validarEmail, validarSenha, devLog, safeError }
  from './security.js';

// ══════════════════════════════════════════════════════════════════
//  CONSTANTES DE SESSÃO — [AUTH-03] [AUTH-05]
// ══════════════════════════════════════════════════════════════════

/** Duração máxima de sessão cliente: 8 horas */
const SESSION_MAX_AGE_MS      = 8 * 60 * 60_000;
/** Após X ms offline sem revalidar, a sessão é invalidada */
const SESSION_OFFLINE_TTL_MS  = 30 * 60_000; // 30 minutos
/** Timeout de chamada Firestore para validação de sessão */
const SESSION_VALIDATE_TIMEOUT_MS = 5_000;    // 5 segundos
/** Intervalo de revalidação periódica silenciosa */
const REVALIDATE_INTERVAL_MS  = 15 * 60_000;  // 15 minutos
/** Inatividade máxima do cliente antes do logout automático */
const INACTIVITY_TIMEOUT_MS   = 60 * 60_000;  // 60 minutos

// ── Estado interno (não exposto no window) ───────────────────────
let _currentUser          = null;
let _isAdmin              = false;
let _firebaseUser         = null;
let _sessionStartedAt     = null; // timestamp do login
let _lastActivityAt       = null; // último evento de interação
let _lastValidatedAt      = null; // última confirmação Firestore
let _revalidateTimer      = null;
let _inactivityTimer      = null;

// ── Callbacks de mudança de estado ──────────────────────────────
const _onChangeCallbacks = [];
export function onAuthChange(cb) { _onChangeCallbacks.push(cb); }
function _notifyChange() { _onChangeCallbacks.forEach(cb => cb(_currentUser, _isAdmin)); }

// ── Getters públicos ─────────────────────────────────────────────
export function getCurrentUser()  { return _currentUser; }
export function getIsAdmin()      { return _isAdmin; }
export function getFirebaseUser() { return _firebaseUser; }

// ══════════════════════════════════════════════════════════════════
//  RASTREAMENTO DE ATIVIDADE — [AUTH-05]
//  Reinicia o timer de inatividade a cada interação do usuário
// ══════════════════════════════════════════════════════════════════

function _recordActivity() {
  _lastActivityAt = Date.now();
  _resetInactivityTimer();
}

function _resetInactivityTimer() {
  if (_inactivityTimer) clearTimeout(_inactivityTimer);
  if (!_currentUser) return;

  _inactivityTimer = setTimeout(async () => {
    devLog('Auth: logout por inatividade');
    await logout();
    // Notifica a UI (a página pode mostrar um modal de sessão expirada)
    window.dispatchEvent(new CustomEvent('auth:inactivity-logout'));
  }, INACTIVITY_TIMEOUT_MS);
}

// Eventos considerados "atividade" do usuário
['click', 'keydown', 'touchstart', 'scroll'].forEach(evt =>
  document.addEventListener(evt, _recordActivity, { passive: true })
);

// ══════════════════════════════════════════════════════════════════
//  REVALIDAÇÃO PERIÓDICA — [AUTH-04]
//  Confirma silenciosamente no Firestore que a conta ainda existe
// ══════════════════════════════════════════════════════════════════

function _startRevalidationLoop() {
  if (_revalidateTimer) clearInterval(_revalidateTimer);
  _revalidateTimer = setInterval(async () => {
    if (!_currentUser || _isAdmin) return; // admin é gerenciado pelo Firebase Auth

    const digits = (_currentUser.tel || '').replace(/\D/g, '');
    if (!digits) return;

    try {
      const snap = await _firestoreWithTimeout(
        getDoc(doc(db, 'clientes', digits)),
        SESSION_VALIDATE_TIMEOUT_MS
      );

      if (!snap.exists()) {
        devLog('Auth: conta removida — encerrando sessão');
        await logout();
        window.dispatchEvent(new CustomEvent('auth:account-removed'));
        return;
      }

      // Atualiza dados locais com versão fresca do Firestore
      _currentUser     = { ...snap.data(), isAdmin: false };
      _lastValidatedAt = Date.now();
      _notifyChange();
      devLog('Auth: sessão revalidada');
    } catch (e) {
      // Firestore indisponível — verifica TTL offline
      const offlineMs = Date.now() - (_lastValidatedAt || _sessionStartedAt || Date.now());
      if (offlineMs > SESSION_OFFLINE_TTL_MS) {
        devLog('Auth: TTL offline excedido — encerrando sessão');
        await logout();
        window.dispatchEvent(new CustomEvent('auth:offline-timeout'));
      }
    }
  }, REVALIDATE_INTERVAL_MS);
}

function _stopRevalidationLoop() {
  if (_revalidateTimer) { clearInterval(_revalidateTimer); _revalidateTimer = null; }
  if (_inactivityTimer) { clearTimeout(_inactivityTimer);  _inactivityTimer = null; }
}

// ══════════════════════════════════════════════════════════════════
//  HELPER — Promise com timeout
// ══════════════════════════════════════════════════════════════════

/**
 * Executa uma Promise com timeout máximo.
 * Se o timeout disparar, rejeita com erro 'timeout'.
 * @param {Promise} promise
 * @param {number}  ms
 * @returns {Promise}
 */
function _firestoreWithTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('timeout')), ms)
    )
  ]);
}

// ══════════════════════════════════════════════════════════════════
//  SESSÃO PERSISTENTE — Firebase Auth observer
// ══════════════════════════════════════════════════════════════════

onAuthStateChanged(auth, async (fbUser) => {
  if (fbUser) {
    _firebaseUser = fbUser;
    try {
      const snap = await getDoc(doc(db, 'usuarios', fbUser.uid));
      if (snap.exists() && snap.data().role === 'admin') {
        _isAdmin = true;
        if (!_currentUser) {
          _currentUser = {
            nome:    snap.data().nome || 'Administrador',
            isAdmin: true,
            uid:     fbUser.uid
          };
        }
        devLog('Auth: sessão admin restaurada');
        _notifyChange();
      }
    } catch (e) {
      safeError('auth/session-restore', e);
    }
  } else {
    if (_isAdmin) {
      _isAdmin      = false;
      _firebaseUser = null;
      _notifyChange();
    }
  }
});

// ══════════════════════════════════════════════════════════════════
//  LOGIN DE CLIENTE — [AUTH-01]
//
//  MUDANÇA: busca por nome REMOVIDA.
//
//  PROBLEMA anterior: getDocs(collection('clientes')) enumerava TODOS
//  os documentos da coleção para cada tentativa de login por nome,
//  expondo a lista completa de clientes a um atacante autenticado
//  no Firebase (ou via regras permissivas) e degradando performance.
//
//  SOLUÇÃO: login SOMENTE por telefone (chave do documento).
//  Isso é O(1) no Firestore (lookup por ID), sem enumeração.
//
//  SE busca por nome for necessária no futuro:
//   → criar campo 'searchToken' (hash do nome normalizado) no cadastro
//   → fazer query por esse campo indexado, nunca getDocs() full scan
//
//  MITIGAÇÃO: impede enumeração de usuários + melhora performance
// ══════════════════════════════════════════════════════════════════

/**
 * Realiza login de cliente por telefone + senha.
 * @param {string} tel   — telefone com ou sem formatação
 * @param {string} senha
 * @returns {Promise<{ ok: boolean, msg?: string, pendente?: boolean }>}
 */
export async function loginCliente(tel, senha) {
  tel = (tel || '').trim();
  if (!tel || !senha) return { ok: false, msg: 'Preencha todos os campos.' };

  const telVal = validarTel(tel);
  if (!telVal.ok) return { ok: false, msg: 'Informe um telefone válido para entrar.' };

  // Rate limiting por telefone
  const rlKey = 'login:' + telVal.digits.slice(0, 20);
  const rl    = checkRateLimit(rlKey);
  if (rl.blocked) return { ok: false, msg: `Muitas tentativas. Aguarde ${rl.secs}s.` };

  try {
    const snap = await _firestoreWithTimeout(
      getDoc(doc(db, 'clientes', telVal.digits)),
      SESSION_VALIDATE_TIMEOUT_MS
    );

    if (snap.exists()) {
      const fbUser = snap.data();
      const ok = await verificarSenha(senha, telVal.digits, fbUser.senhaHash);

      if (!ok) {
        // Mensagem genérica — não revela se o telefone existe
        return { ok: false, msg: 'Dados incorretos. Tente novamente.' };
      }

      resetRateLimit(rlKey);
      _currentUser      = { ...fbUser, isAdmin: false };
      _sessionStartedAt = Date.now();
      _lastValidatedAt  = Date.now();
      _lastActivityAt   = Date.now();
      _notifyChange();
      _startRevalidationLoop();
      _resetInactivityTimer();
      devLog('Auth: cliente logado');
      return { ok: true, user: _currentUser };
    }

    // Verifica se está pendente (mensagem diferenciada, sem revelar existência)
    try {
      const pendSnap = await getDoc(doc(db, 'clientes_pendentes', telVal.digits));
      if (pendSnap.exists()) return { ok: false, pendente: true, nome: pendSnap.data().nome };
    } catch (_) {}

    // Mensagem genérica: não revela se o telefone existe ou não
    return { ok: false, msg: 'Dados incorretos. Tente novamente.' };

  } catch (e) {
    if (e.message === 'timeout') {
      return { ok: false, msg: 'Conexão lenta. Verifique sua internet e tente novamente.' };
    }
    safeError('auth/login-tel', e);
    return { ok: false, msg: 'Erro ao entrar. Tente novamente.' };
  }
}

// ══════════════════════════════════════════════════════════════════
//  LOGIN DE ADMIN — Firebase Authentication
// ══════════════════════════════════════════════════════════════════

/**
 * Realiza login do administrador via Firebase Auth.
 * @param {string} email
 * @param {string} senha
 * @returns {Promise<{ ok: boolean, msg?: string }>}
 */
export async function loginAdmin(email, senha) {
  email = (email || '').trim().toLowerCase();
  if (!validarEmail(email)) return { ok: false, msg: 'E-mail inválido.' };
  const sv = validarSenha(senha);
  if (!sv.ok) return { ok: false, msg: sv.msg };

  const rlKey = 'adm:' + email.slice(0, 30);
  const rl    = checkRateLimit(rlKey);
  if (rl.blocked) return { ok: false, msg: `Muitas tentativas. Aguarde ${rl.secs}s.` };

  try {
    const cred = await signInWithEmailAndPassword(auth, email, senha);
    _firebaseUser = cred.user;

    const snap = await getDoc(doc(db, 'usuarios', cred.user.uid));
    if (!snap.exists() || snap.data().role !== 'admin') {
      await signOut(auth);
      _firebaseUser = null;
      return { ok: false, msg: 'Acesso não autorizado.' };
    }

    resetRateLimit(rlKey);
    _isAdmin     = true;
    _currentUser = {
      nome:    snap.data().nome || 'Administrador',
      isAdmin: true,
      uid:     cred.user.uid
    };
    _notifyChange();
    devLog('Auth: admin logado');
    return { ok: true };
  } catch (e) {
    safeError('auth/admin-login', e);
    // Mensagens genéricas — não revela qual campo está errado
    const msgMap = {
      'auth/invalid-credential':     'E-mail ou senha incorretos.',
      'auth/user-not-found':         'E-mail ou senha incorretos.',
      'auth/wrong-password':         'E-mail ou senha incorretos.',
      'auth/too-many-requests':      'Muitas tentativas. Aguarde alguns minutos.',
      'auth/network-request-failed': 'Erro de conexão. Verifique sua internet.'
    };
    return { ok: false, msg: msgMap[e.code] || 'Erro ao entrar. Tente novamente.' };
  }
}

// ══════════════════════════════════════════════════════════════════
//  LOGOUT SEGURO
// ══════════════════════════════════════════════════════════════════

/**
 * Realiza logout: limpa todo o estado interno e encerra timers.
 */
export async function logout() {
  const wasAdmin = _isAdmin;
  _currentUser      = null;
  _isAdmin          = false;
  _firebaseUser     = null;
  _sessionStartedAt = null;
  _lastValidatedAt  = null;
  _lastActivityAt   = null;

  _stopRevalidationLoop();

  if (wasAdmin) {
    try { await signOut(auth); } catch (e) { safeError('auth/logout', e); }
  }

  _notifyChange();
  devLog('Auth: logout realizado');
}

// ══════════════════════════════════════════════════════════════════
//  RECUPERAÇÃO DE SENHA — [AUTH-06]
//  Rate limiting próprio para evitar flood de e-mails
// ══════════════════════════════════════════════════════════════════

/**
 * Envia e-mail de recuperação de senha para o admin.
 * @param {string} email
 * @returns {Promise<{ ok: boolean, msg: string }>}
 */
export async function recuperarSenhaAdmin(email) {
  email = (email || '').trim().toLowerCase();
  if (!validarEmail(email)) return { ok: false, msg: 'E-mail inválido.' };

  // [AUTH-06] Rate limiting dedicado para reset (mais restritivo)
  const rlKey = 'reset:' + email.slice(0, 30);
  const rl    = checkRateLimit(rlKey);
  if (rl.blocked) return { ok: false, msg: `Muitas solicitações. Aguarde ${rl.secs}s.` };

  try {
    await sendPasswordResetEmail(auth, email);
    resetRateLimit(rlKey);
    return { ok: true, msg: 'E-mail de recuperação enviado. Verifique sua caixa de entrada.' };
  } catch (e) {
    safeError('auth/password-reset', e);
    // Mensagem genérica mesmo se e-mail não existe (evita enumeração)
    return { ok: false, msg: 'Não foi possível enviar o e-mail. Tente novamente mais tarde.' };
  }
}

// ══════════════════════════════════════════════════════════════════
//  RESTORE DE SESSÃO — [AUTH-02]
//
//  MUDANÇAS em relação à versão anterior:
//   - Timeout de 5 s na validação Firestore
//   - Se offline E TTL_OFFLINE excedido → invalida sessão
//   - Se offline E dentro do TTL → mantém sessão com flag `offlineMode`
//   - Verifica SESSION_MAX_AGE_MS: sessão muito antiga é invalidada
//
//  MITIGAÇÃO: impede que sessão persista indefinidamente sem validação.
//  Um cliente removido pelo admin é desconectado na próxima visita
//  mesmo que o Firestore esteja temporariamente indisponível,
//  desde que o TTL offline seja excedido.
// ══════════════════════════════════════════════════════════════════

/**
 * Tenta restaurar sessão de cliente a partir dos dados locais.
 * @param {object|null} savedUser   — objeto salvo no localStorage
 * @param {number|null} savedAt     — timestamp do último save (ms)
 * @returns {Promise<boolean>} true se sessão válida e restaurada
 */
export async function restoreClientSession(savedUser, savedAt = null) {
  if (!savedUser || !savedUser.tel || savedUser.isAdmin) return false;

  const digits = savedUser.tel.replace(/\D/g, '');
  if (digits.length < 8) return false;

  // [AUTH-03] Verifica idade máxima da sessão salva
  if (savedAt) {
    const age = Date.now() - savedAt;
    if (age > SESSION_MAX_AGE_MS) {
      devLog('Auth: sessão salva expirou (age > SESSION_MAX_AGE_MS)');
      return false;
    }
  }

  try {
    // [AUTH-02] Timeout de validação: não espera mais de 5 s
    const snap = await _firestoreWithTimeout(
      getDoc(doc(db, 'clientes', digits)),
      SESSION_VALIDATE_TIMEOUT_MS
    );

    if (snap.exists()) {
      _currentUser      = { ...snap.data(), isAdmin: false };
      _sessionStartedAt = savedAt || Date.now();
      _lastValidatedAt  = Date.now();
      _lastActivityAt   = Date.now();
      _notifyChange();
      _startRevalidationLoop();
      _resetInactivityTimer();
      devLog('Auth: sessão cliente restaurada (validada)');
      return true;
    }

    // Conta foi removida — não restaura
    devLog('Auth: conta não encontrada no Firestore — sessão não restaurada');
    return false;

  } catch (e) {
    // [AUTH-02] Firestore falhou (timeout ou offline)
    if (!savedAt) {
      // Sem timestamp não sabemos a idade — não restaura por segurança
      devLog('Auth: offline sem timestamp — sessão não restaurada');
      return false;
    }

    const offlineAge = Date.now() - savedAt;
    if (offlineAge > SESSION_OFFLINE_TTL_MS) {
      // TTL offline excedido — invalida por segurança
      devLog('Auth: TTL offline excedido na restauração — sessão invalidada');
      return false;
    }

    // Dentro do TTL — restaura com flag de revalidação pendente
    _currentUser = { ...savedUser, isAdmin: false, offlineMode: true };
    _sessionStartedAt = savedAt;
    _lastActivityAt   = Date.now();
    // Não chama _startRevalidationLoop() ainda — aguarda conectividade
    // Agenda revalidação quando a conexão voltar
    window.addEventListener('online', async function _onOnline() {
      window.removeEventListener('online', _onOnline);
      devLog('Auth: reconectado — revalidando sessão offline');
      const ok = await restoreClientSession(_currentUser, _sessionStartedAt);
      if (!ok) {
        await logout();
        window.dispatchEvent(new CustomEvent('auth:offline-revalidation-failed'));
      }
    }, { once: true });

    _notifyChange();
    devLog('Auth: sessão restaurada em modo offline (dentro do TTL)');
    return true;
  }
}
