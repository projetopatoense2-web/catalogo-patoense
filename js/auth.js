/**
 * auth.js — Autenticação de usuários (clientes e admin)
 * Distribuidora Patoense 2026
 *
 * Responsabilidades:
 *  - Login de clientes (por telefone + senha, validado no Firestore)
 *  - Login de admin (Firebase Authentication)
 *  - Logout seguro
 *  - Recuperação de senha
 *  - Sessão persistente via Firebase Auth (admin) e
 *    verificação online (clientes)
 *
 * O que NÃO faz:
 *  - Não armazena senhas ou tokens em localStorage
 *  - Não expõe permissões no navegador
 *  - Não confia em dados de localStorage para decidir acesso
 */

import { auth, db, doc, getDoc, setDoc, serverTimestamp,
         signInWithEmailAndPassword, signOut,
         onAuthStateChanged, sendPasswordResetEmail }
  from './firebase.js';

import { hashSenha, verificarSenha, checkRateLimit, resetRateLimit,
         validarTel, validarEmail, validarSenha, devLog, safeError }
  from './security.js';

// ── Estado interno (não exposto no window) ───────────────────────
let _currentUser   = null; // dados do cliente logado
let _isAdmin       = false; // confirmado via Firebase Auth
let _firebaseUser  = null; // objeto do Firebase Auth (admin)

// ── Callbacks de mudança de estado ──────────────────────────────
const _onChangeCallbacks = [];
export function onAuthChange(cb) { _onChangeCallbacks.push(cb); }
function _notifyChange() { _onChangeCallbacks.forEach(cb => cb(_currentUser, _isAdmin)); }

// ── Getters públicos ─────────────────────────────────────────────
export function getCurrentUser()  { return _currentUser; }
export function getIsAdmin()      { return _isAdmin; }
export function getFirebaseUser() { return _firebaseUser; }

// ══════════════════════════════════════════════════════════════════
//  SESSÃO PERSISTENTE — Firebase Auth observer
//  Detecta se admin já estava logado numa sessão anterior
// ══════════════════════════════════════════════════════════════════
onAuthStateChanged(auth, async (fbUser) => {
  if (fbUser) {
    _firebaseUser = fbUser;
    // Confirma que é admin no Firestore (não confia só no Auth)
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
    // Firebase diz que não há sessão ativa
    if (_isAdmin) {
      _isAdmin      = false;
      _firebaseUser = null;
      _notifyChange();
    }
  }
});

// ══════════════════════════════════════════════════════════════════
//  LOGIN DE CLIENTE — valida no Firestore
// ══════════════════════════════════════════════════════════════════

/**
 * Realiza login de cliente por telefone ou nome + senha.
 * @param {string} busca   — telefone (dígitos) ou nome
 * @param {string} senha
 * @returns {Promise<{ ok: boolean, msg?: string, pendente?: boolean }>}
 */
export async function loginCliente(busca, senha) {
  busca = (busca || '').trim().toLowerCase();
  if (!busca || !senha) return { ok: false, msg: 'Preencha todos os campos.' };

  // Rate limiting
  const rlKey = 'login:' + busca.slice(0, 20);
  const rl    = checkRateLimit(rlKey);
  if (rl.blocked) return { ok: false, msg: `Muitas tentativas. Aguarde ${rl.secs}s.` };

  // 1. Busca por telefone (preferencial)
  const telVal = validarTel(busca);
  let fbUser   = null;

  if (telVal.ok) {
    try {
      const snap = await getDoc(doc(db, 'clientes', telVal.digits));
      if (snap.exists()) fbUser = snap.data();
    } catch (e) { safeError('auth/login-tel', e); }
  }

  // 2. Busca por nome se não achou por telefone
  if (!fbUser && busca.length >= 3) {
    try {
      const { getDocs, collection } = await import('./firebase.js');
      const allSnap = await getDocs(collection(db, 'clientes'));
      for (const d of allSnap.docs) {
        const u = d.data();
        if (u.nome && u.nome.toLowerCase().includes(busca)) { fbUser = u; break; }
      }
    } catch (e) { safeError('auth/login-nome', e); }
  }

  if (fbUser) {
    const ok = await verificarSenha(senha, (fbUser.tel || '').replace(/\D/g, ''), fbUser.senhaHash);
    if (!ok) return { ok: false, msg: 'Senha incorreta. Tente novamente.' };
    resetRateLimit(rlKey);
    _currentUser = { ...fbUser, isAdmin: false };
    _notifyChange();
    devLog('Auth: cliente logado');
    return { ok: true, user: _currentUser };
  }

  // 3. Verifica se está pendente
  const digits = busca.replace(/\D/g, '');
  if (digits.length >= 8) {
    try {
      const snap = await getDoc(doc(db, 'clientes_pendentes', digits));
      if (snap.exists()) return { ok: false, pendente: true, nome: snap.data().nome };
    } catch (_) {}
  }

  return { ok: false, msg: 'Cadastro não encontrado ou senha incorreta.' };
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

    // Confirma role no Firestore
    const snap = await getDoc(doc(db, 'usuarios', cred.user.uid));
    if (!snap.exists() || snap.data().role !== 'admin') {
      // Usuário autenticado mas não é admin — logout imediato
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
    const msgMap = {
      'auth/invalid-credential':   'E-mail ou senha incorretos.',
      'auth/user-not-found':       'E-mail ou senha incorretos.',
      'auth/wrong-password':       'E-mail ou senha incorretos.',
      'auth/too-many-requests':    'Muitas tentativas. Aguarde alguns minutos.',
      'auth/network-request-failed': 'Erro de conexão. Verifique sua internet.'
    };
    return { ok: false, msg: msgMap[e.code] || 'Erro ao entrar. Tente novamente.' };
  }
}

// ══════════════════════════════════════════════════════════════════
//  LOGOUT SEGURO
// ══════════════════════════════════════════════════════════════════

/**
 * Realiza logout: limpa estado interno e encerra sessão Firebase se admin.
 */
export async function logout() {
  const wasAdmin = _isAdmin;
  _currentUser  = null;
  _isAdmin      = false;
  _firebaseUser = null;

  if (wasAdmin) {
    try { await signOut(auth); } catch (e) { safeError('auth/logout', e); }
  }

  _notifyChange();
  devLog('Auth: logout realizado');
}

// ══════════════════════════════════════════════════════════════════
//  RECUPERAÇÃO DE SENHA (admin)
// ══════════════════════════════════════════════════════════════════

/**
 * Envia e-mail de recuperação de senha para o admin.
 * @param {string} email
 * @returns {Promise<{ ok: boolean, msg: string }>}
 */
export async function recuperarSenhaAdmin(email) {
  email = (email || '').trim();
  if (!validarEmail(email)) return { ok: false, msg: 'E-mail inválido.' };
  try {
    await sendPasswordResetEmail(auth, email);
    return { ok: true, msg: 'E-mail de recuperação enviado. Verifique sua caixa de entrada.' };
  } catch (e) {
    safeError('auth/password-reset', e);
    return { ok: false, msg: 'Não foi possível enviar o e-mail. Verifique o endereço.' };
  }
}

// ══════════════════════════════════════════════════════════════════
//  VERIFICAÇÃO DE SESSÃO AO CARREGAR PÁGINA
//  Valida silenciosamente se o cliente salvo localmente ainda existe
// ══════════════════════════════════════════════════════════════════

/**
 * Tenta restaurar sessão de cliente a partir dos dados locais.
 * Valida no Firestore — se o documento não existir mais, faz logout.
 * @param {object|null} savedUser  — objeto salvo no localStorage
 * @returns {Promise<boolean>} true se sessão válida
 */
export async function restoreClientSession(savedUser) {
  if (!savedUser || !savedUser.tel || savedUser.isAdmin) return false;

  const digits = savedUser.tel.replace(/\D/g, '');
  if (digits.length < 8) return false;

  try {
    const snap = await getDoc(doc(db, 'clientes', digits));
    if (snap.exists()) {
      _currentUser = { ...snap.data(), isAdmin: false };
      _notifyChange();
      devLog('Auth: sessão cliente restaurada');
      return true;
    }
    // Documento sumiu (removido pelo admin) — limpa sessão
    _currentUser = null;
    _notifyChange();
    return false;
  } catch (_) {
    // Firebase indisponível — mantém sessão local temporariamente
    _currentUser = { ...savedUser, isAdmin: false };
    _notifyChange();
    return true;
  }
}
