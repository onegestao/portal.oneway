/* =====================================================================
   ONE WAY — Porta de entrada do portal (guard.js)

   O que este arquivo faz:
   - Em toda página do portal, confere se a pessoa já passou pela porta
     de entrada (login.html) nas últimas 24 horas. Se não passou, manda
     para o login e, depois da senha, devolve para a página que ela
     tentou abrir.
   - Guarda apenas o "hash" das senhas (uma impressão digital que não
     dá para reverter), nunca a senha em texto.

   Limite: é uma proteção leve, feita no navegador. Afasta curiosos,
   mas quem entende de programação consegue contornar. A proteção de
   verdade virá com o Cloudflare Access, quando o domínio estiver lá.

   COMO TROCAR UMA SENHA
   1. Abra gerar-hash.html (pelo site ou direto do seu computador).
   2. Digite a nova senha e copie o hash gerado.
   3. Cole o hash no lugar certo em HASHES, logo abaixo, e suba o arquivo.
   Trocar o hash do "portal" desloga todo mundo na hora.
   ===================================================================== */
(function () {
  'use strict';

  var HASHES = {
    // Senha da porta de entrada do portal
    portal:   '628bef66da82b5949a64b5d8f6226537fa5aa9579614cf17dcfcbc92dae85f8d',
    // Gestão de Pagamentos > pasta Notas Fiscais
    nf:       '628bef66da82b5949a64b5d8f6226537fa5aa9579614cf17dcfcbc92dae85f8d',
    // Recrutamento > excluir candidato
    exclusao: '628bef66da82b5949a64b5d8f6226537fa5aa9579614cf17dcfcbc92dae85f8d'
  };

  // Não alterar os itens abaixo sem atualizar o gerar-hash.html junto.
  var SALT = 'oneway-portal-v1';
  var ITERACOES = 150000;
  var DURACAO_HORAS = 24;
  var CHAVE_SESSAO = 'ow_portal_sessao';

  var script = document.currentScript;
  var BASE = script ? script.src.replace(/guard\.js(\?.*)?$/, '') : './';
  var basePath = new URL(BASE, location.href).pathname;
  var ehLogin = !!(script && script.getAttribute('data-pagina') === 'login');

  function lerSessao() {
    try {
      var s = JSON.parse(localStorage.getItem(CHAVE_SESSAO) || 'null');
      if (s && s.h === HASHES.portal && typeof s.exp === 'number' && s.exp > Date.now()) return s;
    } catch (e) {}
    return null;
  }

  function hex(buf) {
    var b = new Uint8Array(buf), out = '';
    for (var i = 0; i < b.length; i++) out += ('0' + b[i].toString(16)).slice(-2);
    return out;
  }

  function gerarHash(senha) {
    if (!window.crypto || !crypto.subtle) {
      return Promise.reject(new Error('Navegador sem suporte a criptografia. Abra o portal pelo endereço https.'));
    }
    var enc = new TextEncoder();
    return crypto.subtle.importKey('raw', enc.encode(senha), 'PBKDF2', false, ['deriveBits'])
      .then(function (chave) {
        return crypto.subtle.deriveBits(
          { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(SALT), iterations: ITERACOES },
          chave, 256);
      })
      .then(hex);
  }

  // Só aceita voltar para páginas do próprio portal (evita redirecionar para fora).
  function destinoSeguro(volta) {
    try {
      var u = new URL(volta || '', location.href);
      if (u.origin === location.origin && u.pathname.indexOf(basePath) === 0 &&
          !/login\.html$/.test(u.pathname)) {
        return u.pathname + u.search + u.hash;
      }
    } catch (e) {}
    return basePath;
  }

  window.OWAuth = {
    base: BASE,
    gerarHash: gerarHash,

    // Confere uma senha contra um dos hashes (portal, nf, exclusao).
    verificar: function (tipo, senha) {
      if (!HASHES[tipo] || !senha) return Promise.resolve(false);
      return gerarHash(senha).then(function (h) { return h === HASHES[tipo]; });
    },

    // Usado pelo login.html. Grava a sessão de 24 horas se a senha estiver certa.
    entrar: function (senha) {
      return window.OWAuth.verificar('portal', senha).then(function (ok) {
        if (ok) {
          localStorage.setItem(CHAVE_SESSAO, JSON.stringify({
            h: HASHES.portal,
            exp: Date.now() + DURACAO_HORAS * 3600 * 1000
          }));
        }
        return ok;
      });
    },

    sair: function () {
      try { localStorage.removeItem(CHAVE_SESSAO); } catch (e) {}
      location.replace(BASE + 'login.html');
    },

    logado: function () { return !!lerSessao(); },
    expiraEm: function () { var s = lerSessao(); return s ? new Date(s.exp) : null; },
    destinoSeguro: destinoSeguro
  };

  if (ehLogin) return;

  if (!lerSessao()) {
    // Esconde a página enquanto redireciona, para não "piscar" o conteúdo.
    document.documentElement.style.visibility = 'hidden';
    location.replace(BASE + 'login.html?volta=' +
      encodeURIComponent(location.pathname + location.search + location.hash));
    return;
  }

  // Se a sessão vencer com a aba aberta, volta para o login.
  setInterval(function () {
    if (!lerSessao()) {
      location.replace(BASE + 'login.html?volta=' +
        encodeURIComponent(location.pathname + location.search + location.hash));
    }
  }, 60 * 1000);
})();
