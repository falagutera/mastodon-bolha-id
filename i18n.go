package main

import (
	"net/http"
	"slices"
	"strings"
)

const langCookie = "__Host-id-lang"

var translations = map[string]map[string]string{
	"en": {
		"lang": "en", "title": "id", "language": "Language", "nav_notes": "Release notes", "notes_title": "Release notes", "notes_lede": "What changed in each version.",
		"lede":          "Sign in to the tools of the community with your %s account.",
		"how":           "Tools that use this service send you here. You sign in on %s as usual, and the tool receives only who you are: your name, your @ and your e-mail. Your password never leaves the instance.",
		"who":           "Only approved and active accounts of %s can sign in. If the account is suspended, signing in stops working.",
		"clients":       "Tools that use it",
		"no_clients":    "None yet.",
		"signed_in_as":  "Signed in here as @%s.",
		"logout":        "Sign out",
		"privacy":       "Kept here: a short session in your browser (2 hours by default), which tools you allowed, and a log of sign-ins (account, tool, time). No passwords and no tokens of your account on the instance.",
		"consent_title": "Allow access?", "consent_lede": "%s wants to sign you in with your account @%s@%s.", "consent_shares": "It will receive:",
		"share_id": "an identifier of your account that doesn't change", "share_profile": "your name, @, profile link and avatar", "share_email": "your e-mail address",
		"share_role": "your role on the instance (such as Moderator or Admin), if you have one", "share_offline": "access that continues while you are away, until you sign out of the tool",
		"consent_note": "You will only be asked again if the tool asks for more. Not you? Sign out first.",
		"allow":        "Allow", "deny": "Deny",
		"logout_confirm_title": "Sign out?", "logout_confirm": "This ends your session here and signs you out of the tools that use it on their next check.", "logged_out_title": "Signed out", "logged_out": "You are signed out of this service. Tools you used may still keep their own session.",
		"error_title": "Something went wrong", "home": "Back",
		"error_bad_client":      "This tool isn't registered here.",
		"error_bad_redirect":    "This tool sent an address that isn't registered. Nothing was shared.",
		"error_bad_request":     "The request could not be read.",
		"error_expired":         "This page expired. Go back to the tool and sign in again.",
		"error_unavailable":     "Temporarily unavailable. Try again in a moment.",
		"error_instance":        "The instance didn't answer as expected. Try again in a moment.",
		"error_refused":         "This account can't sign in here.",
		"error_refused_pending": "This account can't sign in yet: it needs to be approved and to have its e-mail confirmed on the instance.",
		"source":                "Source code",
	},
	"pt-BR": {
		"lang": "pt-BR", "title": "id", "language": "Idioma", "nav_notes": "Novidades", "notes_title": "Novidades", "notes_lede": "O que mudou em cada versão.",
		"lede":          "Entre nas ferramentas da comunidade com sua conta do %s.",
		"how":           "As ferramentas que usam este serviço mandam você para cá. Você entra no %s como sempre, e a ferramenta recebe só quem você é: seu nome, seu @ e seu e-mail. Sua senha nunca sai da instância.",
		"who":           "Só contas aprovadas e ativas do %s entram. Se a conta for suspensa, o acesso para de funcionar.",
		"clients":       "Ferramentas que usam",
		"no_clients":    "Nenhuma ainda.",
		"signed_in_as":  "Conectado aqui como @%s.",
		"logout":        "Sair",
		"privacy":       "Fica guardado aqui: uma sessão curta no seu navegador (2 horas por padrão), quais ferramentas você autorizou e um registro dos acessos (conta, ferramenta, horário). Nenhuma senha e nenhum token da sua conta na instância.",
		"consent_title": "Autorizar acesso?", "consent_lede": "%s quer usar sua conta @%s@%s para você entrar.", "consent_shares": "Vai receber:",
		"share_id": "um identificador da sua conta que não muda", "share_profile": "seu nome, @, link do perfil e avatar", "share_email": "seu endereço de e-mail",
		"share_role": "seu cargo na instância (como Moderação ou Admin), se tiver", "share_offline": "acesso que continua enquanto você estiver fora, até você sair da ferramenta",
		"consent_note": "Só vamos perguntar de novo se a ferramenta pedir mais. Não é você? Saia primeiro.",
		"allow":        "Autorizar", "deny": "Recusar",
		"logout_confirm_title": "Sair?", "logout_confirm": "Isso encerra sua sessão aqui e tira você das ferramentas que a usam na próxima verificação delas.", "logged_out_title": "Você saiu", "logged_out": "Você saiu deste serviço. As ferramentas que você usou podem manter a sessão delas.",
		"error_title": "Algo deu errado", "home": "Voltar",
		"error_bad_client":      "Esta ferramenta não está cadastrada aqui.",
		"error_bad_redirect":    "Esta ferramenta mandou um endereço que não está cadastrado. Nada foi compartilhado.",
		"error_bad_request":     "Não deu para ler o pedido.",
		"error_expired":         "Esta página expirou. Volte para a ferramenta e entre de novo.",
		"error_unavailable":     "Indisponível no momento. Tente de novo daqui a pouco.",
		"error_instance":        "A instância não respondeu como esperado. Tente de novo daqui a pouco.",
		"error_refused":         "Esta conta não pode entrar aqui.",
		"error_refused_pending": "Esta conta ainda não pode entrar: ela precisa estar aprovada e com o e-mail confirmado na instância.",
		"source":                "Código-fonte",
	},
}

func strs(lang string) map[string]string {
	if t, ok := translations[lang]; ok {
		return t
	}
	return translations["en"]
}

func normalize(lang string) string {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if strings.HasPrefix(lang, "pt") {
		return "pt-BR"
	}
	if strings.HasPrefix(lang, "en") {
		return "en"
	}
	return ""
}

// uiLocale picks the first known language of an OpenID Connect ui_locales list.
func uiLocale(list string) string {
	for _, l := range strings.Fields(list) {
		if n := normalize(l); n != "" {
			return n
		}
	}
	return ""
}

// language picks ?lang=, then the cookie, then the browser's languages, then the configured default.
func language(r *http.Request, fallback string) string {
	if q := normalize(r.URL.Query().Get("lang")); q != "" {
		return q
	}
	if c, err := r.Cookie(langCookie); err == nil {
		if l := normalize(c.Value); l != "" {
			return l
		}
	}
	for part := range strings.SplitSeq(r.Header.Get("Accept-Language"), ",") {
		if l := normalize(strings.SplitN(part, ";", 2)[0]); l != "" {
			return l
		}
	}
	if l := normalize(fallback); l != "" {
		return l
	}
	return "en"
}

func setLanguage(w http.ResponseWriter, value string) {
	if l := normalize(value); l != "" && slices.Contains([]string{"en", "pt-BR"}, l) {
		http.SetCookie(w, &http.Cookie{Name: langCookie, Value: l, Path: "/", MaxAge: 31536000, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
}
