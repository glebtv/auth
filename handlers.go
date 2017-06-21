package auth

import (
	"net/http"

	"github.com/qor/qor"
	"github.com/qor/qor/utils"
	"github.com/qor/responder"
)

func respondAfterLogged(claims *Claims, context *Context) {
	token := context.Auth.SignedToken(claims)
	qorContext := &qor.Context{
		Request: context.Request,
		Writer:  context.Writer,
	}

	// TODO set expired at
	utils.SetCookie(http.Cookie{
		Name:  context.Auth.Config.SessionName,
		Value: token,
	}, qorContext)

	responder.With("html", func() {
		// write cookie
		http.Redirect(w, req, "/", http.StatusSeeOther)
	}).With([]string{"json"}, func() {
		// write json token
	}).Respond(req)
}

// DefaultLoginHandler default login behaviour
var DefaultLoginHandler = func(context *Context, authorize func(*Context) (*Claims, error)) {
	var (
		req         = context.Request
		w           = context.Writer
		claims, err = authorize(context)
	)

	if err == nil && claims != nil {
		respondAfterLogged(claims, context)
		return
	}

	// error handling
	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/login", context, req, w)
	}).With([]string{"json"}, func() {
		// write json error
	})
}

// DefaultRegisterHandler default register behaviour
var DefaultRegisterHandler = func(context *Context, register func(*Context) (*Claims, error)) {
	var (
		req         = context.Request
		w           = context.Writer
		claims, err = register(context)
	)

	if err == nil && claims != nil {
		respondAfterLogged(claims, context)
		return
	}

	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/register", context, req, w)
	}).With([]string{"json"}, func() {
		// write json error
	})
}

// DefaultLogoutHandler default logout behaviour
var DefaultLogoutHandler = func(context *Context) {
	qorContext := &qor.Context{
		Request: context.Request,
		Writer:  context.Writer,
	}

	utils.SetCookie(http.Cookie{Name: context.Auth.Config.SessionName, Value: ""}, qorContext)
	http.Redirect(context.Writer, context.Request, "/", http.StatusSeeOther)
}
