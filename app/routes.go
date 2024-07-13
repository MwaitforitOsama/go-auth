package goauth

import "../utils"

func (a *App) LoadRoutes() {
	a.Router.Post("/login", utils.ApiFunc(a.Controller.Login))
	a.Router.Post("/register", utils.ApiFunc(a.Controller.Register))
	// Profile management
	a.Router.With(utils.JwtVerify).Get("/profile", utils.ApiFunc(a.Controller.GetProfile))
	a.Router.With(utils.JwtVerify).Put("/profile", utils.ApiFunc(a.Controller.EditProfile))
	a.Router.With(utils.JwtVerify).Delete("/profile", utils.ApiFunc(a.Controller.DeleteProfile))

	// Password management
	a.Router.Post("/forgot-password", utils.ApiFunc(a.Controller.ForgotPassword))
	a.Router.Post("/reset-password", utils.ApiFunc(a.Controller.ResetPassword))
	a.Router.With(utils.JwtVerify).Post("/change-password", utils.ApiFunc(a.Controller.ChangePassword))

	// Token management
	a.Router.Post("/refresh-token", utils.ApiFunc(a.Controller.RefreshToken))
	a.Router.Post("/verify-token", utils.ApiFunc(a.Controller.VerifyToken))
}
