package goauth

import (
	"log"
	"net/http"
	"time"

	controller "github.com/MwaitforitOsama/go-auth/controller"
	"github.com/MwaitforitOsama/go-auth/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// App struct
type App struct {
	Router     *chi.Mux
	DB         store.DatabaseStore
	Controller controller.UserController
}

func Initialise() *App {
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.RequestID)
	router.Use(timeoutRequestMiddleware)
	var db store.DatabaseStore = nil
	var c controller.UserController
	return &App{
		Router:     router,
		DB:         db,
		Controller: c,
	}
}

func (a *App) IntialiseDb(s store.DatabaseStore) {
	a.DB = s
	a.Controller = controller.GetController(s)
}

func (a *App) Run() {
	a.LoadRoutes()
	log.Println("Starting the server")
	http.ListenAndServe(":3000", a.Router)
}

func timeoutRequestMiddleware(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, 5*time.Second, "Request Timed Out")
}
