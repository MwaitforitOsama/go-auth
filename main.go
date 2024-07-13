package main

import (
	"log"
	"os"

	goauth "github.com/MwaitforitOsama/go-auth/app"
	"github.com/MwaitforitOsama/go-auth/store"
	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {
	app := goauth.Initialise()
	app.IntialiseDb(store.NewPostgresDB(
		os.Getenv("HOST"),
		os.Getenv("PORT"),
		os.Getenv("USER"),
		os.Getenv("PASSWORD"),
		os.Getenv("DB"),
	))
	app.DB.RunMigration()
	app.Run()
}
