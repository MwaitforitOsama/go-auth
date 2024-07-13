package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/MwaitforitOsama/go-auth/model"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func EncryptPassword(pwd string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(pwd), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

type apiFunc func(w http.ResponseWriter, r *http.Request) (int, error)

type APIError struct {
	Error string `json:"error"`
}

func ApiFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status, err := f(w, r)
		if err != nil {
			WriteJSON(w, status, APIError{Error: err.Error()})
		}
	}
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.WriteHeader(status)
	w.Header().Add("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}

func ValidateUserRequest(userRequest model.SignupRequest) error {
	if userRequest.FirstName == "" || userRequest.LastName == "" || userRequest.Email == "" || userRequest.Password == "" {
		return fmt.Errorf("all fields are required")
	}
	if !isValidEmail(userRequest.Email) {
		return fmt.Errorf("invalid email address")
	}
	if len(userRequest.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	return nil
}

func ValidateLoginRequest(userRequest model.LoginRequest) error {
	if userRequest.Email == "" || userRequest.Password == "" {
		return fmt.Errorf("all fields are required")
	}
	if !isValidEmail(userRequest.Email) {
		return fmt.Errorf("invalid email address")
	}
	if len(userRequest.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	return nil
}

func ValidateEditRequest(userRequest model.EditUserRequest) error {
	if userRequest.Email == "" || userRequest.FirstName == "" || userRequest.LastName == "" {
		return fmt.Errorf("all fields are required")
	}
	if !isValidEmail(userRequest.Email) {
		return fmt.Errorf("invalid email address")
	}
	return nil
}

func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+\/=?^_` + `"()` + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	return emailRegex.MatchString(email)
}

func CreateJWToken(user string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"id":  user,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 1).Unix(),
			"iss": "go-auth",
		})

	secret := os.Getenv("SECRET")
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func CreateRefreshToken(user string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"id":  user,
			"exp": time.Now().Add(time.Minute * 2).Unix(),
		})
	secret := os.Getenv("SECRET")
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func VerifyJWTToken(tokenString string) (*jwt.Token, error) {
	secret := os.Getenv("SECRET")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func JwtVerify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("*---------------------------*")
		log.Println("Authorizing the user")
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Println("Authorization header missing")
			WriteJSON(w, http.StatusUnauthorized, APIError{Error: "Missing Authorization Header"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Println("Invalid Authorization Header")
			WriteJSON(w, http.StatusUnauthorized, APIError{Error: "Invalid Authorization Header"})
			return
		}

		tokenString := parts[1]
		claims := &jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("SECRET")), nil
		})

		if err != nil || !token.Valid {
			log.Printf("Invalid Token: %v+\n", err)
			WriteJSON(w, http.StatusUnauthorized, APIError{Error: "Invalid Token"})
			return
		}

		userID, ok := (*claims)["id"].(string)
		if !ok {
			log.Println("Token does not contain user ID")
			WriteJSON(w, http.StatusUnauthorized, APIError{Error: "Invalid Token"})
			return
		}
		ctx := context.WithValue(r.Context(), "userID", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
