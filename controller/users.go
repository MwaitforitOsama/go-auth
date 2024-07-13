package controller

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/MwaitforitOsama/go-auth/model"
	"github.com/MwaitforitOsama/go-auth/store"
	"github.com/MwaitforitOsama/go-auth/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserController struct {
	db store.DatabaseStore
}

func GetController(db store.DatabaseStore) UserController {
	return UserController{
		db: db,
	}
}

func (uc *UserController) Login(w http.ResponseWriter, r *http.Request) (int, error) {
	// The handler logs in existing users
	loginRequest := model.LoginRequest{}
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		return http.StatusBadRequest, fmt.Errorf("INVALID REQUEST BODY")
	}
	log.Println("******----------------------*********")
	// Input validation
	if err := utils.ValidateLoginRequest(loginRequest); err != nil {
		log.Printf("Invalid Login request: %v\nThe request body is %v\n", err, loginRequest)
		return http.StatusBadRequest, err
	}
	log.Printf("User with email %s is logging in\n", loginRequest.Email)
	user, err := uc.db.Login(r.Context(), loginRequest.Email, loginRequest.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("%s Login request failed\n", loginRequest.Email)
			return http.StatusNotFound, fmt.Errorf("USER %s NOT FOUND", loginRequest.Email)
		} else {
			log.Printf("%s Login request failed\n", loginRequest.Email)
			return http.StatusBadRequest, err
		}
	}
	jwtToken, err := utils.CreateJWToken(user.Id.String())
	if err != nil {
		log.Printf("Error creating JWT for user %s : %v+\n", user.Email, err)
		log.Printf("%s Login request failed\n", loginRequest.Email)
		return http.StatusInternalServerError, fmt.Errorf("INTERNAL SERVER ERROR")
	}
	refreshToken, err := utils.CreateRefreshToken(user.Id.String())
	if err != nil {
		log.Printf("Error creating Refresh for user %s: %v+\n", user.Email, err)
		log.Printf("%s Login request failed\n", loginRequest.Email)
		return http.StatusInternalServerError, fmt.Errorf("INTERNAL SERVER ERROR")
	}
	log.Printf("User %s logged in with email %s\n", user.Id, user.Email)
	if err := uc.db.StoreToken(r.Context(), refreshToken, user.Id.String(), time.Now().Add(time.Minute*2)); err != nil {
		log.Printf("Failed to write token for %s to Database: %v+\n", user.Email, err)
		return http.StatusInternalServerError, fmt.Errorf("INTERNAL SERVER ERROR")
	}
	log.Printf("%s Login request Successful\n", loginRequest.Email)
	w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", jwtToken))
	res := model.LoginResponse{
		ID:           user.Id,
		RefreshToken: refreshToken,
	}
	utils.WriteJSON(w, http.StatusAccepted, res)
	return 0, nil
}

func (uc *UserController) Logout(w http.ResponseWriter, r *http.Request) (int, error) {
	return 0, nil
}

func (uc *UserController) Register(w http.ResponseWriter, r *http.Request) (int, error) {
	// The handler register a new user into the system
	userRequest := model.SignupRequest{}
	if err := json.NewDecoder(r.Body).Decode(&userRequest); err != nil {
		return http.StatusBadRequest, fmt.Errorf("INVALID REQUEST BODY")
	}
	log.Println("******----------------------*********")
	// Input validation
	if err := utils.ValidateUserRequest(userRequest); err != nil {
		log.Printf("Invalid signup request: %v\nThe request body is %v\n", err, userRequest)
		return http.StatusBadRequest, err
	}
	log.Printf("User with email %s is signing up\n", userRequest.Email)

	// Check if email already exists
	log.Printf("Checking if the email %s exists in DB\n", userRequest.Email)
	err := uc.db.CheckEmailExists(r.Context(), userRequest.Email)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Email %s already exists in Database\n", userRequest.Email)
			return http.StatusBadRequest, err
		}
	}

	// Encrypt the user password
	encryptedPassword, err := utils.EncryptPassword(userRequest.Password)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("INTERNAL SERVER ERROR")
	}

	userId := uuid.New()
	// Create new user
	createdAt := time.Now().UTC()
	user := model.User{
		Id:        userId,
		FirstName: userRequest.FirstName,
		LastName:  userRequest.LastName,
		Email:     userRequest.Email,
		Password:  encryptedPassword,
		CreatedAt: &createdAt,
	}

	jwtToken, err := utils.CreateJWToken(user.Id.String())
	if err != nil {
		log.Printf("Error creating JWT for user %s : %v+\n", user.Email, err)
		return http.StatusInternalServerError, fmt.Errorf("INTERNAL SERVER ERROR")
	}
	refreshToken, err := utils.CreateRefreshToken(user.Id.String())
	if err != nil {
		log.Printf("Error creating Refresh for user %s: %v+\n", user.Email, err)
		return http.StatusInternalServerError, fmt.Errorf("INTERNAL SERVER ERROR")
	}
	// Save the user in DB
	log.Printf("Writing user %s to Database\n", userRequest.Email)
	if err := uc.db.Signup(r.Context(), &user); err != nil {
		log.Printf("Failed to write user %s to Database\n", userRequest.Email)
		w.WriteHeader(http.StatusInternalServerError)
		return http.StatusInternalServerError, fmt.Errorf("INTERNAL SERVER ERROR")
	}
	log.Printf("User %s created with email %s\n", user.Id, userRequest.Email)
	if err := uc.db.StoreToken(r.Context(), refreshToken, user.Id.String(), time.Now().Add(time.Minute*2)); err != nil {
		log.Printf("Failed to write token for %s to Database: %v+\n", userRequest.Email, err)
		return http.StatusInternalServerError, fmt.Errorf("INTERNAL SERVER ERROR")
	}
	//Send the response to client
	// Add JWT and Refresh Token to the auth header
	w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", jwtToken))
	res := model.LoginResponse{
		ID:           user.Id,
		RefreshToken: refreshToken,
	}
	utils.WriteJSON(w, http.StatusCreated, res)
	return 0, nil
}

func (uc *UserController) ForgotPassword(w http.ResponseWriter, r *http.Request) (int, error) {
	return 0, nil
}

func (uc *UserController) ResetPassword(w http.ResponseWriter, r *http.Request) (int, error) {
	return 0, nil
}

func (uc *UserController) ChangePassword(w http.ResponseWriter, r *http.Request) (int, error) {
	return 0, nil
}

func (uc *UserController) GetProfile(w http.ResponseWriter, r *http.Request) (int, error) {
	id := r.Context().Value("userID")
	log.Printf("User %s is getting profile\n", id)
	user, err := uc.db.GetUser(r.Context(), id.(string))
	if err != nil {
		log.Printf("Failed to get user %s from Database\n", id)
		log.Println(err)
		return http.StatusBadRequest, fmt.Errorf("USER NOT FOUND IN DATABASE")
	}
	log.Println("Got profile successfully")
	utils.WriteJSON(w, http.StatusOK, user)
	return 0, nil
}

func (uc *UserController) EditProfile(w http.ResponseWriter, r *http.Request) (int, error) {
	body := model.EditUserRequest{}
	id := r.Context().Value("userID")
	log.Printf("User %s is getting profile\n", id)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		log.Printf("The request body is not valid %v+\n", err)
		return http.StatusBadRequest, fmt.Errorf("BAD REQUEST BODY")
	}
	if err := utils.ValidateEditRequest(body); err != nil {
		log.Printf("Invalid edit request: %v\nThe request body is %v\n", err, body)
		return http.StatusBadRequest, err
	}
	user, err := uc.db.UpdateUser(r.Context(), body, id.(string))
	if err != nil {
		log.Printf("Failed to edit user %s from Database\n", id)
		log.Println(err)
		return http.StatusBadRequest, fmt.Errorf("USER NOT FOUND IN DATABASE")
	}
	log.Println("Editeds profile successfully")
	utils.WriteJSON(w, http.StatusOK, user)
	return 0, nil
}

func (uc *UserController) DeleteProfile(w http.ResponseWriter, r *http.Request) (int, error) {
	id := r.Context().Value("userID")
	log.Printf("User %s is Deleting profile\n", id)
	err := uc.db.DeleteUser(r.Context(), id.(string))
	if err != nil {
		log.Printf("Failed to delete user %s from Database\n", id)
		log.Println(err)
		return http.StatusBadRequest, fmt.Errorf("USER NOT FOUND IN DATABASE")
	}
	log.Println("Deleted profile successfully")
	var res struct {
		Status string `json:"status"`
	}
	res.Status = "success"
	utils.WriteJSON(w, http.StatusOK, res)
	return 0, nil
}

func (uc *UserController) RefreshToken(w http.ResponseWriter, r *http.Request) (int, error) {
	var body struct {
		Token string `json:"token"`
	}
	log.Println("*--------------------------*")
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		log.Printf("The request body is not valid %v+\n", err)
		return http.StatusBadRequest, fmt.Errorf("BAD REQUEST BODY")
	}
	claims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(body.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil || !token.Valid {
		log.Printf("Invalid Token: %v+\n", err)
		return http.StatusBadRequest, fmt.Errorf("INVALID TOKEN")
	}
	userID, ok := (*claims)["id"].(string)
	if !ok {
		log.Println("Token does not contain user ID")
		return http.StatusBadRequest, fmt.Errorf("INVALID TOKEN")
	}
	_, err = uc.db.GetUser(r.Context(), userID)
	if err != nil {
		log.Println("Failed to get user from Database")
		log.Println(err)
		return http.StatusBadRequest, fmt.Errorf("USER NOT FOUND IN DATABASE")
	}
	err = uc.db.CheckTokenStatus(r.Context(), userID, body.Token)
	if err != nil {
		log.Println("Token status is revoked")
		log.Println(err)
		return http.StatusBadRequest, fmt.Errorf("TOKEN IS NOT VALID")
	}
	jwtToken, err := utils.CreateJWToken(userID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("INTERNAL SERVER ERROR")
	}
	refreshToken, err := utils.CreateRefreshToken(userID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("INTERNAL SERVER ERROR")
	}
	log.Println("Storing new refresh token in db")
	if err := uc.db.StoreToken(r.Context(), refreshToken, userID, time.Now().Add(time.Minute*2)); err != nil {
		log.Printf("Failed to write token to Database: %v+\n", err)
		return http.StatusInternalServerError, fmt.Errorf("INTERNAL SERVER ERROR")
	}
	var res struct {
		ID           string `json:"id"`
		Token        string `json:"auth-token"`
		RefreshToken string `json:"refresh-token"`
	}
	res.ID = userID
	res.Token = jwtToken
	res.RefreshToken = refreshToken

	utils.WriteJSON(w, http.StatusOK, res)
	return 0, nil
}

func (uc *UserController) VerifyToken(w http.ResponseWriter, r *http.Request) (int, error) {
	var requestToken struct {
		Token string `json:"token"`
	}
	log.Println("*--------------------------*")
	err := json.NewDecoder(r.Body).Decode(&requestToken)
	if err != nil || requestToken.Token == "" {
		log.Printf("The request body is not valid %v+\n", err)
		return http.StatusBadRequest, fmt.Errorf("TOKEN MISSING IN THE RESQUEST BODY")
	}
	claims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(requestToken.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil || !token.Valid {
		log.Printf("Invalid Token: %v+\n", err)
		return http.StatusBadRequest, fmt.Errorf("INVALID TOKEN")
	}

	userID, ok := (*claims)["id"].(string)
	if !ok {
		log.Println("Token does not contain user ID")
		return http.StatusBadRequest, fmt.Errorf("INVALID TOKEN")
	}
	user, err := uc.db.GetUser(r.Context(), userID)
	if err != nil {
		log.Println("Failed to get user from Database")
		log.Println(err)
		return http.StatusBadRequest, fmt.Errorf("USER NOT FOUND IN DATABASE")
	}
	log.Println("Verified token successfully")
	utils.WriteJSON(w, http.StatusOK, user)
	return 0, nil
}
