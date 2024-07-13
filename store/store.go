package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/hanzalahimran7/go-auth/model"
)

type DatabaseStore interface {
	RunMigration() error
	Signup(ctx context.Context, user *model.User) error
	Login(ctx context.Context, email string, password string) (model.User, error)
	GetUser(ctx context.Context, id string) (model.User, error)
	DeleteUser(ctx context.Context, username string) error
	UpdateUser(ctx context.Context, user model.EditUserRequest, id string) (model.User, error)
	CheckEmailExists(ctx context.Context, email string) error
	StoreToken(ctx context.Context, jwt string, userId string, expiresAt time.Time) error
	DeleteToken(ctx context.Context, userId uuid.UUID) error
	RevokeToken(ctx context.Context, userId string) error
	CheckTokenStatus(ctx context.Context, userId, token string) error
}
