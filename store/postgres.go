package store

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/MwaitforitOsama/go-auth/model"
	"github.com/MwaitforitOsama/go-auth/utils"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type PostgresDB struct {
	db *sql.DB
}

func NewPostgresDB(host, port, user, password, dbName string) *PostgresDB {
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbName)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}
	log.Println("Successfully connected to Database!")
	return &PostgresDB{db: db}
}

func (p *PostgresDB) RunMigration() error {
	query := `
	DROP TRIGGER IF EXISTS set_updated_at ON users;

	CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        first_name VARCHAR(255) NOT NULL,
        last_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP,
        revoked BOOLEAN DEFAULT FALSE,
        CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE OR REPLACE FUNCTION update_updated_at_column()
    RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP AT TIME ZONE 'UTC';
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;

    CREATE TRIGGER set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
	`

	// Begin a transaction
	println("I reached here")
	tx, err := p.db.Begin()
	if err != nil {
		fmt.Printf("Failed to begin transaction: %v\n", err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	println("Begin Transaction")

	// Execute the query within the transaction
	_, err = tx.Exec(query)
	if err != nil {
		tx.Rollback() // Rollback in case of an error
		fmt.Printf("Failed to execute migration query: %v\n", err)
		return fmt.Errorf("failed to execute migration: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		fmt.Printf("Failed to commit transaction: %v\n", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	fmt.Println("Migration executed successfully!")
	return nil
}

func (p *PostgresDB) Signup(ctx context.Context, user *model.User) error {
	query := `
        INSERT INTO users (id, first_name, last_name, email, password, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `
	_, err := p.db.ExecContext(ctx, query, user.Id, user.FirstName, user.LastName, user.Email, user.Password, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return fmt.Errorf("FAILED TO SIGN UP: %w", err)
	}
	return nil
}

func (p *PostgresDB) Login(ctx context.Context, email string, password string) (model.User, error) {
	user := model.User{}
	query := "SELECT id, first_name, last_name, email, password, created_at, updated_at FROM users WHERE email = $1"
	err := p.db.QueryRowContext(ctx, query, email).Scan(
		&user.Id,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return model.User{}, err
	}
	if !utils.CheckPasswordHash(password, user.Password) {
		return model.User{}, fmt.Errorf("INVALID PASSWORD")
	}
	if err := p.DeleteToken(ctx, user.Id); err != nil {
		return model.User{}, err
	}
	return user, nil
}

func (p *PostgresDB) GetUser(ctx context.Context, id string) (model.User, error) {
	user := model.User{}
	query := "SELECT id, first_name, last_name, email, created_at, updated_at FROM users WHERE id = $1"
	err := p.db.QueryRowContext(ctx, query, id).Scan(
		&user.Id,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return model.User{}, err
	}
	return user, nil
}

func (p *PostgresDB) DeleteUser(ctx context.Context, id string) error {
	// Check if user exists
	var userId string
	if err := p.db.QueryRow("SELECT id from users where id = $1", id).Scan(&userId); err != nil {
		return err
	}
	_, err := p.db.Exec("DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return err
	}
	return nil
}

func (p *PostgresDB) UpdateUser(ctx context.Context, user model.EditUserRequest, id string) (model.User, error) {
	updateUser := model.User{}
	query := `
		UPDATE users 
		SET first_name = $1, last_name = $2, email = $3, updated_at = NOW() 
		WHERE id = $4 
		RETURNING id, first_name, last_name, email, created_at, updated_at`
	err := p.db.QueryRowContext(ctx, query, user.FirstName, user.LastName, user.Email, id).Scan(
		&updateUser.Id,
		&updateUser.FirstName,
		&updateUser.LastName,
		&updateUser.Email,
		&updateUser.CreatedAt,
		&updateUser.UpdatedAt,
	)
	if err != nil {
		return model.User{}, err
	}
	return updateUser, nil
}

func (p *PostgresDB) CheckEmailExists(ctx context.Context, email string) error {
	var emailInDB string
	if err := p.db.QueryRow("SELECT email from users where email = $1", email).Scan(&emailInDB); err != nil {
		return err
	}
	if emailInDB == email {
		return fmt.Errorf("email already exists")
	}
	return nil
}

func (p *PostgresDB) StoreToken(ctx context.Context, jwt string, userId string, expiresAt time.Time) error {
	query := `
        INSERT INTO refresh_tokens (user_id, token, expires_at, revoked)
        VALUES ($1, $2, $3, $4)
    `
	_, err := p.db.ExecContext(ctx, query, userId, jwt, expiresAt, false)
	if err != nil {
		return fmt.Errorf("FAILED TO SAVE REFRESH TOKEN: %v", err)
	}
	return nil
}

func (p *PostgresDB) RevokeToken(ctx context.Context, userId string) error {
	query := `
        UPDATE refresh_tokens
        SET revoked = true
        WHERE user_id = $1;
    `
	_, err := p.db.ExecContext(ctx, query, userId)
	if err != nil {
		return fmt.Errorf("FAILED TO REVOKE TOKEN: %v", err)
	}
	return nil
}

func (p *PostgresDB) CheckTokenStatus(ctx context.Context, userId, token string) error {
	var revoked bool
	var dbToken string
	if err := p.db.QueryRow("SELECT token, revoked from refresh_tokens where user_id = $1", userId).Scan(&dbToken, &revoked); err != nil {
		return err
	}
	log.Println(dbToken, token)
	if revoked || dbToken != token {
		return fmt.Errorf("TOKEN IS REVOKED")
	}
	return nil
}

func (p *PostgresDB) DeleteToken(ctx context.Context, userId uuid.UUID) error {
	query := `
        DELETE FROM refresh_tokens
        WHERE user_id = $1;
    `
	_, err := p.db.ExecContext(ctx, query, userId)
	if err != nil {
		return fmt.Errorf("FAILED TO DELETE TOKEN: %v", err)
	}
	return nil
}
